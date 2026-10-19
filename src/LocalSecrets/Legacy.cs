using System.Text;
using System.Text.Json;

namespace LocalSecrets;

// Fusion des anciens coffres dans le coffre unique (%USERPROFILE%\.local-secrets).
// Jusqu'à la 0.1.2, le coffre était dans %LOCALAPPDATA%\local-secrets. Lancé depuis Claude Desktop
// (paquet MSIX), Windows redirigeait ses écritures vers une copie privée du paquet : deux coffres
// divergents. La fusion est automatique, répétable et ne supprime rien : on la relance dès qu'un
// ancien coffre a changé (une session encore en 0.1.2 peut y écrire).
static class Legacy
{
    static string StatePath => Path.Combine(Vault.Home, "merged.json");

    // Emplacements anciens. Avec LOCAL_SECRETS_HOME (tests, coffre explicite), aucune fusion
    // automatique, sauf liste donnée par LOCAL_SECRETS_LEGACY_DIRS.
    public static List<string> Sources()
    {
        var list = new List<string>();
        var forced = Environment.GetEnvironmentVariable("LOCAL_SECRETS_LEGACY_DIRS");
        if (!string.IsNullOrWhiteSpace(forced))
        {
            list.AddRange(forced.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            return list;
        }
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("LOCAL_SECRETS_HOME"))) return list;

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        list.Add(Path.Combine(local, "local-secrets"));
        var packages = Path.Combine(local, "Packages");
        try
        {
            if (Directory.Exists(packages))
                foreach (var p in Directory.EnumerateDirectories(packages))
                {
                    var d = Path.Combine(p, "LocalCache", "Local", "local-secrets");
                    if (File.Exists(Path.Combine(d, "vault.json"))) list.Add(d);
                }
        }
        catch
        {
            // dossier des paquets illisible : seul l'emplacement classique est fusionné
        }
        return list;
    }

    static string? Stamp(string dir)
    {
        var vault = new FileInfo(Path.Combine(dir, "vault.json"));
        if (!vault.Exists) return null;
        var backups = Path.Combine(dir, "backups");
        var count = Directory.Exists(backups) ? Directory.EnumerateFiles(backups, "*.json").Count() : 0;
        return $"{vault.Length}:{vault.LastWriteTimeUtc.Ticks}:{count}";
    }

    static Dictionary<string, string> LoadState()
    {
        try
        {
            return File.Exists(StatePath)
                ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(StatePath)) ?? new()
                : new();
        }
        catch
        {
            return new();
        }
    }

    // Fusionne ce qui a changé depuis la dernière fois. Renvoie un compte rendu par source.
    public static List<string> EnsureMerged(bool force = false, IEnumerable<string>? extra = null)
    {
        var report = new List<string>();
        var home = Path.TrimEndingDirectorySeparator(Paths.Normalize(Vault.Home));
        var sources = Sources().Concat(extra ?? [])
            .Select(s => Path.TrimEndingDirectorySeparator(Paths.Normalize(s)))
            .Where(s => !s.Equals(home, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (sources.Count == 0) return report;

        var state = LoadState();
        var pending = sources.Select(s => (Dir: s, Stamp: Stamp(s)))
            .Where(s => s.Stamp != null && (force || !state.TryGetValue(s.Dir, out var old) || old != s.Stamp))
            .ToList();
        if (pending.Count == 0) return report;

        Vault.Update(d =>
        {
            foreach (var (dir, _) in pending) report.Add(MergeOne(d, dir));
            return 0;
        });
        foreach (var (dir, stamp) in pending)
        {
            CopyFiles(dir);
            state[dir] = stamp!;
        }
        Directory.CreateDirectory(Vault.Home);
        File.WriteAllText(StatePath, JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        foreach (var line in report) Log.Write("fusion : " + line);
        return report;
    }

    static string MergeOne(VaultData target, string dir)
    {
        VaultData? source;
        try { source = Vault.LoadFrom(dir); }
        catch (Exception e) { return $"{dir} : illisible ({e.Message})"; }
        if (source == null) return $"{dir} : pas de coffre";

        int added = 0, newer = 0, same = 0, kept = 0, unreadable = 0;
        var conflicts = new List<string>();
        foreach (var (name, entry) in source.Secrets)
        {
            string incoming;
            try { incoming = Vault.Decrypt(name, entry); }
            catch { unreadable++; continue; }

            if (!target.Secrets.TryGetValue(name, out var current))
            {
                target.Secrets[name] = Copy(entry);
                added++;
                continue;
            }
            if (current.Data == entry.Data) { same++; continue; }
            string? existing = null;
            try { existing = Vault.Decrypt(name, current); } catch { }
            if (existing == incoming) { same++; continue; }
            // Deux valeurs différentes : la plus récente gagne.
            if (existing == null || entry.Updated > current.Updated)
            {
                target.Secrets[name] = Copy(entry);
                newer++;
            }
            else
            {
                kept++;
            }
            conflicts.Add(name);
        }
        foreach (var (ns, info) in source.Namespaces)
            target.Namespaces.TryAdd(ns, new NamespaceEntry { Path = info.Path, Created = info.Created });

        var line = $"{dir} : {added} ajouté(s), {newer} remplacé(s) par une version plus récente, {same} identique(s)";
        if (kept > 0) line += $", {kept} gardé(s) car plus récent(s) ici";
        if (unreadable > 0) line += $", {unreadable} illisible(s)";
        if (conflicts.Count > 0) line += $" ; valeurs différentes pour : {string.Join(", ", conflicts)}";
        return line;
    }

    static SecretEntry Copy(SecretEntry e) =>
        new() { Data = e.Data, Created = e.Created, Updated = e.Updated, Origin = e.Origin };

    // Copies chiffrées des .env d'origine et réglages : on complète sans jamais écraser.
    static void CopyFiles(string dir)
    {
        var backups = Path.Combine(dir, "backups");
        if (Directory.Exists(backups))
        {
            Directory.CreateDirectory(Vault.BackupDir);
            foreach (var file in Directory.EnumerateFiles(backups, "*.json"))
            {
                var target = Path.Combine(Vault.BackupDir, Path.GetFileName(file));
                if (!File.Exists(target)) File.Copy(file, target);
            }
        }
        var config = Path.Combine(dir, "config.json");
        if (File.Exists(config) && !File.Exists(Settings.FilePath)) File.Copy(config, Settings.FilePath);
    }
}
