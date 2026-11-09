using System.Diagnostics;

namespace LocalSecrets;

static class Doctor
{
    public static int Run()
    {
        var problems = 0;
        void Ok(string m) => Console.WriteLine("  OK   " + m);
        void Bad(string m) { Console.WriteLine("  !!   " + m); problems++; }

        Console.WriteLine($"secret (local-secrets) {Commands.Version}");
        Console.WriteLine($"  exécutable : {Environment.ProcessPath}");
        Console.WriteLine($"  coffre     : {Vault.FilePath}");

        var platform = Platform.Current;
        try
        {
            platform.Unprotect(platform.Protect([1, 2, 3], [7]), [7]);
            Ok($"{platform.ProtectionName} disponible pour ce compte");
        }
        catch (Exception e)
        {
            Bad($"{platform.ProtectionName} : " + e.Message);
        }

        var vault = Vault.Load();
        var all = Vault.DecryptAll(vault);
        var readable = all.Count;
        if (readable == vault.Secrets.Count) Ok($"{readable} secret(s) dans le coffre, tous déchiffrables");
        else Bad($"{vault.Secrets.Count - readable} secret(s) illisible(s) sous ce compte (coffre copié depuis ailleurs ?)");

        // Valeurs faibles : seulement celles qu'un .env utilise encore.
        var weak = all.Where(s => Classifier.IsWeakSecret(s.Value) && IsStillReferenced(vault, s.Name)).Select(s => s.Name).ToList();
        if (weak.Count > 0) Bad($"{weak.Count} secret(s) encore utilisé(s) à valeur faible (mot courant ou trop court), à changer : {string.Join(", ", weak)}");
        var unused = vault.Secrets.Keys.Count(n => !IsStillReferenced(vault, n));
        if (unused > 0) Console.WriteLine($"  ..   {unused} secret(s) qu'aucun .env connu n'utilise plus (« secret rm NOM » pour les retirer)");

        var settings = Settings.Load();
        if (settings.BackupOverdue(vault.Secrets.Count))
            Bad(settings.LastBackup is { } b
                ? $"dernière sauvegarde portable le {b:dd.MM.yyyy} : refais « secret backup FICHIER »"
                : "aucune sauvegarde portable du coffre : lance « secret backup FICHIER » (indispensable pour changer de PC)");
        else if (settings.LastBackup is { } ok)
            Ok($"sauvegarde portable du {ok:dd.MM.yyyy}");

        var legacy = Legacy.Sources().Where(s => File.Exists(Path.Combine(s, "vault.json"))).ToList();
        foreach (var s in legacy) Console.WriteLine($"  ..   ancien coffre fusionné automatiquement, laissé intact : {s}");

        // Le terminal (exe du PATH) et les hooks de Claude (copie du plugin) doivent avoir la même version.
        var mine = Commands.Version;
        if (PluginExe() is { } plugin)
        {
            var theirs = FileVersionInfo.GetVersionInfo(plugin).ProductVersion?.Split('+')[0] ?? AskVersion(plugin) ?? "?";
            if (theirs == mine) Ok($"hooks de Claude à la même version ({theirs})");
            else Bad($"hooks de Claude en {theirs}, cette commande en {mine} : relance {platform.InstallScript}, puis redémarre Claude");
        }

        var onPath = platform.FindExecutable("secret");
        if (onPath != null) Ok($"« secret » trouvé dans le PATH : {onPath}");
        else Bad($"« secret » absent du PATH de ce terminal : lance {platform.InstallScript}");

        var installed = Path.Combine(Paths.UserProfile, ".claude", "plugins", "installed_plugins.json");
        var pluginId = $"{platform.PluginName}@local-secrets";
        if (File.Exists(installed) && File.ReadAllText(installed).Contains(pluginId, StringComparison.OrdinalIgnoreCase))
            Ok("plugin Claude Code installé");
        else
            Bad($"plugin Claude Code non détecté : claude plugin install {pluginId}");

        foreach (var (problem, message) in platform.DoctorChecks())
            if (problem) Bad(message);
            else Ok(message);

        Console.WriteLine(problems == 0 ? "Tout est en ordre." : $"{problems} point(s) à regarder.");
        return problems == 0 ? 0 : 1;
    }

    // Un secret est encore utilisé si son fichier d'origine existe et y fait toujours référence.
    static bool IsStillReferenced(VaultData vault, string name)
    {
        if (!vault.Secrets.TryGetValue(name, out var entry) || entry.Origin is not { } origin) return true;
        try { return File.Exists(origin) && File.ReadAllText(origin).Contains("secret://" + name, StringComparison.Ordinal); }
        catch { return true; }
    }

    // Binaire sans ressource de version (Linux) : on lui demande « secret version ».
    static string? AskVersion(string exe)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(exe, "version") { RedirectStandardOutput = true, UseShellExecute = false })!;
            var text = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(5000);
            return text.Length > 0 ? text.Split(' ')[^1] : null;
        }
        catch
        {
            return null;
        }
    }

    // L'exe de la version installée du plugin la plus récente, dans le cache de Claude Code.
    static string? PluginExe()
    {
        var cache = Path.Combine(Paths.UserProfile, ".claude", "plugins", "cache", "local-secrets", Platform.Current.PluginName);
        if (!Directory.Exists(cache)) return null;
        var exe = Platform.Current.ExecutableName;
        return Directory.EnumerateDirectories(cache)
            .Select(d => (Dir: d, Ok: Version.TryParse(Path.GetFileName(d), out var v), Version: v))
            .Where(x => x.Ok && File.Exists(Path.Combine(x.Dir, "bin", exe)))
            .OrderByDescending(x => x.Version)
            .Select(x => Path.Combine(x.Dir, "bin", exe))
            .FirstOrDefault();
    }
}
