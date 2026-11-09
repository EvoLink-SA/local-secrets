using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LocalSecrets;

sealed class SecretEntry
{
    public string Data { get; set; } = "";
    public DateTime Created { get; set; }
    public DateTime Updated { get; set; }
    public string? Origin { get; set; }
}

sealed class NamespaceEntry
{
    public string Path { get; set; } = "";
    public DateTime Created { get; set; }
}

sealed class VaultData
{
    public int Version { get; set; } = 1;

    // Protection des valeurs (IPlatform.ProtectionId). Absente dans les coffres d'avant la 0.2 : DPAPI.
    public string? Protection { get; set; }
    public Dictionary<string, NamespaceEntry> Namespaces { get; set; } = new();
    public Dictionary<string, SecretEntry> Secrets { get; set; } = new();
}

sealed class EnvBackup
{
    public string Path { get; set; } = "";
    public DateTime Created { get; set; }
    public string Data { get; set; } = "";
}

static partial class Vault
{
    public static string Home
    {
        get
        {
            // Hors d'AppData : Windows redirige les écritures d'AppData des applications empaquetées
            // (Claude Desktop est un paquet MSIX) vers une copie privée, ce qui donnait deux coffres.
            var custom = Environment.GetEnvironmentVariable("LOCAL_SECRETS_HOME");
            return string.IsNullOrWhiteSpace(custom)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local-secrets")
                : Path.GetFullPath(custom);
        }
    }

    public static string FilePath => Path.Combine(Home, "vault.json");
    public static string BackupDir => Path.Combine(Home, "backups");

    [GeneratedRegex(@"^[a-z0-9][a-z0-9._\-]*/[0-9]*[A-Za-z_][A-Za-z0-9_.\-]*$")]
    private static partial Regex NameRx();

    public static bool IsValidName(string name) => NameRx().IsMatch(name);

    // Coffre d'un autre emplacement (ancien coffre, copie de secours), en lecture seule.
    public static VaultData? LoadFrom(string dir)
    {
        var file = Path.Combine(dir, "vault.json");
        if (!File.Exists(file)) return null;
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return JsonSerializer.Deserialize(fs, JsonContext.Default.VaultData);
    }

    public static VaultData Load()
    {
        if (!File.Exists(FilePath)) return new VaultData();
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                using var fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                return JsonSerializer.Deserialize(fs, JsonContext.Default.VaultData) ?? new VaultData();
            }
            catch (IOException) when (attempt < 5)
            {
                Thread.Sleep(50);
            }
        }
    }

    // Lecture, modification et écriture sous verrou : plusieurs hooks peuvent tourner en parallèle.
    public static T Update<T>(Func<VaultData, T> change)
    {
        using var vaultLock = Platform.Current.LockVault(TimeSpan.FromSeconds(15))
                              ?? throw new UserError("le coffre est occupé par un autre processus, réessaie.");
        var data = Load();
        CheckProtection(data);
        var result = change(data);
        data.Protection = Platform.Current.ProtectionId;
        Save(data);
        return result;
    }

    // Un coffre se relit seulement avec la protection qui l'a créé : on n'y mélange pas deux protections.
    public static void CheckProtection(VaultData data)
    {
        var expected = Platform.Current.ProtectionId;
        var actual = data.Protection ?? (data.Secrets.Count > 0 ? "dpapi" : expected);
        if (actual != expected)
            throw new UserError($"ce coffre a été créé avec une autre protection ({actual}) que celle de ce système ({expected}), " +
                                "par exemple copié depuis Windows. Pour changer de système : « secret backup » là où il a été créé, " +
                                "puis « secret restore » ici.");
    }

    static void Save(VaultData data)
    {
        Paths.CreatePrivateDirectory(Home);
        var tmp = FilePath + ".tmp";
        Paths.WritePrivate(tmp, JsonSerializer.Serialize(data, JsonContext.Default.VaultData));
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                File.Move(tmp, FilePath, overwrite: true);
                return;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException && attempt < 20)
            {
                Thread.Sleep(50);
            }
        }
    }

    // L'entropie lie chaque blob à son nom : un blob recopié sous un autre nom ne se déchiffre pas.
    static byte[] Entropy(string name) => Encoding.UTF8.GetBytes("local-secrets/v1:" + name);

    public static string Encrypt(string name, string value) =>
        Convert.ToBase64String(Platform.Current.Protect(Encoding.UTF8.GetBytes(value), Entropy(name)));

    public static string Decrypt(string name, SecretEntry entry) =>
        Encoding.UTF8.GetString(Platform.Current.Unprotect(Convert.FromBase64String(entry.Data), Entropy(name)));

    public static string? TryGet(VaultData d, string name)
    {
        if (!d.Secrets.TryGetValue(name, out var entry)) return null;
        try
        {
            return Decrypt(name, entry);
        }
        catch (Exception e)
        {
            throw e as UserError ?? new UserError($"impossible de déchiffrer « {name} » ({e.Message}). Le coffre a peut-être été créé " +
                                                  "sous un autre compte ou sur une autre machine : restaure une sauvegarde avec « secret restore ».");
        }
    }

    // Les secrets illisibles (autre compte, coffre verrouillé) sont écartés, et nommés dans unreadable.
    public static List<(string Name, string Value)> DecryptAll(VaultData d, ICollection<string>? unreadable = null)
    {
        var list = new List<(string, string)>();
        foreach (var (name, entry) in d.Secrets)
        {
            try
            {
                list.Add((name, Decrypt(name, entry)));
            }
            catch (Exception e)
            {
                Log.Write($"déchiffrement impossible pour {name} : {e.Message}");
                unreadable?.Add(name);
            }
        }
        return list;
    }

    public static void Set(VaultData d, string name, string value, string? origin)
    {
        var now = DateTime.Now;
        if (d.Secrets.TryGetValue(name, out var entry))
        {
            string? current = null;
            try { current = Decrypt(name, entry); } catch { }
            if (current == value) return;
            entry.Data = Encrypt(name, value);
            entry.Updated = now;
            if (origin != null) entry.Origin = origin;
            return;
        }
        d.Secrets[name] = new SecretEntry { Data = Encrypt(name, value), Created = now, Updated = now, Origin = origin };
    }

    // Retrouve un nom complet espace/CLÉ à partir de « CLÉ » : d'abord la référence du .env
    // du dossier courant, sinon une correspondance unique dans le coffre.
    public static string Resolve(VaultData d, string name, string cwd)
    {
        if (name.Contains('/')) return name;
        var env = Path.Combine(cwd, ".env");
        if (File.Exists(env))
        {
            var reference = EnvFile.Load(env).Assignments.LastOrDefault(a => a.Key == name)?.Reference;
            if (reference != null) return reference;
        }
        var candidates = d.Secrets.Keys.Where(k => k.EndsWith("/" + name, StringComparison.Ordinal)).ToList();
        return candidates.Count switch
        {
            1 => candidates[0],
            0 => throw new UserError($"secret introuvable : {name}"),
            _ => throw new UserError($"« {name} » est ambigu ({string.Join(", ", candidates)}) : précise espace/{name}"),
        };
    }

    public static string? FindNamespace(VaultData d, string fullPath) =>
        d.Namespaces.FirstOrDefault(kv => string.Equals(Paths.Normalize(kv.Value.Path), Paths.Normalize(fullPath), Paths.Comparison)).Key;

    // Un espace de noms par fichier .env : deux fichiers ne s'écrasent jamais leurs valeurs.
    public static string NamespaceForFile(VaultData d, string fullPath, string? preferred)
    {
        fullPath = Paths.Normalize(fullPath);
        var known = FindNamespace(d, fullPath);
        if (known != null) return known;

        // Fichier déplacé : il garde l'espace de ses références si l'ancien emplacement n'existe plus.
        if (preferred != null && (!d.Namespaces.TryGetValue(preferred, out var previous) || !File.Exists(previous.Path)))
        {
            d.Namespaces[preferred] = new NamespaceEntry { Path = fullPath, Created = DateTime.Now };
            return preferred;
        }

        var baseName = BaseNamespace(fullPath);
        var ns = baseName;
        for (var n = 2; d.Namespaces.ContainsKey(ns) || d.Secrets.Keys.Any(k => k.StartsWith(ns + "/", StringComparison.Ordinal)); n++)
            ns = $"{baseName}-{n}";
        d.Namespaces[ns] = new NamespaceEntry { Path = fullPath, Created = DateTime.Now };
        return ns;
    }

    public static string BaseNamespace(string fullPath)
    {
        var dir = Path.GetFileName(Path.GetDirectoryName(fullPath) ?? "") ?? "";
        var file = Path.GetFileName(fullPath).ToLowerInvariant();
        string suffix;
        if (file.StartsWith(".env", StringComparison.Ordinal)) suffix = file[4..].TrimStart('.');
        else if (file.EndsWith(".env", StringComparison.Ordinal)) suffix = file[..^4];
        else suffix = file;
        var ns = Sanitize(dir);
        return suffix.Length > 0 ? ns + "." + Sanitize(suffix) : ns;
    }

    public static string Sanitize(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s.ToLowerInvariant())
            sb.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '-');
        var r = sb.ToString();
        while (r.Contains("--")) r = r.Replace("--", "-");
        r = r.Trim('-', '.', '_');
        return r.Length == 0 ? "projet" : r;
    }

    public static void BackupEnvFile(string fullPath, byte[] original)
    {
        Paths.CreatePrivateDirectory(Home);
        Paths.CreatePrivateDirectory(BackupDir);
        var record = new EnvBackup
        {
            Path = fullPath,
            Created = DateTime.Now,
            Data = Convert.ToBase64String(Platform.Current.Protect(original, Entropy("backup"))),
        };
        var file = Path.Combine(BackupDir, $"{DateTime.Now:yyyyMMdd-HHmmss-fff}-{Guid.NewGuid().ToString("N")[..8]}.json");
        Paths.WritePrivate(file, JsonSerializer.Serialize(record, JsonContext.Default.EnvBackup));

        // On garde les 10 dernières sauvegardes de chaque fichier.
        foreach (var old in ListBackups()
                     .Where(b => string.Equals(b.Record.Path, fullPath, Paths.Comparison))
                     .OrderByDescending(b => b.Record.Created)
                     .Skip(10))
            File.Delete(old.File);
    }

    public static List<(string File, EnvBackup Record)> ListBackups()
    {
        var list = new List<(string, EnvBackup)>();
        if (!Directory.Exists(BackupDir)) return list;
        foreach (var file in Directory.EnumerateFiles(BackupDir, "*.json"))
        {
            try
            {
                var record = JsonSerializer.Deserialize(File.ReadAllText(file), JsonContext.Default.EnvBackup);
                if (record != null) list.Add((file, record));
            }
            catch
            {
                // sauvegarde illisible : ignorée
            }
        }
        return list;
    }

    public static byte[] RestoreBackup(EnvBackup b) => Platform.Current.Unprotect(Convert.FromBase64String(b.Data), Entropy("backup"));
}
