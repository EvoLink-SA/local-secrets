using System.Text;

namespace LocalSecrets;

static class Paths
{
    static readonly string[] ExcludedSuffixes = [".example", ".sample", ".template", ".tpl", ".dist", ".defaults", ".schema", ".vault"];

    static readonly HashSet<string> KeyFileNames = new(StringComparer.OrdinalIgnoreCase)
        { "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk" };

    static readonly HashSet<string> KeyFileExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".pem", ".key", ".ppk", ".pfx", ".p12", ".jks", ".keystore" };

    static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules", ".git", ".hg", ".svn", "vendor", "bin", "obj", "dist", "build", "out", "target", ".venv", "venv",
        "__pycache__", ".next", ".nuxt", ".cache", "coverage", "packages", ".terraform", ".gradle", ".idea", ".vs", "site-packages",
    };

    public static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    // Comparaison de chemins : insensible à la casse sous Windows, sensible ailleurs.
    public static readonly StringComparison Comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    public static readonly StringComparer Comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    // Dossier et fichiers du coffre, réservés à ce compte : 0700 et 0600 hors Windows. Sous Windows,
    // le profil utilisateur protège déjà son contenu et rien ne change.
    const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    const UnixFileMode PrivateDir = PrivateFile | UnixFileMode.UserExecute;

    public static void CreatePrivateDirectory(string dir)
    {
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(dir);
            return;
        }
        Directory.CreateDirectory(dir, PrivateDir);
        File.SetUnixFileMode(dir, PrivateDir);
    }

    public static void WritePrivate(string path, string text) => WritePrivate(path, new UTF8Encoding(false).GetBytes(text));

    // Créé directement en 0600 : le contenu n'est jamais lisible par les autres, même un instant.
    public static void WritePrivate(string path, byte[] bytes)
    {
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllBytes(path, bytes);
            return;
        }
        using (var fs = new FileStream(path, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = PrivateFile }))
            fs.Write(bytes);
        File.SetUnixFileMode(path, PrivateFile);
    }

    // Fichier créé par un autre moyen (copie, ajout en fin de fichier) : ramené à 0600.
    public static void RestrictToOwner(string path)
    {
        if (!OperatingSystem.IsWindows() && File.Exists(path)) File.SetUnixFileMode(path, PrivateFile);
    }

    // .env, .env.prod, prod.env, docker.env... mais pas .env.example ni les modèles.
    public static bool IsEnvFileName(string? fileName)
    {
        if (string.IsNullOrEmpty(fileName)) return false;
        var n = fileName.ToLowerInvariant();
        foreach (var s in ExcludedSuffixes)
            if (n.EndsWith(s, StringComparison.Ordinal)) return false;
        return n == ".env"
               || n.StartsWith(".env.", StringComparison.Ordinal)
               || (n.Length > 4 && n.EndsWith(".env", StringComparison.Ordinal));
    }

    public static bool IsEnvFile(string? fullPath) =>
        fullPath != null && IsEnvFileName(Path.GetFileName(fullPath)) && File.Exists(fullPath);

    static readonly HashSet<string> CredentialFileNames = new(StringComparer.OrdinalIgnoreCase)
        { ".pgpass", "pgpass.conf", ".netrc", "_netrc", ".git-credentials" };

    // Fichiers d'identifiants bien connus, qui ne sont pas des .env : jamais lus par Claude.
    public static bool IsCredentialFile(string fullPath) => IsCredentialFileName(fullPath) && File.Exists(fullPath);

    public static bool IsCredentialFileName(string fullPath)
    {
        var name = Path.GetFileName(fullPath);
        if (CredentialFileNames.Contains(name)) return true;
        return name.Equals("credentials", StringComparison.OrdinalIgnoreCase)
               && Path.GetFileName(Path.GetDirectoryName(fullPath) ?? "").Equals(".aws", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsPrivateKeyFile(string fullPath)
    {
        var name = Path.GetFileName(fullPath);
        var ext = Path.GetExtension(name);
        if (!KeyFileNames.Contains(name) && !KeyFileExtensions.Contains(ext)) return false;
        if (!File.Exists(fullPath)) return false;
        if (ext.ToLowerInvariant() is ".pfx" or ".p12" or ".jks" or ".keystore") return true;
        try
        {
            using var fs = File.OpenRead(fullPath);
            var buffer = new byte[8192];
            var n = fs.Read(buffer);
            var head = Encoding.ASCII.GetString(buffer, 0, n);
            return head.Contains("PRIVATE KEY") || head.Contains("PuTTY-User-Key-File");
        }
        catch
        {
            return false;
        }
    }

    public static bool IsVaultPath(string? fullPath)
    {
        if (fullPath == null) return false;
        fullPath = Normalize(fullPath);
        var home = Path.TrimEndingDirectorySeparator(Normalize(Vault.Home));
        return fullPath.Equals(home, Comparison)
               || fullPath.StartsWith(home + Path.DirectorySeparatorChar, Comparison);
    }

    // Chemin absolu à partir de ce que Claude a écrit : relatif, ~, /c/... (Git Bash) ou Windows.
    public static string? Full(string? path, string cwd)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            var p = path.Trim().Trim('"', '\'');
            p = Platform.Current.FromShellPath(p);
            if (p == "~" || p.StartsWith("~/") || p.StartsWith("~\\")) p = Path.Combine(UserProfile, p.Length > 2 ? p[2..] : "");
            return Normalize(Path.Combine(cwd, p));
        }
        catch
        {
            return null;
        }
    }

    // Forme canonique : absolue et sans noms courts 8.3, pour comparer deux chemins vers le même fichier.
    public static string Normalize(string path)
    {
        var full = Path.GetFullPath(path);
        if (!full.Contains('~')) return full;
        if (Platform.Current.LongPath(full) is { } longPath) return longPath;
        // Fichier pas encore créé : on normalise le dossier parent.
        var dir = Path.GetDirectoryName(full);
        return dir != null && Platform.Current.LongPath(dir) is { } longDir ? Path.Combine(longDir, Path.GetFileName(full)) : full;
    }

    // Dossier trop large pour être parcouru en entier (racine, profil, Bureau...).
    public static bool IsBroad(string dir)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dir));
        if (Path.GetPathRoot(full) is { } root && Path.TrimEndingDirectorySeparator(root).Equals(full, Comparison)) return true;
        string[] broad =
        [
            UserProfile,
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(UserProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        ];
        return broad.Any(b => b.Length > 0 && Path.TrimEndingDirectorySeparator(b).Equals(full, Comparison));
    }

    // Le fichier appartient-il au projet ouvert ? Il doit être sous la racine, sans dépôt git
    // intermédiaire : C:\tools\AutreProjet\.env n'appartient pas à une session ouverte dans C:\tools.
    public static bool IsInProject(string file, string? root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        var r = Path.TrimEndingDirectorySeparator(Normalize(root));
        if (IsBroad(r)) return false;
        var f = Normalize(file);
        if (!f.StartsWith(r + Path.DirectorySeparatorChar, Comparison)) return false;
        for (var d = Path.GetDirectoryName(f); d != null && d.Length > r.Length; d = Path.GetDirectoryName(d))
            if (Directory.Exists(Path.Combine(d, ".git")) || File.Exists(Path.Combine(d, ".git"))) return false;
        return true;
    }

    public static List<string> FindEnvFiles(string root, int maxDepth, int maxEntries = 20000)
    {
        var result = new List<string>();
        if (!Directory.Exists(root)) return result;
        var options = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0, RecurseSubdirectories = false };
        var stack = new Stack<(DirectoryInfo Dir, int Depth)>();
        stack.Push((new DirectoryInfo(root), 0));
        var seen = 0;
        while (stack.Count > 0 && seen < maxEntries)
        {
            var (dir, depth) = stack.Pop();
            try
            {
                foreach (var entry in dir.EnumerateFileSystemInfos("*", options))
                {
                    if (++seen > maxEntries) break;
                    if (entry is DirectoryInfo sub)
                    {
                        if ((sub.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if (depth + 1 < maxDepth && !SkipDirs.Contains(sub.Name) && !File.Exists(Path.Combine(sub.FullName, "pyvenv.cfg")))
                            stack.Push((sub, depth + 1));
                    }
                    else if (IsEnvFileName(entry.Name))
                    {
                        result.Add(entry.FullName);
                    }
                }
            }
            catch
            {
                // dossier illisible : ignoré
            }
        }
        result.Sort(Comparer);
        return result;
    }

    public static bool HasReferences(string file)
    {
        try { return File.ReadAllText(file).Contains("secret://", StringComparison.Ordinal); }
        catch { return false; }
    }
}
