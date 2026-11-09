using System.Runtime.Versioning;
using System.Diagnostics;
using System.Security.Cryptography;

namespace LocalSecrets;

[SupportedOSPlatform("linux")]
sealed class LinuxPlatform : IPlatform
{
    public string ProtectionName => "ECIES P-256";

    public string ProtectionId => "ecies-p256";

    public string ExecutableName => "secret";

    public string InstallScript => "install.sh";

    public string PluginName => "local-secrets-linux";

    public string ProtectionDescription => "clé de ce compte, déverrouillée par phrase de passe";

    public string ShellHints(string exe) =>
        $"Si « secret » est introuvable, appelle-le par son chemin : '{exe}' run -- <commande>. " +
        "Si une commande échoue avec « coffre verrouillé », demande à l'utilisateur de lancer « secret unlock » dans un autre terminal : " +
        "tu ne peux pas le faire à sa place. Sous Linux, « secret show » n'ouvre pas de fenêtre : c'est aussi à lui de le taper dans " +
        "un autre terminal. Ne propose jamais le préfixe « ! » de Claude Code pour ces commandes : leur sortie et leur saisie " +
        "passeraient par la conversation. ";

    public string BackupHint =>
        "Sans elle, un changement de PC ou l'oubli de la phrase de passe rend tout illisible. Dans ton terminal : secret backup ~/coffre.lsbackup";

    public string SshAgentName => "l'agent ssh (ssh-agent)";

    public string UnreadableHint => "Coffre verrouillé ? L'utilisateur lance « secret unlock » dans son terminal.";

    public byte[] Protect(byte[] data, byte[] entropy) => KeyStore.Protect(data, entropy);

    public byte[] Unprotect(byte[] data, byte[] entropy) => KeyStore.Unprotect(data, entropy);

    public bool CanDecrypt => KeyStore.Exists && KeyStore.UnlockedFor() != null;

    // Verrou de fichier : FileShare.None pose un flock exclusif, respecté par tous les processus
    // de ce compte, quelle que soit leur session.
    public IDisposable? LockVault(TimeSpan timeout)
    {
        Paths.CreatePrivateDirectory(Vault.Home);
        var path = Path.Combine(Vault.Home, "vault.lock");
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            try
            {
                var fs = new FileStream(path, new FileStreamOptions
                {
                    Mode = FileMode.OpenOrCreate,
                    Access = FileAccess.ReadWrite,
                    Share = FileShare.None,
                    UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
                });
                return fs;
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(50);
            }
            catch (IOException)
            {
                return null;
            }
        }
    }

    public string FromShellPath(string path) => path;

    public string? LongPath(string path) => null;

    // Sorties de programmes en UTF-8 : UTF-8 et UTF-16 sont déjà couverts.
    public IEnumerable<int> OutputCodePages() => [];

    public bool IsDedicatedConsole() => LinuxNative.IsTerminal(0) && LinuxNative.IsTerminal(1);

    // Pas encore de fenêtre à part sous Linux.
    public void OpenWindow(string cwd, IEnumerable<string> args) =>
        throw new UserError("pas de fenêtre à part sous Linux pour l'instant : demande à l'utilisateur de lancer lui-même " +
                            "« secret show » dans son terminal. Les valeurs ne doivent pas passer par ta sortie.");

    const UnixFileMode AnyExecute = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;

    static bool IsExecutable(string path) =>
        File.Exists(path) && (File.GetUnixFileMode(path) & AnyExecute) != 0;

    public string? FindExecutable(string name)
    {
        if (name.Contains('/'))
        {
            var full = Paths.Full(name, Environment.CurrentDirectory);
            return full != null && IsExecutable(full) ? full : null;
        }
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(':', StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir, name);
            if (IsExecutable(candidate)) return candidate;
        }
        return null;
    }

    // Lancement direct : le noyau suit le shebang des scripts.
    public (string File, List<string> Args, string? Raw) ResolveCommand(string path, List<string> args) => (path, args, null);

    public void PrepareChildEnvironment(ProcessStartInfo psi, string file, ICollection<string> keys)
    {
    }

    public ProcessStartInfo InteractiveShell()
    {
        var shell = Environment.GetEnvironmentVariable("SHELL");
        return new ProcessStartInfo(string.IsNullOrEmpty(shell) ? "/bin/bash" : shell) { UseShellExecute = false };
    }

    public IEnumerable<string> LegacyVaultDirs() => [];

    public IEnumerable<(bool Problem, string Message)> DoctorChecks()
    {
        if (AesGcm.IsSupported) yield return (false, "OpenSSL disponible (AES-GCM)");
        else yield return (true, "AES-GCM indisponible : installe OpenSSL (paquet libssl3 ou équivalent)");

        if (!LinuxNative.KeyringAvailable(out var error))
            yield return (true, $"trousseau noyau inutilisable ({error}) : secret unlock ne pourra pas garder la clé");

        if (!KeyStore.Exists)
        {
            yield return (true, "aucune clé de coffre : lance « secret init »");
        }
        else if (KeyStore.UnlockedFor() is { } left)
        {
            yield return (false, left > TimeSpan.Zero
                ? $"coffre déverrouillé (encore {(int)left.TotalHours} h {left.Minutes:00} min)"
                : "coffre déverrouillé");
        }
        else
        {
            yield return (false, "coffre verrouillé : « secret unlock » pour utiliser les valeurs (la conversion des .env fonctionne quand même)");
        }

        var loose = new[] { Vault.Home, Vault.FilePath, KeyStore.FilePath, Settings.FilePath }
            .Where(p => Path.Exists(p) && (File.GetUnixFileMode(p) & (UnixFileMode.GroupRead | UnixFileMode.OtherRead | UnixFileMode.OtherExecute)) != 0)
            .ToList();
        if (loose.Count > 0) yield return (true, $"lisible(s) par d'autres comptes : {string.Join(", ", loose)} (chmod 700 du dossier, 600 des fichiers)");
        else yield return (false, "coffre réservé à ce compte (permissions 700 et 600)");

        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK"))) yield return (false, "agent ssh disponible (SSH_AUTH_SOCK)");
        else yield return (true, "pas d'agent ssh dans ce terminal (SSH_AUTH_SOCK vide) : utile pour les clés SSH");
    }
}
