using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace LocalSecrets;

// Gardien de session pour la clé privée du coffre Linux (« secret unlock --remember ») :
// - sous WSL, la DPAPI du compte Windows, via secret.exe wsl-key (pont WSL) ;
// - sur un bureau Linux, le trousseau de session (Secret Service : GNOME Keyring, KWallet), via secret-tool.
// Le coffre se rouvre alors sans phrase de passe, comme sous Windows, tant que la session est ouverte.
[SupportedOSPlatform("linux")]
static class SessionKeeper
{
    public const string Wsl = "wsl-dpapi";
    public const string SecretService = "secret-service";

    // Liée au pont : un blob DPAPI de la clé du coffre ne sert à rien d'autre.
    static readonly byte[] BridgeEntropy = Encoding.UTF8.GetBytes("local-secrets/wsl-bridge");

    // Gardien utilisable ici, ou null avec la raison.
    public static string? Available(out string why)
    {
        why = "";
        if (IsWsl)
        {
            if (WindowsExe() != null) return Wsl;
            why = "sous WSL, secret.exe (Windows) est introuvable à côté de ce binaire ; indique son chemin dans LOCAL_SECRETS_WINDOWS_EXE";
            return null;
        }
        if (Platform.Current.FindExecutable("secret-tool") != null && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS")))
            return SecretService;
        why = "pas de trousseau de session (secret-tool absent ou pas de session de bureau) : sur un serveur, la phrase de passe reste la seule clé";
        return null;
    }

    public static void Remember(byte[] pkcs8)
    {
        var method = Available(out var why) ?? throw new UserError("impossible de mémoriser la clé : " + why + ".");
        var encoded = Convert.ToBase64String(pkcs8);
        if (method == Wsl)
        {
            var blob = Run(WindowsExe()!, ["wsl-key", "wrap"], encoded).Trim();
            KeyStore.Remember(Wsl, new JsonObject { ["blob"] = blob });
        }
        else
        {
            // Libellé en ASCII : sans locale UTF-8, secret-tool refuse les caractères accentués.
            Run("secret-tool", ["store", "--label=local-secrets vault key", .. Attributes], encoded);
            KeyStore.Remember(SecretService, new JsonObject());
        }
    }

    public static byte[] Recall()
    {
        var details = KeyStore.RememberDetails ?? throw new UserError("aucune clé mémorisée");
        if ((string?)details["method"] == Wsl)
        {
            var exe = WindowsExe() ?? throw new UserError("secret.exe (Windows) introuvable");
            // La clé revient chiffrée pour une clé éphémère de ce processus : la sortie de secret.exe
            // ne la montre jamais en clair, même si elle passait sous les yeux de quelqu'un.
            using var ephemeral = Ecies.NewKey();
            var request = new JsonObject { ["blob"] = (string?)details["blob"], ["point"] = Convert.ToBase64String(Ecies.Point(ephemeral)) };
            var answer = Convert.FromBase64String(Run(exe, ["wsl-key", "unwrap"], request.ToJsonString()).Trim());
            return Ecies.Decrypt(ephemeral, answer, BridgeEntropy);
        }
        var text = Run("secret-tool", ["lookup", .. Attributes], "").Trim();
        if (text.Length == 0) throw new UserError("clé absente du trousseau de session");
        return Convert.FromBase64String(text);
    }

    public static void Forget()
    {
        if (KeyStore.RememberedBy == SecretService)
        {
            try { Run("secret-tool", ["clear", .. Attributes], ""); }
            catch (UserError e) { Log.Write("trousseau de session : " + e.Message); }
        }
        KeyStore.Forget();
    }

    public static string Describe(string? method) => method switch
    {
        Wsl => "DPAPI de Windows (pont WSL)",
        SecretService => "trousseau de session (Secret Service)",
        _ => "rien",
    };

    static string[] Attributes => ["application", "local-secrets", "vault", KeyStore.VaultId];

    static bool IsWsl =>
        File.Exists("/proc/sys/fs/binfmt_misc/WSLInterop") || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WSL_DISTRO_NAME"));

    // secret.exe de la variante Windows, livré dans le même dépôt : plugins/local-secrets/bin.
    static string? WindowsExe()
    {
        var custom = Environment.GetEnvironmentVariable("LOCAL_SECRETS_WINDOWS_EXE");
        if (!string.IsNullOrWhiteSpace(custom)) return File.Exists(custom) ? custom : null;
        var here = Path.GetDirectoryName(Environment.ProcessPath);
        if (here == null) return null;
        var exe = Path.GetFullPath(Path.Combine(here, "..", "..", "local-secrets", "bin", "secret.exe"));
        return File.Exists(exe) ? exe : null;
    }

    static string Run(string file, string[] args, string input)
    {
        // Un .exe cloné dans le système de fichiers Linux n'a pas toujours le bit d'exécution.
        if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && (File.GetUnixFileMode(file) & UnixFileMode.UserExecute) == 0)
        {
            try { File.SetUnixFileMode(file, File.GetUnixFileMode(file) | UnixFileMode.UserExecute); } catch { }
        }
        var psi = new ProcessStartInfo(file)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        // Le processus Windows démarre dans un dossier Windows : depuis un chemin Linux, cmd et
        // l'interop se plaignent des chemins UNC.
        if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && Directory.Exists("/mnt/c")) psi.WorkingDirectory = "/mnt/c";
        using var p = Process.Start(psi) ?? throw new UserError($"lancement impossible : {file}");
        p.StandardInput.Write(input);
        p.StandardInput.Close();
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(30_000))
        {
            try { p.Kill(); } catch { }
            throw new UserError($"{Path.GetFileName(file)} ne répond pas");
        }
        if (p.ExitCode != 0)
            throw new UserError($"{Path.GetFileName(file)} a échoué : {stderr.Result.Trim()}");
        return stdout.Result;
    }
}
