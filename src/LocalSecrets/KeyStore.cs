using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LocalSecrets;

// Clé du coffre sous Linux : une paire ECDH P-256 propre à ce compte.
// La clé publique chiffre : toujours disponible, les hooks convertissent un .env même coffre verrouillé.
// La clé privée déchiffre : rangée dans key.json, chiffrée par la phrase de passe de l'utilisateur, et
// gardée déverrouillée dans le trousseau noyau de l'utilisateur pour une durée limitée (secret unlock).
// Avec « secret unlock --remember », une copie est confiée à un gardien de session (DPAPI de Windows
// sous WSL, trousseau de session sur un bureau Linux) : le coffre se rouvre alors tout seul.
[SupportedOSPlatform("linux")]
static class KeyStore
{
    const string Algorithm = "ecies-p256-hkdf-sha256-aes256gcm";

    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(12);

    public static string FilePath => Path.Combine(Vault.Home, "key.json");

    // Présent après « secret lock » : le coffre ne se rouvre pas tout seul avant le prochain unlock.
    static string LockedFlag => Path.Combine(Vault.Home, "locked");

    public static bool Exists => File.Exists(FilePath);

    // Un nom par coffre : un coffre de test (LOCAL_SECRETS_HOME) ne touche pas au vrai.
    public static string VaultId =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Paths.Normalize(Vault.Home))))[..16];

    static string KeyringName => "local-secrets:" + VaultId;

    static ECDiffieHellman? cachedPrivate;

    public const string NoKey = "aucune clé de coffre sur ce compte : l'utilisateur lance « secret init » dans son terminal.";
    public const string Locked = "coffre verrouillé : l'utilisateur lance « secret unlock » dans un autre terminal (une fois par démarrage).";

    // Nouvelle paire de clés, la privée chiffrée par la phrase de passe.
    public static void Init(string passphrase)
    {
        if (Exists) throw new UserError($"une clé existe déjà ({FilePath}). Pour changer la phrase de passe : « secret passwd ».");
        using var key = Ecies.NewKey();
        var pkcs8 = key.ExportPkcs8PrivateKey();
        try
        {
            Write(o =>
            {
                o["version"] = 1;
                o["algorithm"] = Algorithm;
                o["created"] = DateTime.Now.ToString("o");
                o["publicKey"] = Convert.ToBase64String(Ecies.Point(key));
                o["privateKey"] = JsonNode.Parse(BackupCmd.EncryptPayload(pkcs8, passphrase));
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    public static void ChangePassphrase(string current, string next)
    {
        var pkcs8 = OpenPrivate(current);
        try
        {
            Write(o => o["privateKey"] = JsonNode.Parse(BackupCmd.EncryptPayload(pkcs8, next)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    // La clé privée est enveloppée comme une sauvegarde portable (PBKDF2-SHA256 + AES-256-GCM).
    public static byte[] OpenPrivate(string passphrase)
    {
        if (!Exists) throw new UserError(NoKey);
        var wrapped = ReadFile()["privateKey"] ?? throw new UserError("clé privée absente de key.json");
        return BackupCmd.DecryptPayload(wrapped.ToJsonString(), passphrase);
    }

    // Déverrouille : la clé privée part dans le trousseau noyau, jamais sur le disque en clair.
    public static void Open(byte[] pkcs8, TimeSpan lifetime)
    {
        LinuxNative.Store(KeyringName, pkcs8, lifetime);
        File.Delete(LockedFlag);
    }

    public static void Lock()
    {
        LinuxNative.Drop(KeyringName);
        cachedPrivate?.Dispose();
        cachedPrivate = null;
        if (Exists) Paths.WritePrivate(LockedFlag, DateTime.Now.ToString("o"));
    }

    // Durée de déverrouillage restante, ou null si le coffre est verrouillé.
    public static TimeSpan? UnlockedFor()
    {
        var key = LinuxNative.Read(KeyringName);
        if (key == null) return null;
        CryptographicOperations.ZeroMemory(key);
        return LinuxNative.Remaining(KeyringName) ?? TimeSpan.Zero;
    }

    // Gardien de session qui garde une copie de la clé privée : « wsl-dpapi », « secret-service » ou null.
    public static string? RememberedBy => Exists ? (string?)ReadFile()["remember"]?["method"] : null;

    public static bool LockedByUser => File.Exists(LockedFlag);

    public static void Remember(string method, JsonObject details)
    {
        details["method"] = method;
        Write(o => o["remember"] = details);
    }

    public static JsonObject? RememberDetails => Exists ? ReadFile()["remember"] as JsonObject : null;

    public static void Forget() => Write(o => o.Remove("remember"));

    // Coffre verrouillé mais mémorisé par un gardien de session, et pas reverrouillé exprès :
    // on le rouvre sans phrase de passe. Vrai si le coffre est déverrouillé à la sortie.
    public static bool TryAutoUnlock()
    {
        if (!Exists) return false;
        if (UnlockedFor() != null) return true;
        if (LockedByUser || RememberedBy == null) return false;
        try
        {
            var pkcs8 = SessionKeeper.Recall();
            try
            {
                Open(pkcs8, DefaultLifetime);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
            Log.Write($"coffre rouvert automatiquement ({RememberedBy})");
            return true;
        }
        catch (Exception e)
        {
            Log.Write($"réouverture automatique impossible ({RememberedBy}) : {e.Message}");
            return false;
        }
    }

    public static byte[] Protect(byte[] data, byte[] entropy)
    {
        if (!Exists) throw new UserError(NoKey);
        return Ecies.Encrypt(PublicPoint(), data, entropy);
    }

    public static byte[] Unprotect(byte[] blob, byte[] entropy)
    {
        if (!Exists) throw new UserError(NoKey);
        if (cachedPrivate == null)
        {
            var pkcs8 = LinuxNative.Read(KeyringName);
            if (pkcs8 == null && TryAutoUnlock()) pkcs8 = LinuxNative.Read(KeyringName);
            if (pkcs8 == null) throw new UserError(Locked);
            try
            {
                var key = ECDiffieHellman.Create();
                key.ImportPkcs8PrivateKey(pkcs8, out _);
                cachedPrivate = key;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }
        return Ecies.Decrypt(cachedPrivate, blob, entropy);
    }

    static JsonObject ReadFile()
    {
        try
        {
            return JsonNode.Parse(File.ReadAllText(FilePath)) as JsonObject ?? throw new FormatException();
        }
        catch (Exception e) when (e is not UserError)
        {
            throw new UserError($"clé du coffre illisible ({FilePath}) : {e.Message}");
        }
    }

    static byte[] PublicPoint() => Convert.FromBase64String((string?)ReadFile()["publicKey"] ?? throw new UserError("clé publique absente de key.json"));

    // Modifie key.json en gardant les autres champs, par fichier temporaire puis renommage.
    static void Write(Action<JsonObject> change)
    {
        var o = Exists ? ReadFile() : new JsonObject();
        change(o);
        Paths.CreatePrivateDirectory(Vault.Home);
        var tmp = FilePath + ".tmp";
        Paths.WritePrivate(tmp, o.ToJsonString(new JsonSerializerOptions { WriteIndented = true, TypeInfoResolver = JsonContext.Default }));
        File.Move(tmp, FilePath, overwrite: true);
    }
}
