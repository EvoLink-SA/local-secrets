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
[SupportedOSPlatform("linux")]
static class KeyStore
{
    const string Algorithm = "ecies-p256-hkdf-sha256-aes256gcm";
    const byte BlobVersion = 1;
    const int PointLength = 65;   // point P-256 non compressé : 0x04, X, Y
    static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("local-secrets/ecies-v1");

    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(12);

    public static string FilePath => Path.Combine(Vault.Home, "key.json");

    public static bool Exists => File.Exists(FilePath);

    // Un nom par coffre dans le trousseau : un coffre de test (LOCAL_SECRETS_HOME) ne touche pas au vrai.
    static string KeyringName =>
        "local-secrets:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Paths.Normalize(Vault.Home))))[..16];

    static ECDiffieHellman? cachedPrivate;

    public const string NoKey = "aucune clé de coffre sur ce compte : l'utilisateur lance « secret init » dans son terminal.";
    public const string Locked = "coffre verrouillé : l'utilisateur lance « secret unlock » dans son terminal (une fois par démarrage).";

    // Nouvelle paire de clés, la privée chiffrée par la phrase de passe.
    public static void Init(string passphrase)
    {
        if (Exists) throw new UserError($"une clé existe déjà ({FilePath}). Pour changer la phrase de passe : « secret passwd ».");
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var pkcs8 = key.ExportPkcs8PrivateKey();
        try
        {
            Write(Point(key), pkcs8, passphrase);
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
            Write(PublicPoint(), pkcs8, next);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    // Déverrouille : la clé privée part dans le trousseau noyau, jamais sur le disque en clair.
    public static void Unlock(string passphrase, TimeSpan lifetime)
    {
        var pkcs8 = OpenPrivate(passphrase);
        try
        {
            LinuxNative.Store(KeyringName, pkcs8, lifetime);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }

    public static void Lock()
    {
        LinuxNative.Drop(KeyringName);
        cachedPrivate?.Dispose();
        cachedPrivate = null;
    }

    // Durée de déverrouillage restante, ou null si le coffre est verrouillé.
    public static TimeSpan? UnlockedFor()
    {
        var key = LinuxNative.Read(KeyringName);
        if (key == null) return null;
        CryptographicOperations.ZeroMemory(key);
        return LinuxNative.Remaining(KeyringName) ?? TimeSpan.Zero;
    }

    public static byte[] Protect(byte[] data, byte[] entropy)
    {
        if (!Exists) throw new UserError(NoKey);
        return Encrypt(PublicPoint(), data, entropy);
    }

    public static byte[] Unprotect(byte[] blob, byte[] entropy)
    {
        if (!Exists) throw new UserError(NoKey);
        if (cachedPrivate == null)
        {
            var pkcs8 = LinuxNative.Read(KeyringName) ?? throw new UserError(Locked);
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
        return Decrypt(cachedPrivate, blob, entropy);
    }

    // ECIES : clé éphémère, accord ECDH avec la clé publique du coffre, HKDF-SHA256, AES-256-GCM.
    // L'entropie (le nom du secret) est la donnée associée : relu sous un autre nom, le blob est refusé.
    // Format : version (1) | point éphémère (65) | nonce (12) | tag (16) | chiffré.
    public static byte[] Encrypt(byte[] recipientPoint, byte[] data, byte[] entropy)
    {
        using var recipient = FromPoint(recipientPoint);
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var ephemeralPoint = Point(ephemeral);
        var key = DeriveKey(ephemeral.DeriveRawSecretAgreement(recipient.PublicKey), ephemeralPoint, recipientPoint);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[data.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, data, cipher, tag, entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return [BlobVersion, .. ephemeralPoint, .. nonce, .. tag, .. cipher];
    }

    public static byte[] Decrypt(ECDiffieHellman privateKey, byte[] blob, byte[] entropy)
    {
        const int header = 1 + PointLength + 12 + 16;
        if (blob.Length < header || blob[0] != BlobVersion)
            throw new CryptographicException("format de valeur inconnu (coffre créé par une autre protection ?)");
        var ephemeralPoint = blob[1..(1 + PointLength)];
        var nonce = blob[(1 + PointLength)..(1 + PointLength + 12)];
        var tag = blob[(1 + PointLength + 12)..header];
        var cipher = blob[header..];
        using var ephemeral = FromPoint(ephemeralPoint);
        var key = DeriveKey(privateKey.DeriveRawSecretAgreement(ephemeral.PublicKey), ephemeralPoint, Point(privateKey));
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plain, entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return plain;
    }

    static byte[] DeriveKey(byte[] shared, byte[] ephemeralPoint, byte[] recipientPoint)
    {
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, [.. ephemeralPoint, .. recipientPoint], HkdfInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
        }
    }

    public static byte[] Point(ECDiffieHellman key)
    {
        var q = key.ExportParameters(false).Q;
        return [0x04, .. q.X!, .. q.Y!];
    }

    static ECDiffieHellman FromPoint(byte[] point)
    {
        if (point.Length != PointLength || point[0] != 0x04) throw new CryptographicException("clé publique invalide");
        return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = point[1..33], Y = point[33..] },
        });
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

    // La clé privée est enveloppée comme une sauvegarde portable (PBKDF2-SHA256 + AES-256-GCM).
    static byte[] OpenPrivate(string passphrase)
    {
        if (!Exists) throw new UserError(NoKey);
        var wrapped = ReadFile()["privateKey"] ?? throw new UserError("clé privée absente de key.json");
        return BackupCmd.DecryptPayload(wrapped.ToJsonString(), passphrase);
    }

    static void Write(byte[] publicPoint, byte[] pkcs8, string passphrase)
    {
        var o = new JsonObject
        {
            ["version"] = 1,
            ["algorithm"] = Algorithm,
            ["created"] = DateTime.Now.ToString("o"),
            ["publicKey"] = Convert.ToBase64String(publicPoint),
            ["privateKey"] = JsonNode.Parse(BackupCmd.EncryptPayload(pkcs8, passphrase)),
        };
        Paths.CreatePrivateDirectory(Vault.Home);
        var tmp = FilePath + ".tmp";
        Paths.WritePrivate(tmp, o.ToJsonString(new JsonSerializerOptions { WriteIndented = true, TypeInfoResolver = JsonContext.Default }));
        File.Move(tmp, FilePath, overwrite: true);
    }
}
