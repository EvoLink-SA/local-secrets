using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LocalSecrets;

// Sauvegarde portable du coffre, chiffrée par phrase de passe (PBKDF2-SHA256 + AES-256-GCM).
// Indispensable pour changer de PC ou de système : le coffre lui-même ne se relit que sous le même
// compte, sur la même machine. C'est aussi le passage d'un coffre Windows vers Linux.
static class BackupCmd
{
    const int Iterations = 600_000;

    public static int Backup(string[] args)
    {
        Ui.RequireInteractive("secret backup");
        var partial = args.Contains("--partial");
        var file = Path.GetFullPath(args.FirstOrDefault(a => !a.StartsWith('-'))
                                    ?? $"local-secrets-{DateTime.Now:yyyyMMdd-HHmm}.lsbackup");

        // Une sauvegarde qui omettrait des secrets sans le dire perdrait ces valeurs au changement de poste.
        var vault = Vault.Load();
        var unreadable = new List<string>();
        var values = Vault.DecryptAll(vault, unreadable);
        if (unreadable.Count > 0 && !partial)
            throw new UserError($"{unreadable.Count} secret(s) illisible(s) ici ({string.Join(", ", unreadable)}) : sauvegarde " +
                                "annulée. Relance avec --partial pour sauvegarder seulement les autres.");

        var pass = Ui.ReadSecret("Phrase de passe pour la sauvegarde (12 caractères minimum) : ");
        if (pass.Length < 12) throw new UserError("phrase trop courte, 12 caractères minimum.");
        if (Ui.ReadSecret("Confirmation : ") != pass) throw new UserError("les deux saisies diffèrent.");

        var secrets = new JsonObject();
        foreach (var (name, value) in values) secrets[name] = value;
        var namespaces = new JsonObject();
        foreach (var (ns, entry) in vault.Namespaces) namespaces[ns] = entry.Path;
        var plain = new JsonObject { ["secrets"] = secrets, ["namespaces"] = namespaces };

        Paths.WritePrivate(file, EncryptPayload(Encoding.UTF8.GetBytes(plain.ToJsonString()), pass));
        if (unreadable.Count > 0) Console.WriteLine($"{unreadable.Count} secret(s) illisible(s) laissé(s) de côté (--partial).");
        Console.WriteLine($"{secrets.Count} secret(s) sauvegardé(s) dans {file}.");
        var settings = Settings.Load();
        settings.LastBackup = DateTime.Now;
        settings.Save();
        Console.WriteLine("Garde la phrase de passe à part : sans elle, la sauvegarde est illisible.");
        return 0;
    }

    public static int Restore(string[] args)
    {
        Ui.RequireInteractive("secret restore");
        var file = args.FirstOrDefault(a => !a.StartsWith('-')) ?? throw new UserError("usage : secret restore FICHIER");
        var pass = Ui.ReadSecret("Phrase de passe de la sauvegarde : ");
        var plain = JsonNode.Parse(DecryptPayload(File.ReadAllText(file), pass)) as JsonObject
                    ?? throw new UserError("contenu de sauvegarde illisible");
        var secrets = plain["secrets"] as JsonObject ?? new JsonObject();
        var namespaces = plain["namespaces"] as JsonObject ?? new JsonObject();
        var count = Vault.Update(d =>
        {
            foreach (var (ns, path) in namespaces)
                if (!d.Namespaces.ContainsKey(ns))
                    d.Namespaces[ns] = new NamespaceEntry { Path = (string?)path ?? "", Created = DateTime.Now };
            var n = 0;
            foreach (var (name, value) in secrets)
            {
                if (value is null) continue;
                Vault.Set(d, name, (string)value!, null);
                n++;
            }
            return n;
        });
        Console.WriteLine($"{count} secret(s) restauré(s) dans le coffre de ce compte.");
        return 0;
    }

    public static string EncryptPayload(byte[] plain, string passphrase)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Iterations, HashAlgorithmName.SHA256, 32);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plain, cipher, tag);
        CryptographicOperations.ZeroMemory(key);
        var o = new JsonObject
        {
            ["format"] = "local-secrets-backup",
            ["version"] = 1,
            ["kdf"] = "pbkdf2-sha256",
            ["iterations"] = Iterations,
            ["salt"] = Convert.ToBase64String(salt),
            ["nonce"] = Convert.ToBase64String(nonce),
            ["tag"] = Convert.ToBase64String(tag),
            ["data"] = Convert.ToBase64String(cipher),
        };
        return o.ToJsonString(new JsonSerializerOptions { WriteIndented = true, TypeInfoResolver = JsonContext.Default });
    }

    public static byte[] DecryptPayload(string json, string passphrase)
    {
        JsonObject o;
        try { o = JsonNode.Parse(json) as JsonObject ?? throw new FormatException(); }
        catch (Exception) { throw new UserError("ce fichier n'est pas une sauvegarde local-secrets lisible."); }
        if ((string?)o["format"] != "local-secrets-backup") throw new UserError("ce fichier n'est pas une sauvegarde local-secrets.");

        var iterations = (int?)o["iterations"] ?? Iterations;
        var salt = Convert.FromBase64String((string)o["salt"]!);
        var nonce = Convert.FromBase64String((string)o["nonce"]!);
        var tag = Convert.FromBase64String((string)o["tag"]!);
        var cipher = Convert.FromBase64String((string)o["data"]!);
        var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, 32);
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new UserError("phrase de passe incorrecte, ou fichier abîmé.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return plain;
    }
}
