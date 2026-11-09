using System.Globalization;
using System.Runtime.Versioning;

namespace LocalSecrets;

// Clé du coffre sous Linux : secret init, unlock, lock, passwd.
// La phrase de passe ne passe jamais par Claude : ces commandes sont refusées quand c'est lui qui lance.
[SupportedOSPlatform("linux")]
static class KeyCmd
{
    public static int Run(string verb, string[] args) => verb switch
    {
        "init" => Init(args),
        "unlock" => Unlock(args),
        "lock" => Lock(args),
        _ => Passwd(args),
    };

    static int Init(string[] args)
    {
        Require("secret init");
        if (KeyStore.Exists) throw new UserError($"une clé existe déjà ({KeyStore.FilePath}). Pour changer la phrase de passe : « secret passwd ».");
        var pass = NewPassphrase(args, "Phrase de passe du coffre (12 caractères minimum) : ");
        KeyStore.Init(pass);
        Console.WriteLine($"Clé du coffre créée : {KeyStore.FilePath}.");
        Console.WriteLine("Garde la phrase de passe à part : sans elle, les secrets de ce compte sont illisibles.");
        if (!args.Contains("--no-unlock")) Unlock(pass, args);
        return 0;
    }

    static int Unlock(string[] args)
    {
        Require("secret unlock");
        if (!KeyStore.Exists) throw new UserError(KeyStore.NoKey);
        Unlock(Passphrase(args, "Phrase de passe du coffre : "), args);
        return 0;
    }

    // --forget : retire aussi la copie confiée au gardien de session (le coffre ne se rouvrira plus seul).
    static int Lock(string[] args)
    {
        KeyStore.Lock();
        if (args.Contains("--forget") && KeyStore.RememberedBy is { } method)
        {
            SessionKeeper.Forget();
            Console.WriteLine($"Copie de la clé retirée : {SessionKeeper.Describe(method)}.");
        }
        Console.WriteLine(KeyStore.RememberedBy is { } kept
            ? $"Coffre verrouillé. Il ne se rouvrira pas seul avant ton prochain « secret unlock » (clé gardée par : {SessionKeeper.Describe(kept)})."
            : "Coffre verrouillé : « secret unlock » pour utiliser de nouveau les valeurs.");
        return 0;
    }

    static int Passwd(string[] args)
    {
        Require("secret passwd");
        var current = Passphrase(args, "Phrase de passe actuelle : ");
        var next = NewPassphrase(args, "Nouvelle phrase de passe (12 caractères minimum) : ");
        KeyStore.ChangePassphrase(current, next);
        Console.WriteLine("Phrase de passe changée. Le déverrouillage en cours reste valable.");
        return 0;
    }

    // --remember : une copie de la clé est confiée au gardien de session (DPAPI sous WSL, trousseau de
    // session sur un bureau), et le coffre se rouvre ensuite tout seul, sans phrase de passe.
    static void Unlock(string pass, string[] args)
    {
        var lifetime = Lifetime(args);
        var pkcs8 = KeyStore.OpenPrivate(pass);
        try
        {
            KeyStore.Open(pkcs8, lifetime);
            if (args.Contains("--remember")) SessionKeeper.Remember(pkcs8);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(pkcs8);
        }
        Console.WriteLine($"Coffre déverrouillé pour {Describe(lifetime)} (jusqu'au redémarrage au plus). « secret lock » pour le refermer avant.");
        if (KeyStore.RememberedBy is { } method)
            Console.WriteLine($"Clé mémorisée par : {SessionKeeper.Describe(method)}. Le coffre se rouvrira seul, sans phrase de passe " +
                              "(« secret lock --forget » pour l'oublier).");
    }

    // Réservé à l'utilisateur ; --stdin permet l'automatisation (tests, scripts), jamais depuis Claude.
    static void Require(string what)
    {
        if (Ui.FromClaude)
            throw new UserError($"« {what} » demande la phrase de passe du coffre : réservé à l'utilisateur, dans son terminal. " +
                                "Claude ne doit jamais la recevoir.");
    }

    static string NewPassphrase(string[] args, string prompt)
    {
        if (args.Contains("--stdin"))
        {
            var p = ReadLine();
            if (p.Length < 12) throw new UserError("phrase trop courte, 12 caractères minimum.");
            return p;
        }
        if (!Ui.IsInteractive) throw new UserError("saisie impossible : lance cette commande dans ton terminal (ou avec --stdin).");
        var pass = Ui.ReadSecret(prompt);
        if (pass.Length < 12) throw new UserError("phrase trop courte, 12 caractères minimum.");
        if (Ui.ReadSecret("Confirmation : ") != pass) throw new UserError("les deux saisies diffèrent.");
        return pass;
    }

    static string Passphrase(string[] args, string prompt)
    {
        if (args.Contains("--stdin")) return ReadLine();
        if (!Ui.IsInteractive) throw new UserError("saisie impossible : lance cette commande dans ton terminal (ou avec --stdin).");
        return Ui.ReadSecret(prompt);
    }

    static string ReadLine() => Console.In.ReadLine() ?? throw new UserError("aucune phrase de passe reçue sur l'entrée standard.");

    // --for 8h, 30m, 2d ; 12 h par défaut, 7 jours au plus.
    static TimeSpan Lifetime(string[] args)
    {
        var i = Array.IndexOf(args, "--for");
        if (i < 0) return KeyStore.DefaultLifetime;
        var text = i + 1 < args.Length ? args[i + 1].Trim().ToLowerInvariant() : "";
        if (text.Length < 2 || !int.TryParse(text[..^1], NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n <= 0)
            throw new UserError($"durée illisible : « {text} » (exemples : 30m, 8h, 2d)");
        var lifetime = text[^1] switch
        {
            'm' => TimeSpan.FromMinutes(n),
            'h' => TimeSpan.FromHours(n),
            'd' => TimeSpan.FromDays(n),
            _ => throw new UserError($"durée illisible : « {text} » (exemples : 30m, 8h, 2d)"),
        };
        return lifetime > TimeSpan.FromDays(7) ? TimeSpan.FromDays(7) : lifetime;
    }

    static string Describe(TimeSpan t) =>
        t.TotalDays >= 1 && t.TotalHours % 24 == 0 ? $"{(int)t.TotalDays} jour(s)"
        : t.TotalHours >= 1 ? $"{(int)t.TotalHours} h{(t.Minutes > 0 ? $" {t.Minutes:00}" : "")}"
        : $"{(int)t.TotalMinutes} min";
}
