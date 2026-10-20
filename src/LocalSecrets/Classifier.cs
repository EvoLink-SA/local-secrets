using System.Text.RegularExpressions;

namespace LocalSecrets;

readonly record struct Verdict(bool Secret, string Reason);

// Décide, sans IA et sans rien envoyer nulle part, si une valeur de .env est sensible.
// Règle d'or : dans le doute, chiffrer. Une valeur chiffrée à tort ne casse rien.
static partial class Classifier
{
    static readonly string[] SensitiveParts =
    [
        "PASSWORD", "PASSWD", "PASSPHRASE", "SECRET", "TOKEN", "APIKEY", "CREDENTIAL", "PRIVATEKEY",
        "ACCESSKEY", "SECRETKEY", "CONNECTIONSTRING", "CONNSTR", "MOTDEPASSE", "WEBHOOK",
        // allemand, italien, français
        "PASSWORT", "KENNWORT", "GEHEIM", "SEGRETO", "JETON",
    ];

    static readonly HashSet<string> SensitiveTokens =
    [
        "PASS", "PWD", "PW", "MDP", "KEY", "KEYS", "PIN", "OTP", "TOTP", "SALT", "PEPPER", "AUTH", "COOKIE",
        "SESSION", "SIGNATURE", "SIGNING", "HMAC", "JWT", "BEARER", "DSN", "CRED", "CREDS", "LICENSE", "LICENCE",
        "SEED", "MNEMONIC", "PRIVATE", "PSK", "COMMUNITY", "ENCRYPTION", "HOOK",
        "CLE", "CLEF", "SCHLUESSEL", "SCHLUSSEL", "CHIAVE",
    ];

    // Une URL de webhook est elle-même le secret : jamais de dérogation pour ces noms.
    static readonly HashSet<string> StrongNames = ["WEBHOOK", "HOOK"];

    static readonly HashSet<string> NeutralTokens =
    [
        "PATH", "FILE", "DIR", "FOLDER", "LOCATION", "NAME", "ID", "PUBLIC", "PUB", "ENABLED", "ENABLE", "DISABLED",
        "DISABLE", "LENGTH", "LEN", "MIN", "MAX", "SIZE", "TTL", "EXPIRY", "EXPIRES", "EXPIRE", "EXPIRATION", "TIMEOUT",
        "LIFETIME", "DURATION", "ALGORITHM", "ALGO", "TYPE", "MODE", "METHOD", "HEADER", "PROVIDER", "DRIVER", "STORE",
        "BACKEND", "ENGINE", "ISSUER", "AUDIENCE", "SCOPE", "SCOPES", "PREFIX", "FORMAT", "VERSION", "PORT", "HOST",
        "URL", "URI", "ENDPOINT", "DOMAIN", "REGION", "COUNT", "LIMIT", "INTERVAL", "STRATEGY", "POLICY", "LEVEL",
        "USER", "USERNAME", "SECURE", "SAMESITE", "COLUMN", "FIELD", "TABLE",
    ];

    static readonly HashSet<string> UserTokens = ["USER", "USERNAME", "USR", "LOGIN", "ACCOUNT", "EMAIL", "MAIL", "OWNER", "UID", "UPN"];

    public static Verdict Classify(string key, string value, Annotation annotation)
    {
        if (annotation == Annotation.Secret) return new(true, "annotation @secret");
        if (annotation == Annotation.Public) return new(false, "annotation @public");
        var v = value.Trim();
        if (v.Length == 0) return new(false, "vide");
        // ${VAR} est une référence, résolue par Docker ou l'application : on juge le reste de la valeur.
        var rest = WithoutInterpolation(v);
        if (rest.Length != v.Length)
        {
            if (rest.Trim().Length == 0) return new(false, "référence à une variable");
            v = rest.Trim();
        }
        if (StrongShape(v) is { } strong) return new(true, strong);
        if (BoolRx().IsMatch(v)) return new(false, "booléen");

        var tokens = Tokens(key);
        var compact = string.Concat(tokens);
        var sensitive = SensitiveParts.FirstOrDefault(p => compact.Contains(p, StringComparison.Ordinal))
                        ?? tokens.FirstOrDefault(SensitiveTokens.Contains);
        if (sensitive != null)
        {
            if (!StrongNames.Contains(sensitive))
            {
                // Un mot de passe n'a jamais la forme d'une IP, d'un FQDN, d'une URL ou d'un chemin.
                if (StructuralKind(v) is { } structural) return new(false, structural);
                var neutral = tokens.FirstOrDefault(NeutralTokens.Contains);
                if (neutral != null && PlainKind(v) is { } plain) return new(false, $"{plain}, nom neutre ({neutral})");
            }
            return new(true, $"nom ({sensitive})");
        }
        if (tokens.Any(UserTokens.Contains)) return new(false, "nom d'utilisateur");
        if (PlainKind(v) is { } kind) return new(false, kind);
        // Nom anodin : seule une valeur vraiment aléatoire est chiffrée. Avec un nom neutre (ID, TABLE,
        // NAME...), ou sur la seule allure d'un mot de passe, on laisse en clair : trop de faux positifs
        // (identifiants de tenant, noms de tables) pour un gain faible.
        if (tokens.FirstOrDefault(NeutralTokens.Contains) is { } neutralName) return new(false, $"nom neutre ({neutralName})");
        if (IsHighEntropy(v)) return new(true, "chaîne aléatoire");
        return new(false, "valeur simple");
    }

    // Retire les références ${VAR}, ${VAR:-défaut} et $(commande), et une valeur qui n'est que $VAR :
    // ce sont des renvois vers d'autres variables, pas des secrets.
    public static string WithoutInterpolation(string v)
    {
        var t = v.Trim();
        if (BareVariableRx().IsMatch(t)) return "";
        return t.Contains('$') ? InterpolationRx().Replace(t, "") : t;
    }

    [GeneratedRegex(@"\$\{[A-Za-z_][A-Za-z0-9_]*(?:[:]?[\-?+=][^}]*)?\}|\$\([^)]*\)")]
    private static partial Regex InterpolationRx();

    [GeneratedRegex(@"^\$[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex BareVariableRx();

    // Valeur d'un secret trop faible pour être masquée partout : mot courant, court, ou lisible.
    public static bool IsWeakSecret(string v) =>
        v.Length < 8 || (v.Length < 12 && CharClasses(v) <= 2) || (PlainKind(v) != null && !IsHighEntropy(v));

    static List<string> Tokens(string key) =>
        CamelRx().Replace(key, "$1_$2")
            .Split(['_', '-', '.'], StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.ToUpperInvariant())
            .ToList();

    static string? StrongShape(string v)
    {
        if (PrivateKeyRx().IsMatch(v)) return "clé privée";
        if (KnownTokenRx().IsMatch(v) || JwtRx().IsMatch(v)) return "jeton reconnu";
        if (UrlCredRx().IsMatch(v)) return "URL avec identifiants";
        if (ConnStrRx().IsMatch(v)) return "chaîne de connexion avec mot de passe";
        if (WebhookRx().IsMatch(v)) return "URL de webhook";
        if (UrlSecretParamRx().IsMatch(v)) return "URL avec jeton";
        return null;
    }

    static string? StructuralKind(string v)
    {
        if (IPv4Rx().IsMatch(v) || (v.Count(c => c == ':') >= 2 && IPv6Rx().IsMatch(v))) return "adresse IP";
        if (HostRx().IsMatch(v) && v == v.ToLowerInvariant()) return "nom d'hôte";
        if (IsPlainUrl(v)) return "URL";
        if (RootedPathRx().IsMatch(v)) return "chemin";
        return null;
    }

    public static string? PlainKind(string v)
    {
        if (BoolRx().IsMatch(v)) return "booléen";
        if (NumberRx().IsMatch(v)) return "nombre";
        if (DurationRx().IsMatch(v)) return "durée";
        if (DateRx().IsMatch(v)) return "date";
        if (StructuralKind(v) is { } s) return s;
        if (HostRx().IsMatch(v)) return "nom d'hôte";
        if (EmailRx().IsMatch(v)) return "e-mail";
        if (UuidRx().IsMatch(v)) return "identifiant UUID";
        if (HostPortRx().IsMatch(v)) return "hôte et port";
        if (RelPathRx().IsMatch(v) && v.Split('/').All(p => !LooksRandom(p))) return "chemin";
        if ((v.Contains(':') || v.Contains('/') || v.Contains('@')) && ImageRx().IsMatch(v)) return "image ou version";
        if (VersionRx().IsMatch(v)) return "version";
        if (IsIdentifier(v)) return "identifiant";
        if (WordRx().IsMatch(v) && CharClasses(v) <= 2 && !LooksRandom(v)) return "mot simple";
        if (v.Any(char.IsWhiteSpace) && !LooksRandom(string.Concat(v.Where(c => !char.IsWhiteSpace(c))))) return "texte";
        if (v.IndexOfAny([',', ';']) >= 0)
        {
            var items = v.Split(',', ';').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            if (items.Count > 1 && items.All(x => PlainKind(x) != null)) return "liste";
        }
        return null;
    }

    static bool IsPlainUrl(string v)
    {
        if (!UrlRx().IsMatch(v) || UrlCredRx().IsMatch(v) || UrlSecretParamRx().IsMatch(v) || WebhookRx().IsMatch(v)) return false;
        foreach (var part in v.Split('/', '?', '&', '=', '#', ':', '.'))
            if (LooksRandom(part)) return false;
        return true;
    }

    static bool IsIdentifier(string v)
    {
        var segments = v.Split('-', '_', '.');
        return segments.Length > 1
               && segments.All(s => s.Length > 0 && SegmentRx().IsMatch(s) && !LooksRandom(s));
    }

    public static bool IsHighEntropy(string v) =>
        v.Length >= 16 && !v.Any(char.IsWhiteSpace) && CharClasses(v) >= 2 && Entropy(v) >= 3.5;

    public static bool IsPasswordLike(string v) =>
        v.Length is >= 6 and <= 64 && !v.Any(char.IsWhiteSpace) && CharClasses(v) >= 3;

    static bool LooksRandom(string s) => s.Length >= 16 && Entropy(s) >= 3.5;

    static int CharClasses(string v)
    {
        int lower = 0, upper = 0, digit = 0, other = 0;
        foreach (var c in v)
        {
            if (char.IsLower(c)) lower = 1;
            else if (char.IsUpper(c)) upper = 1;
            else if (char.IsDigit(c)) digit = 1;
            else other = 1;
        }
        return lower + upper + digit + other;
    }

    public static double Entropy(string s)
    {
        if (s.Length == 0) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var c in s) counts[c] = counts.GetValueOrDefault(c) + 1;
        double h = 0;
        foreach (var n in counts.Values)
        {
            var p = (double)n / s.Length;
            h -= p * Math.Log2(p);
        }
        return h;
    }

    // Détection dans un texte libre (message tapé dans le chat).
    public static List<string> ScanText(string text)
    {
        var found = new List<string>();
        if (PrivateKeyRx().IsMatch(text)) found.Add("une clé privée");
        if (KnownTokenInTextRx().IsMatch(text) || JwtInTextRx().IsMatch(text)) found.Add("un jeton d'API reconnaissable");
        if (UrlCredRx().IsMatch(text)) found.Add("une URL contenant un mot de passe");
        foreach (Match m in LabeledRx().Matches(text))
        {
            var value = m.Groups["v"].Value.Trim('"', '\'', '«', '»', '`', ',', '.', ';', ')', '(');
            if (LooksLikeSecretValue(value))
            {
                found.Add($"une valeur après « {m.Groups["label"].Value.Trim()} »");
                break;
            }
        }
        // Lignes collées depuis un .env, un YAML ou un JSON : CLÉ=valeur, clé: valeur, "clé": "valeur".
        foreach (Match m in AssignmentInTextRx().Matches(text))
        {
            var key = m.Groups["k"].Value;
            var value = m.Groups["v"].Value.Trim().Trim('"', '\'', '`').TrimEnd(',', ';', ')');
            if (IsSecretPair(key, value))
            {
                found.Add($"une valeur sensible pour {key}");
                break;
            }
        }
        return found;
    }

    // Vide, sans aucune lettre ni chiffre (« ... », « *** »), référence, variable ou modèle.
    static bool IsPlaceholder(string v) =>
        v.Length == 0 || !v.Any(char.IsLetterOrDigit) || v.StartsWith("secret://", StringComparison.OrdinalIgnoreCase)
        || v[0] is '$' or '%' or '<' or '{' || PlaceholderRx().IsMatch(v);

    // Valeur à ne jamais masquer : vide, modèle, référence, variable, code, ou déjà masquée.
    public static bool IsIgnorableValue(string v) => IsPlaceholder(v.Trim()) || CodeReferenceRx().IsMatch(v.Trim());

    public static bool IsSensitiveName(string key)
    {
        var tokens = Tokens(key);
        var compact = string.Concat(tokens);
        return SensitiveParts.Any(p => compact.Contains(p, StringComparison.Ordinal)) || tokens.Any(SensitiveTokens.Contains);
    }

    public enum NameKind { Neutral, Weak, Strong }

    // Noms de secret sans ambiguïté. Un mot doit finir par PASSWORD, TOKEN... : TOKENIZER ou
    // SECRETARY ne comptent pas, contrairement au tri des .env qui cherche le mot n'importe où.
    static readonly string[] StrongWordEndings =
    [
        "PASSWORD", "PASSWD", "PASSPHRASE", "SECRET", "SECRETS", "TOKEN", "TOKENS", "APIKEY", "CREDENTIAL", "CREDENTIALS",
        "PASSWORT", "KENNWORT", "GEHEIM", "SEGRETO", "JETON", "MOTDEPASSE",
    ];
    static readonly HashSet<string> StrongExactTokens = ["PASS", "PWD", "PW", "MDP", "PSK"];
    static readonly string[] StrongCompactParts =
        ["APIKEY", "ACCESSKEY", "SECRETKEY", "PRIVATEKEY", "CONNECTIONSTRING", "CONNSTR", "MOTDEPASSE", "CLIENTSECRET", "WEBHOOK", "ACCOUNTKEY", "SHAREDACCESSKEY", "SHAREDACCESSSIGNATURE"];

    public static NameKind OutputNameKind(string key)
    {
        var tokens = Tokens(key);
        var compact = string.Concat(tokens);
        if (tokens.Any(t => StrongExactTokens.Contains(t) || StrongWordEndings.Any(w => t.EndsWith(w, StringComparison.Ordinal)))
            || StrongCompactParts.Any(p => compact.Contains(p, StringComparison.Ordinal)))
            return NameKind.Strong;
        return tokens.Any(SensitiveTokens.Contains) ? NameKind.Weak : NameKind.Neutral;
    }

    // Une paire clé/valeur vue dans une sortie ou un message est-elle un secret ?
    // Plus strict que le tri des .env : on masque sur le nom ou sur une forme de secret reconnue,
    // jamais sur la seule allure de la valeur. Une regex de matcher, une empreinte git, un GUID ou
    // du base64 sous un nom anodin restent donc visibles.
    // valueMustLookSecret : même sous un nom de secret, la valeur doit avoir l'air d'un secret
    // (utilisé pour les tableaux « NOM   valeur », où un mot ordinaire n'est pas une valeur).
    public static bool IsSecretPair(string key, string value, bool valueMustLookSecret = false)
    {
        var v = WithoutInterpolation(value).Trim();
        if (v.Length < 4 || IsIgnorableValue(v)) return false;
        if (StrongShape(v) != null) return true;
        var kind = OutputNameKind(key);
        if (kind == NameKind.Neutral) return false;
        var looksSecret = (IsHighEntropy(v) || IsPasswordLike(v)) && !LooksStructured(v);
        if ((kind == NameKind.Weak || valueMustLookSecret) && !looksSecret) return false;
        return Classify(key, v, Annotation.None).Secret;
    }

    // Plusieurs morceaux lisibles (unix:path=/run/user/1000/bus, tcp:db:5432) : une adresse ou un
    // chemin, pas une chaîne aléatoire.
    static bool LooksStructured(string v)
    {
        var parts = v.Split(['/', ':', '=', ',', ';', '@', ' '], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2
               && parts.All(p => NumberRx().IsMatch(p) || (WordRx().IsMatch(p) && CharClasses(p) <= 2 && !LooksRandom(p)));
    }

    static bool LooksLikeSecretValue(string v)
    {
        if (v.Length < 6 || IsPlaceholder(v) || CodeReferenceRx().IsMatch(v)) return false;
        if (v[0] is '/' or ':') return false;
        if (BoolRx().IsMatch(v) || EmailRx().IsMatch(v) || StructuralKind(v) != null) return false;
        return IsPasswordLike(v) || IsHighEntropy(v);
    }

    const string TokenPattern =
        @"sk-[A-Za-z0-9_\-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|rk_(?:live|test)_[A-Za-z0-9]{16,}" +
        @"|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_\-]{20,}" +
        @"|xox[abprs]-[A-Za-z0-9\-]{10,}|xapp-[A-Za-z0-9\-]{10,}|(?:AKIA|ASIA)[A-Z0-9]{16}" +
        @"|AIza[A-Za-z0-9_\-]{30,}|ya29\.[A-Za-z0-9_\-]{20,}|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}" +
        @"|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{30,}|pypi-[A-Za-z0-9_\-]{30,}|dop_v1_[a-f0-9]{40,}" +
        @"|shp(?:at|ss|ca|pa)_[a-fA-F0-9]{20,}|\d{8,10}:AA[A-Za-z0-9_\-]{30,}";

    const string JwtPattern = @"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}";

    [GeneratedRegex("^(?:" + TokenPattern + ")$")] private static partial Regex KnownTokenRx();
    [GeneratedRegex(@"(?<![A-Za-z0-9_\-])(?:" + TokenPattern + @")(?![A-Za-z0-9_\-])")] internal static partial Regex KnownTokenInTextRx();
    [GeneratedRegex("^" + JwtPattern + "$")] private static partial Regex JwtRx();
    [GeneratedRegex(@"(?<![A-Za-z0-9_\-])" + JwtPattern)] internal static partial Regex JwtInTextRx();
    [GeneratedRegex(@"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|PuTTY-User-Key-File")] private static partial Regex PrivateKeyRx();
    [GeneratedRegex(@"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^\s@/]+@")] private static partial Regex UrlCredRx();
    [GeneratedRegex(@"(?i)(^|;)\s*(password|pwd|accountkey|sharedaccesskey|sharedaccesssignature|clientsecret|client_secret)\s*=\s*[^;\s]")] private static partial Regex ConnStrRx();
    [GeneratedRegex(@"(?i)hooks\.slack\.com/|discord(app)?\.com/api/webhooks/|webhook\.office\.com/|outlook\.office\.com/webhook|api\.telegram\.org/bot")] private static partial Regex WebhookRx();
    [GeneratedRegex(@"(?i)[?&](token|access_token|api_key|apikey|key|sig|signature|password|pwd|secret|auth|code)=[^&\s]{8,}")] private static partial Regex UrlSecretParamRx();
    [GeneratedRegex(@"(?i)(?<![\w])(?<label>mot\s+de\s+passe|mdp|password|passwd|pwd|passphrase|token|jeton|api[\s_\-]?key|cl[ée]\s+(?:d'|de\s+l')?api|secret|pass)(?![\w])(?!://)\s*(?:est|is|=|:|=>|->|vaut)?\s*[:=]?\s*[«""'`]?\s*(?<v>[^\s""'»`]{6,})")] private static partial Regex LabeledRx();

    [GeneratedRegex(@"(?<![\w$.])[""']?(?<k>[A-Za-z_][A-Za-z0-9_.\-]{1,60})[""']?[ \t]*[:=][ \t]*(?<v>""[^""\r\n]{1,200}""|'[^'\r\n]{1,200}'|[^\s""'`]{1,200})")] private static partial Regex AssignmentInTextRx();
    [GeneratedRegex(@"^(x{3,}.*|\*+|\.{3,}|changeme|change_me|change-me|example|exemple|placeholder|todo|tbd|secret|password|motdepasse|mot_de_passe|your[_\-].*|my[_\-].*|none|null|undefined|redacted|\[secret:.*\]|\[masqué:.*\]|\[secret:.*|\[masqué:.*)$", RegexOptions.IgnoreCase)] private static partial Regex PlaceholderRx();
    [GeneratedRegex(@"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+(\(.*)?$|\(|^[A-Za-z_][\w.]*\[")] private static partial Regex CodeReferenceRx();
    [GeneratedRegex(@"^(true|false|yes|no|on|off|oui|non|null|none|nil|enabled|disabled)$", RegexOptions.IgnoreCase)] private static partial Regex BoolRx();
    [GeneratedRegex(@"^[+\-]?\d+([.,]\d+)?$")] private static partial Regex NumberRx();
    [GeneratedRegex(@"^\d+(ms|s|m|h|d|w|min|sec)$", RegexOptions.IgnoreCase)] private static partial Regex DurationRx();
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}([T ][0-9:.+\-Z]+)?$")] private static partial Regex DateRx();
    [GeneratedRegex(@"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?(:\d{1,5})?$")] private static partial Regex IPv4Rx();
    [GeneratedRegex(@"^\[?[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}\]?(/\d{1,3})?$")] private static partial Regex IPv6Rx();
    [GeneratedRegex(@"^(localhost|(?=.{4,253}$)([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?)(:\d{1,5})?$")] private static partial Regex HostRx();
    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9_\-]*:\d{1,5}$")] private static partial Regex HostPortRx();
    [GeneratedRegex(@"^[^@\s:/]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")] private static partial Regex EmailRx();
    [GeneratedRegex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")] private static partial Regex UuidRx();
    [GeneratedRegex(@"^([A-Za-z]:[\\/]|\\\\|/|~[\\/]|\.{1,2}[\\/])")] private static partial Regex RootedPathRx();
    [GeneratedRegex(@"^[A-Za-z0-9._\-]+(/[A-Za-z0-9._\-]+)+/?$")] private static partial Regex RelPathRx();
    [GeneratedRegex(@"^[a-z0-9]+([._/\-][a-z0-9]+)*(:[A-Za-z0-9._\-]+)?(@sha256:[a-f0-9]{64})?$")] private static partial Regex ImageRx();
    [GeneratedRegex(@"^v?\d+(\.\d+)+([\-+][0-9A-Za-z.\-]+)?$")] private static partial Regex VersionRx();
    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,40}$")] private static partial Regex WordRx();
    [GeneratedRegex(@"^([a-z]+|[A-Z]+|[A-Z][a-z]+|[0-9]+)$")] private static partial Regex SegmentRx();
    [GeneratedRegex(@"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$")] private static partial Regex UrlRx();
    [GeneratedRegex(@"([a-z0-9])([A-Z])")] private static partial Regex CamelRx();
}
