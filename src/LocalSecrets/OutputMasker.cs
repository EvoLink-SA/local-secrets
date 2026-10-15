using System.Text.RegularExpressions;

namespace LocalSecrets;

// Masquage générique : repère dans une sortie les paires clé/valeur et les formes de secrets,
// sans connaître les valeurs à l'avance (.env distant, docker inspect, printenv, réponse d'API...).
// Les valeurs masquées ne sont stockées nulle part.
static partial class OutputMasker
{
    public static string Marker(string name) => $"[masqué:{name}]";

    static readonly Regex[] PairPatterns = [JsonPairRx(), QuotedEnvRx(), YamlRx(), AssignQuotedRx(), AssignRx(), ConnStrRx()];

    public static string Mask(string text, ICollection<string> neverMask, ISet<string> hits)
    {
        if (string.IsNullOrEmpty(text)) return text;
        var r = PrivateKeyBlockRx().Replace(text, _ => Hit(hits, "CLE_PRIVEE"));
        r = Classifier.KnownTokenInTextRx().Replace(r, _ => Hit(hits, "JETON"));
        r = Classifier.JwtInTextRx().Replace(r, _ => Hit(hits, "JETON"));
        r = UrlPasswordRx().Replace(r, m => Classifier.IsIgnorableValue(m.Groups["v"].Value) ? m.Value : Swap(m, Hit(hits, "MOT_DE_PASSE_URL")));
        foreach (var rx in PairPatterns) r = rx.Replace(r, m => Pair(m, neverMask, hits, tableRow: false));
        // Tableau « NOM   valeur » (Get-ChildItem env:) : la valeur doit en plus avoir l'air d'un secret.
        r = TableRx().Replace(r, m => Pair(m, neverMask, hits, tableRow: true));
        return r;
    }

    // Masqué seulement si le nom est celui d'un secret ou si la valeur a une forme de secret connue
    // (voir Classifier.IsSecretPair) : jamais sur la seule allure de la valeur.
    static string Pair(Match m, ICollection<string> neverMask, ISet<string> hits, bool tableRow)
    {
        var key = m.Groups["k"].Value;
        var value = m.Groups["v"].Value.Trim().Trim('"', '\'').Replace("\\\"", "\"").Replace("\\\\", "\\");
        if (neverMask.Contains(key, StringComparer.OrdinalIgnoreCase)) return m.Value;
        if (!Classifier.IsSecretPair(key, value, valueMustLookSecret: tableRow)) return m.Value;
        return Swap(m, Hit(hits, key));
    }

    static string Swap(Match m, string replacement)
    {
        var v = m.Groups["v"];
        var start = v.Index - m.Index;
        return m.Value[..start] + replacement + m.Value[(start + v.Length)..];
    }

    static string Hit(ISet<string> hits, string name)
    {
        hits.Add(name);
        return Marker(name);
    }

    [GeneratedRegex(@"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)")]
    private static partial Regex PrivateKeyBlockRx();

    [GeneratedRegex(@"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@'""]+:(?<v>[^\s@/'""]+)@")]
    private static partial Regex UrlPasswordRx();

    // "clé": "valeur"
    [GeneratedRegex(@"""(?<k>[A-Za-z_][A-Za-z0-9_.\-]{0,60})""\s*:\s*""(?<v>(?:[^""\\\r\n]|\\.){1,4000})""")]
    private static partial Regex JsonPairRx();

    // "CLÉ=valeur" (liste Env de docker inspect)
    [GeneratedRegex(@"""(?<k>[A-Za-z_][A-Za-z0-9_]{0,60})=(?<v>(?:[^""\\\r\n]|\\.){1,4000})""")]
    private static partial Regex QuotedEnvRx();

    // clé: valeur ou clé:valeur, en début de ligne (YAML, docker compose config, Format-List, .env maison)
    [GeneratedRegex(@"(?m)^(?<pre>[ \t]*(?:\d+\t)?(?:-[ \t]+)?)(?<k>[A-Za-z_][A-Za-z0-9_.\-]{0,60})[ \t]*:[ \t]*(?:""(?<v>[^""\r\n]*)""|'(?<v>[^'\r\n]*)'|(?<v>[^\s""'][^\r\n]*?))(?:[ \t]+#[^\r\n]*)?[ \t]*\r?$")]
    private static partial Regex YamlRx();

    // clé = "valeur", clé: 'valeur', 'clé': "valeur" (code, INI, TOML, dictionnaires)
    [GeneratedRegex(@"(?<![\w$.])(?<k>[A-Za-z_][A-Za-z0-9_.\-]{0,60})[""']?[ \t]*[:=][ \t]*(?<q>[""'])(?<v>[^""'\r\n]{1,500})\k<q>")]
    private static partial Regex AssignQuotedRx();

    // CLÉ=valeur sans espaces (.env, printenv, set, --password=...)
    [GeneratedRegex(@"(?<![\w$.])(?<k>[A-Za-z_][A-Za-z0-9_.\-]{0,60})=(?<v>[^\s""'`,;&|<>()\[\]{}]{1,1000})")]
    private static partial Regex AssignRx();

    // Password = x; dans une chaîne de connexion
    [GeneratedRegex(@"(?i)(?<k>password|pwd|accountkey|sharedaccesskey|client_secret|clientsecret)[ \t]*=[ \t]*(?<v>[^;'""\s\[]{1,500})")]
    private static partial Regex ConnStrRx();

    [GeneratedRegex(@"(?m)^(?<k>[A-Za-z_][A-Za-z0-9_]{2,60})[ \t]{2,}(?<v>[^\s\[][^\r\n]*?)[ \t]*\r?$")]
    private static partial Regex TableRx();
}
