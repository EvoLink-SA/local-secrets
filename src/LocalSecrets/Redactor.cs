using System.Net;
using System.Text;

namespace LocalSecrets;

// Un motif à masquer, et ce qui le remplace.
readonly record struct RedactPattern(string Pattern, string Name, string Replacement);

// Masque les valeurs du coffre partout où elles pourraient ressortir.
static class Redactor
{
    public const int MinLength = 4;

    public static string Mask(string name) => $"[secret:{name}]";

    // Toutes les formes sous lesquelles une valeur peut apparaître dans une sortie.
    public static List<RedactPattern> Variants(IEnumerable<(string Name, string Value)> secrets)
    {
        var list = new List<RedactPattern>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void Add(string pattern, string name, string? replacement = null)
        {
            if (pattern.Length >= MinLength && seen.Add(pattern)) list.Add(new(pattern, name, replacement ?? Mask(name)));
        }
        foreach (var (name, value) in secrets)
        {
            if (value.Length < MinLength) continue;

            // Valeur faible (« guest », « secret », « admin123 ») : la masquer partout remplacerait un
            // mot courant dans toutes les sorties, et trahirait la valeur. On ne la masque qu'à côté de
            // son nom (CLÉ=valeur, "clé": "valeur"...).
            if (Classifier.IsWeakSecret(value))
            {
                var key = KeyOf(name);
                foreach (var (before, after) in ContextForms(key))
                    Add(before + value + after, name, before + Mask(name) + after);
                continue;
            }

            Add(value, name);
            Add(Uri.EscapeDataString(value), name);
            Add(WebUtility.UrlEncode(value), name);
            Add(JsEscape(value), name);
            if (value.Contains('\n'))
            {
                Add(value.Replace("\r\n", "\n").Replace("\n", "\r\n"), name);
                Add(JsEscape(value.Replace("\r\n", "\n").Replace("\n", "\r\n")), name);
                // Chaque ligne longue d'une clé PEM, pour couvrir un affichage partiel.
                foreach (var line in value.Split('\n'))
                {
                    var l = line.Trim();
                    if (l.Length >= 16 && !l.StartsWith("-----", StringComparison.Ordinal)) Add(l, name);
                }
            }
        }
        list.Sort((a, b) => b.Pattern.Length.CompareTo(a.Pattern.Length));
        return list;
    }

    // Nom de la variable à partir du nom complet : espace/CLÉ, ou espace/CLÉ.2 pour un doublon.
    static string KeyOf(string name)
    {
        var key = name[(name.LastIndexOf('/') + 1)..];
        var dot = key.LastIndexOf('.');
        return dot > 0 && key[(dot + 1)..].All(char.IsAsciiDigit) ? key[..dot] : key;
    }

    static (string Before, string After)[] ContextForms(string key) =>
    [
        ($"{key}=", ""), ($"{key}: ", ""), ($"{key}:", ""), ($"{key}=\"", "\""), ($"{key}='", "'"),
        ($"\"{key}\": \"", "\""), ($"\"{key}\":\"", "\""),
    ];

    // Échappement façon JSON.stringify, tel qu'on le trouve dans les transcripts .jsonl.
    public static string JsEscape(string s)
    {
        var sb = new StringBuilder(s.Length + 8);
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20) sb.Append($"\\u{(int)c:x4}");
                    else sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    // Remplacement en une seule passe : le masque inséré n'est jamais réexaminé.
    public static string Redact(string s, List<RedactPattern> patterns, ISet<string>? hits = null)
    {
        if (patterns.Count == 0 || s.Length == 0) return s;
        var any = false;
        foreach (var p in patterns)
            if (s.Contains(p.Pattern, StringComparison.Ordinal)) { any = true; break; }
        if (!any) return s;

        var sb = new StringBuilder(s.Length);
        var i = 0;
        while (i < s.Length)
        {
            var matched = false;
            foreach (var p in patterns)
            {
                var pattern = p.Pattern;
                if (i + pattern.Length <= s.Length && s[i] == pattern[0] && string.CompareOrdinal(s, i, pattern, 0, pattern.Length) == 0)
                {
                    sb.Append(p.Replacement);
                    i += pattern.Length;
                    hits?.Add(p.Name);
                    matched = true;
                    break;
                }
            }
            if (!matched) sb.Append(s[i++]);
        }
        return sb.ToString();
    }

    static bool providerRegistered;

    // Motifs en octets pour les sorties de programmes, dans chaque encodage plausible sous Windows.
    public static List<(byte[] Pattern, byte[] Replacement)> BytePatterns(List<RedactPattern> variants, bool allEncodings = true)
    {
        var encodings = new List<Encoding> { new UTF8Encoding(false) };
        if (allEncodings)
        {
            encodings.Add(new UnicodeEncoding(false, false, true));
            try
            {
                if (!providerRegistered) { Encoding.RegisterProvider(CodePagesEncodingProvider.Instance); providerRegistered = true; }
                foreach (var cp in new[] { Native.GetACP(), Native.GetOEMCP(), Native.GetConsoleOutputCP() }.Distinct())
                    if (cp > 0 && cp != 65001)
                        encodings.Add(Encoding.GetEncoding(cp, EncoderFallback.ExceptionFallback, DecoderFallback.ReplacementFallback));
            }
            catch
            {
                // code page indisponible : UTF-8 et UTF-16 restent couverts
            }
        }

        var list = new List<(byte[], byte[])>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var v in variants)
        {
            foreach (var enc in encodings)
            {
                byte[] bytes, replacement;
                try
                {
                    bytes = enc.GetBytes(v.Pattern);
                    replacement = enc.GetBytes(v.Replacement);
                }
                catch (EncoderFallbackException)
                {
                    continue;
                }
                if (bytes.Length == 0 || !seen.Add(System.Convert.ToHexString(bytes))) continue;
                list.Add((bytes, replacement));
            }
        }
        list.Sort((a, b) => b.Item1.Length.CompareTo(a.Item1.Length));
        return list;
    }
}

// Masquage d'un flux d'octets : on retient juste assez d'octets pour ne jamais laisser
// passer le début d'une valeur coupée entre deux lectures.
sealed class StreamRedactor(List<(byte[] Pattern, byte[] Replacement)> patterns)
{
    readonly int lookahead = patterns.Count == 0 ? 1 : patterns.Max(p => p.Pattern.Length);
    byte[] buffer = new byte[32768];
    int length;

    public int Hits { get; private set; }

    public void Process(byte[] chunk, int count, Stream output, bool final)
    {
        if (length + count > buffer.Length) Array.Resize(ref buffer, Math.Max(buffer.Length * 2, length + count));
        Buffer.BlockCopy(chunk, 0, buffer, length, count);
        length += count;

        using var result = new MemoryStream();
        var i = 0;
        while (i < length)
        {
            if (!final && i + lookahead > length) break;
            var m = MatchAt(i);
            if (m >= 0)
            {
                result.Write(patterns[m].Replacement);
                i += patterns[m].Pattern.Length;
                Hits++;
            }
            else
            {
                result.WriteByte(buffer[i]);
                i++;
            }
        }
        Buffer.BlockCopy(buffer, i, buffer, 0, length - i);
        length -= i;
        if (result.Length > 0)
        {
            output.Write(result.GetBuffer(), 0, (int)result.Length);
            output.Flush();
        }
    }

    int MatchAt(int i)
    {
        for (var k = 0; k < patterns.Count; k++)
        {
            var p = patterns[k].Pattern;
            if (i + p.Length <= length && buffer[i] == p[0] && buffer.AsSpan(i, p.Length).SequenceEqual(p)) return k;
        }
        return -1;
    }
}
