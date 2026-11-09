using System.Text;
using System.Text.RegularExpressions;

namespace LocalSecrets;

enum Annotation { None, Secret, Public }

sealed class EnvAssignment
{
    public int StartLine;
    public int EndLine;              // exclusif : une valeur entre guillemets peut couvrir plusieurs lignes
    public string Prefix = "";       // indentation, « export », clé, jusqu'au « = » (ou « : ») inclus
    public string Key = "";
    public string LeadingSpace = "";
    public string RawValue = "";
    public string Value = "";
    public char Quote;
    public string Comment = "";      // fin de ligne après la valeur, espaces inclus
    public Annotation Annotation;

    public string? Reference => EnvFile.ParseReference(Value);
}

// Lecture et réécriture d'un .env sans rien changer d'autre que les valeurs remplacées :
// commentaires, ordre, guillemets, fins de ligne et encodage sont conservés.
sealed partial class EnvFile
{
    public const string HeaderMarker = "local-secrets:";
    public const string Header =
        "# local-secrets: les valeurs secret:// sont chiffrées dans le coffre local. " +
        "Une valeur ajoutée en clair sera chiffrée au prochain accès.";

    public List<string> Lines { get; } = new();
    public List<EnvAssignment> Assignments { get; } = new();
    public byte[] OriginalBytes { get; private set; } = [];

    string eol = "\n";
    Encoding encoding = new UTF8Encoding(false);
    byte[] preamble = [];

    // CLÉ=valeur, et aussi clé:valeur, que certains outils maison acceptent dans un .env : une ligne
    // de ce format resterait sinon invisible, donc jamais chiffrée. La clé peut commencer par des
    // chiffres (3CX_PASSWORD) mais contient au moins une lettre : « 10.0.0.1:22 » reste du texte.
    [GeneratedRegex(@"^(?<pre>[ \t]*(?:export[ \t]+)?(?<key>[0-9]*[A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*[=:])(?<rest>.*)$")]
    private static partial Regex AssignRx();

    public const string IgnoreMarker = "# local-secrets: ignore";

    [GeneratedRegex(@"(?im)^[ \t]*#[ \t]*local-secrets[ \t]*:[ \t]*ignore\b")]
    private static partial Regex IgnoreMarkerRx();

    // Fichier que l'utilisateur ne veut jamais voir converti (fichier de déploiement, par exemple).
    public static bool HasIgnoreMarker(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists && info.Length < 2_000_000 && IgnoreMarkerRx().IsMatch(File.ReadAllText(path));
        }
        catch
        {
            return false;
        }
    }

    public static bool HasIgnoreMarkerText(string text) => IgnoreMarkerRx().IsMatch(text);

    // Lignes données, avec l'encodage et les fins de ligne du fichier d'origine.
    public byte[] RenderLines(IEnumerable<string> lines) => [.. preamble, .. encoding.GetBytes(string.Join(eol, lines))];

    public static bool IsHeaderLine(string line) => line.TrimStart().StartsWith("# local-secrets: les valeurs", StringComparison.Ordinal);

    // Même fichier avec une ligne ajoutée en tête, encodage et fins de ligne conservés.
    public byte[] RenderWithFirstLine(string line)
    {
        var text = line + eol + string.Join(eol, Lines);
        return [.. preamble, .. encoding.GetBytes(text)];
    }

    // Lignes ni vides, ni commentaires, ni affectations : ignorées par le tri, signalées par « secret status ».
    public List<int> UnrecognizedLines()
    {
        var covered = new HashSet<int>();
        foreach (var a in Assignments)
            for (var i = a.StartLine; i < a.EndLine; i++) covered.Add(i);
        var result = new List<int>();
        for (var i = 0; i < Lines.Count; i++)
        {
            var t = Lines[i].Trim();
            if (t.Length > 0 && !t.StartsWith('#') && !covered.Contains(i)) result.Add(i);
        }
        return result;
    }

    [GeneratedRegex(@"^secret://(?<name>[a-z0-9][a-z0-9._\-]*/[0-9]*[A-Za-z_][A-Za-z0-9_.\-]*)$")]
    private static partial Regex ReferenceRx();

    [GeneratedRegex(@"@(?<a>secret|public)\b", RegexOptions.IgnoreCase)]
    private static partial Regex AnnotationRx();

    public static string? ParseReference(string value)
    {
        var m = ReferenceRx().Match(value.Trim());
        return m.Success ? m.Groups["name"].Value : null;
    }

    public static EnvFile Load(string path) => Parse(File.ReadAllBytes(path));

    public static EnvFile Parse(byte[] bytes)
    {
        var f = new EnvFile { OriginalBytes = bytes };
        var text = f.Decode(bytes);
        f.eol = text.Contains("\r\n") ? "\r\n" : "\n";
        foreach (var raw in text.Split('\n'))
            f.Lines.Add(raw.EndsWith('\r') ? raw[..^1] : raw);
        f.ParseAssignments();
        return f;
    }

    string Decode(byte[] b)
    {
        if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF)
        {
            preamble = [0xEF, 0xBB, 0xBF];
            return encoding.GetString(b, 3, b.Length - 3);
        }
        if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE)
        {
            encoding = new UnicodeEncoding(bigEndian: false, byteOrderMark: false);
            preamble = [0xFF, 0xFE];
            return encoding.GetString(b, 2, b.Length - 2);
        }
        if (b.Length >= 2 && b[0] == 0xFE && b[1] == 0xFF)
        {
            encoding = new UnicodeEncoding(bigEndian: true, byteOrderMark: false);
            preamble = [0xFE, 0xFF];
            return encoding.GetString(b, 2, b.Length - 2);
        }
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(b);
        }
        catch (DecoderFallbackException)
        {
            // Latin-1 relit et réécrit chaque octet à l'identique.
            encoding = Encoding.Latin1;
            return encoding.GetString(b);
        }
    }

    void ParseAssignments()
    {
        var pending = Annotation.None;
        for (var i = 0; i < Lines.Count; i++)
        {
            var line = Lines[i];
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith('#'))
            {
                pending = AnnotationOf(trimmed) ?? Annotation.None;
                continue;
            }
            var m = AssignRx().Match(line);
            if (!m.Success)
            {
                pending = Annotation.None;
                continue;
            }

            var a = new EnvAssignment { StartLine = i, Prefix = m.Groups["pre"].Value, Key = m.Groups["key"].Value };
            var rest = m.Groups["rest"].Value;
            var ws = 0;
            while (ws < rest.Length && rest[ws] is ' ' or '\t') ws++;
            a.LeadingSpace = rest[..ws];
            var body = rest[ws..];
            var last = i;

            if (body.Length > 0 && body[0] is '"' or '\'' or '`')
            {
                var q = body[0];
                var acc = body;
                var close = FindClose(acc, q);
                var j = i;
                while (close < 0 && j + 1 < Lines.Count && j - i < 500)
                {
                    j++;
                    acc += "\n" + Lines[j];
                    close = FindClose(acc, q);
                }
                if (close >= 0)
                {
                    a.Quote = q;
                    a.RawValue = acc[..(close + 1)];
                    var inner = acc[1..close];
                    a.Value = q == '"' ? Unescape(inner) : inner;
                    a.Comment = acc[(close + 1)..];
                    last = j;
                }
                else
                {
                    ParseUnquoted(a, body);
                }
            }
            else
            {
                ParseUnquoted(a, body);
            }

            a.EndLine = last + 1;
            a.Annotation = AnnotationOf(a.Comment) ?? pending;
            pending = Annotation.None;
            Assignments.Add(a);
            i = last;
        }
    }

    static Annotation? AnnotationOf(string comment)
    {
        var m = AnnotationRx().Match(comment);
        if (!m.Success) return null;
        return m.Groups["a"].Value.Equals("secret", StringComparison.OrdinalIgnoreCase) ? Annotation.Secret : Annotation.Public;
    }

    static int FindClose(string s, char q)
    {
        for (var i = 1; i < s.Length; i++)
        {
            if (q == '"' && s[i] == '\\') { i++; continue; }
            if (s[i] == q) return i;
        }
        return -1;
    }

    static void ParseUnquoted(EnvAssignment a, string body)
    {
        // « # » n'ouvre un commentaire que précédé d'un espace (ou en tête après un espace).
        var hash = -1;
        if (body.StartsWith('#') && a.LeadingSpace.Length > 0) hash = 0;
        else
        {
            for (var k = 1; k < body.Length; k++)
                if (body[k] == '#' && body[k - 1] is ' ' or '\t') { hash = k; break; }
        }
        var value = (hash >= 0 ? body[..hash] : body).TrimEnd();
        a.RawValue = value;
        a.Value = value;
        a.Comment = body[value.Length..];
    }

    static string Unescape(string s)
    {
        if (!s.Contains('\\')) return s;
        var sb = new StringBuilder(s.Length);
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] != '\\' || i + 1 >= s.Length) { sb.Append(s[i]); continue; }
            var n = s[++i];
            switch (n)
            {
                case 'n': sb.Append('\n'); break;
                case 'r': sb.Append('\r'); break;
                case 't': sb.Append('\t'); break;
                case '"': sb.Append('"'); break;
                case '\\': sb.Append('\\'); break;
                default: sb.Append('\\').Append(n); break;
            }
        }
        return sb.ToString();
    }

    // Valeur prête à écrire dans un .env, entre guillemets si nécessaire.
    public static string Quote(string value)
    {
        if (value.Length > 0 && !value.Any(c => char.IsWhiteSpace(c) || c is '#' or '"' or '\'' or '`' or '\\'))
            return value;
        var escaped = value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n");
        return "\"" + escaped + "\"";
    }

    public byte[] Render(IReadOnlyDictionary<EnvAssignment, string> newValues, bool addHeader, IEnumerable<string>? append = null)
    {
        var output = new List<string>();
        if (addHeader && !Lines.Any(l => l.Contains(HeaderMarker))) output.Add(Header);
        var byStart = Assignments.ToDictionary(a => a.StartLine);
        for (var i = 0; i < Lines.Count; i++)
        {
            if (byStart.TryGetValue(i, out var a) && newValues.TryGetValue(a, out var value))
            {
                output.Add(a.Prefix + a.LeadingSpace + value + a.Comment);
                i = a.EndLine - 1;
            }
            else
            {
                output.Add(Lines[i]);
            }
        }
        if (append != null)
        {
            var endsWithNewLine = output.Count > 0 && output[^1].Length == 0;
            if (endsWithNewLine) output.RemoveAt(output.Count - 1);
            output.AddRange(append);
            output.Add("");
        }
        var text = string.Join(eol, output);
        return [.. preamble, .. encoding.GetBytes(text)];
    }

    // Réécrit le fichier sur place après avoir écrasé l'ancien contenu par des zéros.
    // C'est un effacement au mieux : un SSD ou le journal NTFS peuvent garder des traces.
    public static void WriteInPlace(string path, byte[] content)
    {
        FileStream fs;
        try { fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { fs = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite); }
        using (fs)
        {
            var oldLength = (int)fs.Length;
            fs.Write(new byte[oldLength]);
            fs.Flush(flushToDisk: true);
            fs.Position = 0;
            fs.Write(content);
            fs.SetLength(content.Length);
            fs.Flush(flushToDisk: true);
        }
    }
}
