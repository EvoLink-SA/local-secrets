using System.Text.RegularExpressions;

namespace LocalSecrets;

// Garde-fous sur les commandes shell de Claude. Ils évitent les accidents ; ce n'est pas
// un bac à sable contre un agent qui voudrait vraiment contourner (pas de sandbox sous Windows).
static partial class Guards
{
    public const string VaultDenied =
        "Le coffre local-secrets ne se lit pas directement. Utilise « secret list » pour voir les noms " +
        "et « secret run -- <commande> » pour utiliser les valeurs.";

    [GeneratedRegex(@"\bsecret(?:\.exe)?[""']?\s+(?<verb>reveal|undo|unprotect|backup|restore|rm|remove|shell|env)\b", RegexOptions.IgnoreCase)]
    private static partial Regex ForbiddenVerbRx();

    [GeneratedRegex(@"local-secrets[\\/]+(vault\.json|backups|config\.json)", RegexOptions.IgnoreCase)]
    private static partial Regex VaultPathRx();

    [GeneratedRegex(@"ProtectedData\]?\s*::\s*Unprotect|CryptUnprotectData|Unprotect-CmsMessage|ConvertFrom-SecureString\b[^|;\r\n]*-AsPlainText|GetNetworkCredential\(\)\s*\.\s*Password", RegexOptions.IgnoreCase)]
    private static partial Regex DpapiRx();

    [GeneratedRegex(@"\bsecret(?:\.exe)?[""']?\s+run\b", RegexOptions.IgnoreCase)]
    private static partial Regex SecretRunRx();

    [GeneratedRegex(@"\bdocker(?:\.exe)?\s+compose\b|\bdocker-compose\b", RegexOptions.IgnoreCase)]
    private static partial Regex ComposeRx();

    [GeneratedRegex(@"\b(up|run|create|start|restart|config|convert|exec|build|watch)\b", RegexOptions.IgnoreCase)]
    private static partial Regex ComposeVerbRx();

    [GeneratedRegex(@"\b(?:ssh|plink)(?:\.exe)?\s", RegexOptions.IgnoreCase)]
    private static partial Regex RemoteRx();

    [GeneratedRegex(@"\bsecret(?:\.exe)?[""']?\s+config\s+(?:masking\s+off|convert\s+off|allow)\b", RegexOptions.IgnoreCase)]
    private static partial Regex ConfigOffRx();

    // Lecture du presse-papiers ou capture d'écran depuis un shell.
    [GeneratedRegex(@"Get-Clipboard|Clipboard\]::Get|\.GetText\(\)|CopyFromScreen|pbpaste|xclip|xsel|PrintWindow", RegexOptions.IgnoreCase)]
    public static partial Regex ScreenOrClipboardRx();

    public const string DisplayDenied =
        "Une fenêtre local-secrets affiche (ou vient d'afficher) des secrets à l'utilisateur : capture d'écran et " +
        "lecture du presse-papiers sont bloquées pendant l'affichage et dix minutes après.";

    // Claude Code lancé depuis un terminal où le profil a déjà chargé les secrets du projet :
    // les commandes reçoivent les vraies valeurs, même sans secret run.
    public static bool AlreadyInjected(string envPath)
    {
        try
        {
            var refs = EnvFile.Load(envPath).Assignments.Where(a => a.Reference != null).Select(a => a.Key).ToList();
            return refs.Count > 0 && refs.All(k =>
                Environment.GetEnvironmentVariable(k) is { Length: > 0 } v && !v.StartsWith("secret://", StringComparison.Ordinal));
        }
        catch
        {
            return false;
        }
    }

    // Un masque concret, tel qu'il apparaît dans une sortie : [masqué:CLÉ] ou [secret:espace/CLÉ].
    [GeneratedRegex(@"\[masqué:[0-9]*[A-Za-z_][A-Za-z0-9_.\-]*\]|\[secret:[a-z0-9][a-z0-9._\-]*/[0-9]*[A-Za-z_][A-Za-z0-9_.\-]*\]")]
    public static partial Regex MaskMarkerRx();

    public const string MaskDenied =
        "Ce contenu contient un masque local-secrets ([masqué:...] ou [secret:...]) : ce n'est pas la vraie valeur. " +
        "L'écrire remplacerait la valeur réelle par le masque. Ne touche pas à ces lignes. Pour une valeur du coffre dans " +
        "une commande, écris secret://espace/CLÉ avec secret run ; une valeur [masqué:...] n'est pas récupérable, " +
        "demande à l'utilisateur de l'enregistrer avec secret set si tu en as besoin.";

    [GeneratedRegex(@"""(?<p>[^""\r\n]*\.env(?:\.[\w\-]+)?)""|'(?<p>[^'\r\n]*\.env(?:\.[\w\-]+)?)'|(?<p>[^\s""'`|&;<>()=,]*\.env(?:\.[\w\-]+)?)(?![\w\-])")]
    private static partial Regex EnvPathRx();

    [GeneratedRegex(@"^\s*(?:cd|Set-Location|sl|pushd)\s+(?:""(?<d>[^""]+)""|'(?<d>[^']+)'|(?<d>[^\s;&|]+))\s*(?:&&|;|\|\|)", RegexOptions.IgnoreCase)]
    private static partial Regex LeadingCdRx();

    [GeneratedRegex(@"\$(?:env:)?\{?(?<n>[0-9]*[A-Za-z_][A-Za-z0-9_]*)")]
    private static partial Regex VariableRx();

    [GeneratedRegex(@"--project-directory[ =](?:""(?<d>[^""]+)""|(?<d>\S+))|(?:-f|--file)[ =](?:""(?<f>[^""]+)""|(?<f>\S+))")]
    private static partial Regex ComposeLocationRx();

    // Refus immédiats, avant toute conversion.
    public static string? CheckForbidden(string text)
    {
        foreach (Match m in ForbiddenVerbRx().Matches(text))
        {
            var verb = m.Groups["verb"].Value.ToLowerInvariant();
            // « secret undo --dry-run » ne fait que lister : autorisé.
            if (verb is "undo" or "unprotect" && CommandAt(text, m.Index).Contains("--dry-run", StringComparison.Ordinal)) continue;
            return $"« secret {verb} » est réservé à l'utilisateur, dans son propre terminal. " +
                   "Si c'est nécessaire, demande-lui de le lancer lui-même.";
        }
        if (ConfigOffRx().IsMatch(text))
            return "Couper le masquage ou autoriser une clé est réservé à l'utilisateur, dans son propre terminal.";
        if (VaultPathRx().IsMatch(text)) return VaultDenied;
        if (MaskMarkerRx().IsMatch(text)) return MaskDenied;
        if (DpapiRx().IsMatch(text))
            return "local-secrets bloque le déchiffrement direct de secrets (DPAPI, SecureString en clair). " +
                   "Utilise « secret run », qui injecte les valeurs sans les afficher.";
        return null;
    }

    // La commande qui commence à cet endroit, jusqu'au prochain séparateur (; & | ou fin de ligne).
    static string CommandAt(string text, int index)
    {
        var end = text.IndexOfAny([';', '&', '|', '\n'], index);
        return end < 0 ? text[index..] : text[index..end];
    }

    [GeneratedRegex(@"^\s*(?:(?:cd|Set-Location|sl|pushd)\s+(?:""[^""]+""|'[^']+'|[^\s;&|]+)\s*(?:&&|;)\s*)?&?\s*[""']?(?:[^\s""']*[\\/])?secret(?:\.exe)?[""']?\s+(?:status|import|generate|setenv|list|doctor|undo|unprotect|show)\b(?<rest>.*)$", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex SafeSecretCommandRx();

    // Une commande « secret » seule qui n'affiche aucune valeur (status, import, generate...) : elle
    // peut citer un .env hors du projet ou marqué sans qu'on la bloque. Pas d'enchaînement autorisé.
    public static bool IsSafeSecretCommand(string command)
    {
        var m = SafeSecretCommandRx().Match(command);
        if (!m.Success) return false;
        var rest = m.Groups["rest"].Value;
        return !rest.Contains("&&") && !rest.Contains("||") && !rest.Contains(';') && !rest.Contains('|') && !rest.Contains('\n');
    }

    // Pour les outils MCP qui n'exécutent rien : seul l'envoi d'un masque à la place d'une valeur compte.
    public static string? CheckMaskOnly(string text) => MaskMarkerRx().IsMatch(text) ? MaskDenied : null;

    // Vérifications qui dépendent de l'état des fichiers, après conversion.
    public static string? CheckCommand(string command, string cwd)
    {
        var dir = EffectiveCwd(command, cwd);
        if (SecretRunRx().Match(command) is { Success: true } run)
            return CheckExpansion(command[(run.Index + run.Length)..], dir);

        // « ssh hôte "docker compose up" » tourne sur le serveur, avec ses propres fichiers : pas concerné.
        var compose = ComposeRx().Match(command);
        var remote = RemoteRx().Match(command);
        if (compose.Success && !(remote.Success && remote.Index < compose.Index) && ComposeVerbRx().IsMatch(command[compose.Index..]))
        {
            var envPath = Path.Combine(ComposeDir(command, dir), ".env");
            if (File.Exists(envPath) && Paths.HasReferences(envPath) && !AlreadyInjected(envPath))
                return "Le .env de ce projet contient des références secret://. Sans « secret run », Docker Compose recevrait ces " +
                       "références à la place des vraies valeurs (une base pourrait être initialisée avec un mauvais mot de passe). " +
                       "Préfixe la commande docker compose par « secret run -- », par exemple : secret run -- docker compose up -d";
        }
        return null;
    }

    // Les variables $X entre guillemets doubles sont développées par le shell de Claude avant
    // que secret run ne démarre : elles arriveraient vides.
    static string? CheckExpansion(string tail, string dir)
    {
        var envPath = Path.Combine(dir, ".env");
        if (!File.Exists(envPath) || AlreadyInjected(envPath)) return null;
        HashSet<string> keys;
        try { keys = EnvFile.Load(envPath).Assignments.Select(a => a.Key).ToHashSet(StringComparer.OrdinalIgnoreCase); }
        catch { return null; }
        foreach (Match m in VariableRx().Matches(tail))
        {
            var name = m.Groups["n"].Value;
            if (!keys.Contains(name) || InsideSingleQuotes(tail, m.Index)) continue;
            return $"« ${name} » serait remplacé par ton shell avant que secret run ne démarre, donc par une valeur vide. " +
                   $"Écris secret://{name} dans l'argument (secret run le remplace), ou passe par bash -c '...' ou " +
                   "pwsh -Command '...' entre guillemets simples pour que la variable soit lue à l'intérieur.";
        }
        return null;
    }

    static bool InsideSingleQuotes(string s, int index)
    {
        var inSingle = false;
        var inDouble = false;
        for (var i = 0; i < index; i++)
        {
            if (s[i] == '\'' && !inDouble) inSingle = !inSingle;
            else if (s[i] == '"' && !inSingle) inDouble = !inDouble;
        }
        return inSingle;
    }

    static string EffectiveCwd(string command, string cwd)
    {
        var m = LeadingCdRx().Match(command);
        if (!m.Success) return cwd;
        var dir = Paths.Full(m.Groups["d"].Value, cwd);
        return dir != null && Directory.Exists(dir) ? dir : cwd;
    }

    static string ComposeDir(string command, string cwd)
    {
        foreach (Match m in ComposeLocationRx().Matches(command))
        {
            if (m.Groups["d"].Success && Paths.Full(m.Groups["d"].Value, cwd) is { } d && Directory.Exists(d)) return d;
            if (m.Groups["f"].Success && Paths.Full(m.Groups["f"].Value, cwd) is { } f && Path.GetDirectoryName(f) is { } fd) return fd;
        }
        return cwd;
    }

    // Fichiers .env cités dans un texte de commande, résolus en chemins absolus existants.
    public static List<string> EnvFilesIn(string text, string cwd)
    {
        var result = new List<string>();
        var dirs = new List<string> { cwd };
        var effective = EffectiveCwd(text, cwd);
        if (!effective.Equals(cwd, StringComparison.OrdinalIgnoreCase)) dirs.Insert(0, effective);

        foreach (Match m in EnvPathRx().Matches(text))
        {
            var raw = m.Groups["p"].Value;
            if (raw.Length == 0) continue;
            foreach (var dir in dirs)
            {
                if (raw.IndexOfAny(['*', '?']) >= 0)
                {
                    var full = Paths.Full(raw, dir);
                    var folder = full == null ? null : Path.GetDirectoryName(full);
                    if (folder == null || !Directory.Exists(folder)) continue;
                    try
                    {
                        result.AddRange(Directory.EnumerateFiles(folder, Path.GetFileName(full!))
                            .Where(f => Paths.IsEnvFileName(Path.GetFileName(f))));
                    }
                    catch
                    {
                        // motif invalide : ignoré
                    }
                }
                else if (Paths.Full(raw, dir) is { } full && Paths.IsEnvFile(full))
                {
                    result.Add(full);
                    break;
                }
            }
        }
        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
