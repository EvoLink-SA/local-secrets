using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace LocalSecrets;

// Point d'entrée des hooks Claude Code : JSON sur l'entrée standard, JSON sur la sortie.
static class Hooks
{
    static readonly HashSet<string> FileTools = ["Read", "Edit", "MultiEdit", "Write", "NotebookEdit"];
    static readonly HashSet<string> WriteTools = ["Edit", "MultiEdit", "Write", "NotebookEdit"];
    static readonly HashSet<string> ShellTools = ["Bash", "PowerShell"];

    // Outils MCP qui exécutent des commandes (terminal intégré, shells distants...).
    static readonly string[] ExecTools = ["terminal", "shell", "exec", "run_command", "command", "ssh"];

    // Racine du projet ouvert : celle que Claude Code donne aux hooks, sinon le dossier courant.
    static string ProjectRoot(string cwd)
    {
        var dir = Environment.GetEnvironmentVariable("CLAUDE_PROJECT_DIR");
        return !string.IsNullOrWhiteSpace(dir) && Directory.Exists(dir) ? dir : cwd;
    }

    public static int Run(string evt)
    {
        JsonObject? input = null;
        try
        {
            input = JsonNode.Parse(ReadStdin()) as JsonObject;
        }
        catch (Exception e)
        {
            Log.Write("hook : entrée illisible : " + e.Message);
        }
        input ??= new JsonObject();

        JsonObject? output;
        try
        {
            output = evt switch
            {
                "session-start" => SessionStart(input),
                "pre-tool-use" => PreToolUse(input),
                "post-tool-use" => PostToolUse(input),
                "user-prompt-submit" => UserPromptSubmit(input),
                _ => null,
            };
        }
        catch (Exception e)
        {
            Log.Write($"hook {evt} : {e.GetType().Name} : {e.Message}");
            // Échec sur un accès qui vise un .env : on bloque plutôt que de laisser lire en clair.
            output = evt == "pre-tool-use" && (input["tool_input"]?.ToJsonString().Contains(".env", StringComparison.OrdinalIgnoreCase) ?? false)
                ? Deny($"local-secrets n'a pas pu protéger ce fichier ({e.Message}). Accès bloqué par précaution.")
                : null;
        }
        if (output != null) Emit(output);
        return 0;
    }

    static JsonObject? PreToolUse(JsonObject input)
    {
        var tool = Str(input, "tool_name") ?? "";
        var ti = input["tool_input"] as JsonObject ?? new JsonObject();
        var cwd = Str(input, "cwd") ?? Environment.CurrentDirectory;
        var root = ProjectRoot(cwd);
        var converted = new List<ConversionReport>();

        // Pendant (et juste après) l'affichage de secrets à l'utilisateur : pas de capture d'écran
        // ni de lecture du presse-papiers.
        var (displayOpen, displayRecent) = DisplayGuard.State();
        if (displayRecent)
        {
            var isComputer = tool.StartsWith("mcp__", StringComparison.Ordinal) && tool.Contains("computer", StringComparison.OrdinalIgnoreCase);
            var text = ShellTools.Contains(tool) ? Str(ti, "command") ?? "" : string.Join(" ", Strings(ti));
            if ((isComputer && (displayOpen || text.Contains("clipboard", StringComparison.OrdinalIgnoreCase) || tool.Contains("clipboard", StringComparison.OrdinalIgnoreCase)))
                || (ShellTools.Contains(tool) && Guards.ScreenOrClipboardRx().IsMatch(text)))
                return Deny(Guards.DisplayDenied);
        }

        if (FileTools.Contains(tool))
        {
            var full = Paths.Full(Str(ti, "file_path") ?? Str(ti, "notebook_path"), cwd);
            if (full == null) return null;
            if (Paths.IsVaultPath(full)) return Deny(Guards.VaultDenied);
            if (WriteTools.Contains(tool) && WritesMask(ti, full)) return Deny(Guards.MaskDenied);
            if (Paths.IsEnvFile(full) && Protect(full, converted, root) is { } refused) return Deny(refused);
            if (tool == "Read" && Paths.IsPrivateKeyFile(full)) return Deny(PrivateKeyMessage(full));
            if (tool == "Read" && Paths.IsCredentialFile(full)) return Deny(CredentialFileMessage(full));
        }
        else if (tool == "Grep")
        {
            // Une recherche dans un dossier ne convertit rien : seul le fichier précis visé peut l'être.
            // Les valeurs qui ressortiraient sont couvertes par le masquage des sorties.
            var full = Paths.Full(Str(ti, "path") ?? ".", cwd);
            if (full == null) return null;
            if (Paths.IsVaultPath(full)) return Deny(Guards.VaultDenied);
            if (File.Exists(full))
            {
                if (Paths.IsEnvFile(full) && Protect(full, converted, root) is { } refused) return Deny(refused);
                if (Paths.IsPrivateKeyFile(full)) return Deny(PrivateKeyMessage(full));
                if (Paths.IsCredentialFile(full)) return Deny(CredentialFileMessage(full));
            }
        }
        else if (ShellTools.Contains(tool))
        {
            var command = Str(ti, "command") ?? "";
            if (Guards.CheckForbidden(command) is { } forbidden) return Deny(forbidden);
            if (!Guards.IsSafeSecretCommand(command))
                foreach (var f in Guards.EnvFilesIn(command, cwd))
                    if (Protect(f, converted, root) is { } refused) return Deny(refused, converted);
            if (Guards.CheckCommand(command, cwd) is { } reason) return Deny(reason, converted);
        }
        else if (tool.StartsWith("mcp__", StringComparison.Ordinal))
        {
            // Les commandes réservées ne concernent que les outils MCP qui exécutent quelque chose
            // (terminal) ; pour les autres (liste de tâches, messages...), seul l'envoi d'un masque compte.
            var text = string.Join(" ", Strings(ti));
            var executes = ExecTools.Any(t => tool.Contains(t, StringComparison.OrdinalIgnoreCase));
            if ((executes ? Guards.CheckForbidden(text) : Guards.CheckMaskOnly(text)) is { } forbidden) return Deny(forbidden);
            if (executes)
                foreach (var f in Guards.EnvFilesIn(text, cwd))
                    if (Protect(f, converted, root) is { } refused) return Deny(refused, converted);
        }

        if (converted.Count == 0) return null;
        return new JsonObject
        {
            ["systemMessage"] = "local-secrets : " + Summary(converted),
            ["hookSpecificOutput"] = new JsonObject
            {
                ["hookEventName"] = "PreToolUse",
                ["additionalContext"] = "local-secrets a protégé ces fichiers juste avant ton accès : " + Summary(converted) +
                                        ". Les valeurs secret:// sont dans le coffre local. Pour une commande qui en a besoin : " +
                                        "secret run -- <commande>. N'essaie pas d'afficher ces valeurs.",
            },
        };
    }

    static JsonObject? PostToolUse(JsonObject input)
    {
        var tool = Str(input, "tool_name") ?? "";
        var ti = input["tool_input"] as JsonObject ?? new JsonObject();
        var cwd = Str(input, "cwd") ?? Environment.CurrentDirectory;
        var converted = new List<ConversionReport>();

        // Claude vient d'écrire dans un .env : les valeurs sensibles partent aussitôt au coffre.
        if (WriteTools.Contains(tool) && Paths.Full(Str(ti, "file_path") ?? Str(ti, "notebook_path"), cwd) is { } full
            && Paths.IsEnvFile(full) && Paths.IsInProject(full, ProjectRoot(cwd)))
        {
            try
            {
                if (Converter.AutoConvert(full) is { Changed: true } r) converted.Add(r);
            }
            catch (Exception e)
            {
                Log.Write($"conversion après écriture impossible pour {full} : {e.Message}");
            }
        }

        // Filet de sécurité : une valeur du coffre qui ressortirait quand même est masquée,
        // puis, sauf si l'utilisateur l'a coupé, tout ce qui ressemble à un secret.
        var hits = new SortedSet<string>(StringComparer.Ordinal);
        var generic = new SortedSet<string>(StringComparer.Ordinal);
        JsonNode? replaced = null;
        var vault = Vault.Load();
        var settings = Settings.Load();
        var genericOn = settings.OutputMaskingFor(cwd, out _);
        if ((vault.Secrets.Count > 0 || genericOn) && input["tool_response"] is { } response)
        {
            var patterns = vault.Secrets.Count > 0 ? Redactor.Variants(Vault.DecryptAll(vault)) : [];
            replaced = RedactNode(response.DeepClone(), s =>
            {
                var r = Redactor.Redact(s, patterns, hits);
                return genericOn ? OutputMasker.Mask(r, settings.NeverMask, generic) : r;
            });
        }
        if (hits.Count == 0 && generic.Count == 0 && converted.Count == 0) return null;

        var context = new List<string>();
        var user = new List<string>();
        if (converted.Count > 0)
        {
            context.Add("local-secrets a chiffré les valeurs sensibles que tu viens d'écrire : " + Summary(converted) +
                        ". Le fichier contient maintenant des références secret://. Pour les utiliser : secret run -- <commande>.");
            user.Add(Summary(converted));
        }
        if (hits.Count > 0)
        {
            context.Add($"local-secrets a masqué dans cette sortie la valeur de : {string.Join(", ", hits)}. " +
                        "Ces valeurs restent utilisables via secret run ; ne cherche pas à les afficher autrement.");
            user.Add($"valeur(s) du coffre masquée(s) dans la sortie de {tool} ({string.Join(", ", hits)})");
        }
        if (generic.Count > 0)
        {
            context.Add($"local-secrets a masqué des valeurs qui ressemblent à des secrets : {string.Join(", ", generic)}. " +
                        "Elles ne sont stockées nulle part et ne sont pas récupérables. Ne recopie jamais un masque [masqué:...] " +
                        "dans un fichier ou une commande. Si tu as besoin d'une de ces valeurs, demande à l'utilisateur de " +
                        "l'enregistrer avec « secret set ».");
            user.Add($"valeur(s) sensible(s) masquée(s) dans la sortie de {tool} ({string.Join(", ", generic)})");
        }
        var specific = new JsonObject
        {
            ["hookEventName"] = "PostToolUse",
            ["additionalContext"] = string.Join(" ", context),
        };
        if ((hits.Count > 0 || generic.Count > 0) && replaced != null) specific["updatedToolOutput"] = replaced;
        return new JsonObject
        {
            ["systemMessage"] = "local-secrets : " + string.Join(" ; ", user),
            ["hookSpecificOutput"] = specific,
        };
    }

    static JsonObject? UserPromptSubmit(JsonObject input)
    {
        var prompt = Str(input, "prompt") ?? "";
        if (prompt.Contains("[nosecret]", StringComparison.OrdinalIgnoreCase)) return null;
        var findings = Classifier.ScanText(prompt);
        var vault = Vault.Load();
        if (vault.Secrets.Count > 0)
        {
            foreach (var (name, value) in Vault.DecryptAll(vault))
            {
                // Une valeur faible (« guest », « secret ») bloquerait tout message contenant ce mot.
                if (value.Length >= 6 && !Classifier.IsWeakSecret(value) && prompt.Contains(value, StringComparison.Ordinal))
                {
                    findings.Add($"la valeur de {name}, déjà dans le coffre");
                    break;
                }
            }
        }
        if (findings.Count == 0) return null;
        Log.Write("message bloqué : " + string.Join(", ", findings.Distinct()));
        return new JsonObject
        {
            ["decision"] = "block",
            ["reason"] = $"local-secrets : message non envoyé, il contient {string.Join(", ", findings.Distinct())}. " +
                         "Enregistre le secret dans ton terminal avec « secret set NOM » (saisie masquée), puis parle-en à Claude par son nom. " +
                         "Le texte peut rester dans l'historique local de Claude Code : « secret scrub --ask » l'efface. " +
                         "Pour envoyer ce message quand même, ajoute [nosecret].",
            ["hookSpecificOutput"] = new JsonObject
            {
                ["hookEventName"] = "UserPromptSubmit",
                ["suppressOriginalPrompt"] = true,
            },
        };
    }

    static JsonObject? SessionStart(JsonObject input)
    {
        var dir = Environment.GetEnvironmentVariable("CLAUDE_PROJECT_DIR");
        if (string.IsNullOrWhiteSpace(dir)) dir = Str(input, "cwd") ?? Environment.CurrentDirectory;
        if (!Directory.Exists(dir) || Paths.IsBroad(dir)) return null;

        // Lecture seule : le démarrage ne convertit plus rien, il liste ce qui est déjà protégé.
        var files = Paths.FindEnvFiles(dir, maxDepth: 2, maxEntries: 5000);

        var protectedFiles = new List<string>();
        foreach (var f in files)
        {
            try
            {
                var keys = EnvFile.Load(f).Assignments.Where(a => a.Reference != null).Select(a => a.Key).ToList();
                if (keys.Count > 0) protectedFiles.Add($"- {Path.GetRelativePath(dir, f)} : {string.Join(", ", keys)}");
            }
            catch
            {
                // fichier illisible : ignoré
            }
        }
        var reminder = BackupReminder();
        if (protectedFiles.Count == 0)
            return reminder == null ? null : new JsonObject { ["systemMessage"] = reminder };

        var context =
            "local-secrets est actif sur ce poste. Les valeurs sensibles des fichiers .env sont chiffrées dans un coffre local " +
            "(DPAPI Windows) et remplacées par des références secret://espace/CLÉ.\n" +
            "Fichiers protégés dans ce projet, avec leurs clés chiffrées :\n" + string.Join("\n", protectedFiles) + "\n" +
            "Pour lancer une commande qui a besoin de ces valeurs, préfixe-la par « secret run -- » : les variables du .env du " +
            "dossier courant sont injectées et leurs valeurs masquées dans la sortie. Dans un argument, écris secret://CLÉ, " +
            "secret run le remplace. Attention, $VAR entre guillemets doubles est développée trop tôt par ton shell. " +
            $"Si « secret » est introuvable (outil PowerShell notamment), appelle-le par son chemin : & '{Environment.ProcessPath}' run -- <commande>. " +
            "Dans l'outil Bash (Git Bash), un argument qui commence par / est converti en chemin : écris //c au lieu de /c. " +
            "Si l'utilisateur veut voir des valeurs, lance « secret show [FICHIER|NOM] » : elles s'affichent dans une fenêtre " +
            "à part sur son écran, jamais dans ta sortie. N'essaie jamais d'afficher une valeur toi-même. " +
            "Mode d'emploi complet : skill local-secrets:secrets.";
        var root = Path.Combine(dir, ".env");
        if (File.Exists(root) && Guards.AlreadyInjected(root))
            context += "\nLes secrets du .env de ce projet sont déjà chargés dans ton environnement (terminal de l'utilisateur) : " +
                       "les commandes du projet les reçoivent même sans secret run, et leurs sorties restent masquées.";
        var o = new JsonObject
        {
            ["hookSpecificOutput"] = new JsonObject { ["hookEventName"] = "SessionStart", ["additionalContext"] = context },
        };
        if (reminder != null) o["systemMessage"] = reminder;
        return o;
    }

    // Une fois par semaine au plus, tant qu'aucune sauvegarde portable récente n'existe.
    static string? BackupReminder()
    {
        try
        {
            var count = Vault.Load().Secrets.Count;
            var s = Settings.Load();
            if (!s.BackupOverdue(count)) return null;
            if (s.LastBackupReminder is { } last && DateTime.Now - last < TimeSpan.FromDays(7)) return null;
            s.LastBackupReminder = DateTime.Now;
            s.Save();
            var since = s.LastBackup is { } b ? $"depuis le {b:dd.MM.yyyy}" : "jamais faite";
            return $"local-secrets : sauvegarde du coffre ({count} secret(s)) {since}. Sans elle, un changement de PC ou de mot de passe " +
                   "Windows peut tout rendre illisible. Dans ton terminal : secret backup D:\\coffre.lsbackup";
        }
        catch
        {
            return null;
        }
    }

    // Convertit le fichier avant l'accès. Renvoie un motif de refus si le dossier est exclu de la
    // conversion et que le fichier contient encore des valeurs sensibles en clair.
    static string? Protect(string file, List<ConversionReport> converted, string root)
    {
        var excluded = Converter.IsExcluded(file);
        var inProject = Paths.IsInProject(file, root);
        if (!excluded && inProject)
        {
            if (Converter.Convert(file) is { Changed: true } r) converted.Add(r);
            return null;
        }

        // Hors du projet ouvert, ou exclu par l'utilisateur : on ne modifie pas le fichier, et on en
        // bloque l'accès s'il contient des valeurs sensibles en clair.
        var a = Converter.Analyze(file);
        if (a is not { Encrypted.Count: > 0 }) return null;
        var keys = string.Join(", ", a.Encrypted.Select(e => e.Key));
        var why = excluded
            ? "il est exclu de la conversion automatique (marqueur « # local-secrets: ignore » ou « secret config convert off »)"
            : $"il n'appartient pas au projet ouvert ({root})";
        return $"{Path.GetFileName(file)} contient des valeurs sensibles en clair ({keys}) et {why} : local-secrets ne le modifie pas, " +
               "et bloque l'accès pour qu'elles ne te soient pas transmises. Ouvre Claude dans le projet de ce fichier, ou l'utilisateur " +
               "lance « secret import » sur ce fichier dans son terminal.";
    }

    static string Summary(List<ConversionReport> reports) =>
        string.Join(" ; ", reports.Select(r =>
            $"{Path.GetFileName(r.FilePath)} : {r.Encrypted.Count} valeur(s) chiffrée(s) ({string.Join(", ", r.Encrypted.Select(e => e.Key))})"));

    static string CredentialFileMessage(string full) =>
        $"Lecture bloquée par local-secrets : {Path.GetFileName(full)} est un fichier d'identifiants (mots de passe ou jetons). " +
        "Les programmes qui s'en servent (psql, git, aws, curl...) le lisent eux-mêmes : lance-les directement, sans ouvrir le fichier.";

    static string PrivateKeyMessage(string full) =>
        $"Lecture bloquée par local-secrets : {Path.GetFileName(full)} contient une clé privée. Pour SSH, l'utilisateur l'ajoute " +
        "une fois à l'agent ssh de Windows (ssh-add), ensuite ssh s'en sert sans que tu la lises. Si une commande a besoin " +
        "du fichier, passe-lui son chemin sans l'ouvrir.";

    static JsonObject Deny(string reason, List<ConversionReport>? converted = null)
    {
        var o = new JsonObject
        {
            ["hookSpecificOutput"] = new JsonObject
            {
                ["hookEventName"] = "PreToolUse",
                ["permissionDecision"] = "deny",
                ["permissionDecisionReason"] = reason,
            },
        };
        if (converted is { Count: > 0 }) o["systemMessage"] = "local-secrets : " + Summary(converted);
        return o;
    }

    // Un masque n'est jamais écrit dans un fichier : il remplacerait la vraie valeur.
    // Toléré seulement s'il figure déjà tel quel dans le fichier (documentation, par exemple).
    static bool WritesMask(JsonObject ti, string full)
    {
        var written = new List<string>();
        foreach (var field in new[] { "content", "new_string", "new_source" })
            if (Str(ti, field) is { } s) written.Add(s);
        if (ti["edits"] is JsonArray edits)
            foreach (var e in edits.OfType<JsonObject>())
                if (Str(e, "new_string") is { } s) written.Add(s);

        string? existing = null;
        foreach (var text in written)
        {
            foreach (Match m in Guards.MaskMarkerRx().Matches(text))
            {
                existing ??= File.Exists(full) ? File.ReadAllText(full) : "";
                if (!existing.Contains(m.Value, StringComparison.Ordinal)) return true;
            }
        }
        return false;
    }

    static JsonNode? RedactNode(JsonNode? node, Func<string, string> redact)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var key in o.Select(p => p.Key).ToList())
                {
                    var before = o[key];
                    var after = RedactNode(before, redact);
                    if (!ReferenceEquals(before, after)) o[key] = after;
                }
                return o;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    var before = a[i];
                    var after = RedactNode(before, redact);
                    if (!ReferenceEquals(before, after)) a[i] = after;
                }
                return a;
            case JsonValue v when v.GetValueKind() == JsonValueKind.String:
                var s = v.GetValue<string>();
                var r = redact(s);
                return r == s ? v : JsonValue.Create(r);
            default:
                return node;
        }
    }

    static IEnumerable<string> Strings(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var (_, child) in o)
                foreach (var s in Strings(child))
                    yield return s;
                break;
            case JsonArray a:
                foreach (var child in a)
                foreach (var s in Strings(child))
                    yield return s;
                break;
            case JsonValue v when v.GetValueKind() == JsonValueKind.String:
                yield return v.GetValue<string>();
                break;
        }
    }

    static string? Str(JsonObject o, string key) =>
        o[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    static string ReadStdin()
    {
        using var stdin = Console.OpenStandardInput();
        using var ms = new MemoryStream();
        stdin.CopyTo(ms);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    static void Emit(JsonObject o)
    {
        var bytes = Encoding.UTF8.GetBytes(o.ToJsonString());
        using var stdout = Console.OpenStandardOutput();
        stdout.Write(bytes);
        stdout.Flush();
    }
}
