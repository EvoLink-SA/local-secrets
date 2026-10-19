using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace LocalSecrets;

static partial class Commands
{
    public static string Version =>
        typeof(Commands).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "?";

    static readonly string[] Known =
    [
        "help", "--help", "-h", "version", "--version", "set", "list", "ls", "status", "import", "protect", "unprotect",
        "run", "shell", "reveal", "rm", "remove", "undo", "backup", "restore", "scrub", "doctor", "selftest", "hook", "config",
        "show", "env", "migrate",
    ];

    public static bool IsKnown(string arg) => Known.Contains(arg, StringComparer.OrdinalIgnoreCase);

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_.\-]*$")]
    private static partial Regex KeyRx();

    public static int Dispatch(string[] args)
    {
        if (args.Length == 0) { Help(); return 0; }
        var rest = args[1..];
        switch (args[0].ToLowerInvariant())
        {
            case "help": case "--help": case "-h": Help(); return 0;
            case "version": case "--version": Console.WriteLine($"secret (local-secrets) {Version}"); return 0;
            case "set": return Set(rest);
            case "list": case "ls": return List(rest);
            case "status": return Status(rest);
            case "import": return Import(rest);
            case "protect": return Protect(rest);
            case "unprotect": return Unprotect(rest);
            case "run": return Runner.Run(rest);
            case "shell": return Runner.Shell(rest);
            case "reveal": return Reveal(rest);
            case "rm": case "remove": return Remove(rest);
            case "undo": return Undo(rest);
            case "backup": return BackupCmd.Backup(rest);
            case "restore": return BackupCmd.Restore(rest);
            case "scrub": return Scrub.Run(rest);
            case "config": return Config(rest);
            case "show": return ShowCmd.Run(rest);
            case "env": return EnvCmd.Run(rest);
            case "migrate": return Migrate(rest);
            case "doctor": return Doctor.Run();
            case "selftest": return SelfTest.Run();
            case "hook": return Hooks.Run(rest.Length > 0 ? rest[0] : "");
            default: throw new UserError($"commande inconnue « {args[0]} ». Tape « secret help ».");
        }
    }

    static void Help()
    {
        Console.WriteLine($"""
            secret (local-secrets) {Version} : secrets locaux chiffrés par DPAPI, utilisables par Claude sans être vus.

            Utilisation courante
              secret status [FICHIER]          état de chaque clé d'un .env : chiffrée, en clair, à chiffrer
              secret show [FICHIER | NOM...]   montre les valeurs ; lancé par Claude, dans une fenêtre à part
              secret import [CHEMIN] [--dry-run]  chiffre maintenant les .env d'un fichier ou d'un dossier
              secret import --stdin [--to FICHIER] [--only CLÉ,CLÉ] [--secret]
                                               importe un .env reçu par un tuyau (depuis un serveur)
              secret run [options] -- CMD ...  lance CMD avec les secrets en variables d'environnement,
                                               valeurs masquées dans la sortie
                  -e, --env-file FICHIER       .env à injecter (défaut : .env du dossier courant)
                  --ns ESPACE                  injecte tout un espace du coffre
                  -s, --secret NOM[=VARIABLE]  injecte un seul secret
                  --ssh-pass NOM               fournit ce mot de passe à ssh (SSH_ASKPASS)
                  secret://CLÉ dans un argument est remplacé par la valeur
              secret list [--ns ESPACE]        noms des secrets (jamais les valeurs)
              secret set NOM [--env FICHIER] [--file FICHIER_VALEUR]
                                               enregistre un secret, saisie masquée ; NOM = CLÉ ou espace/CLÉ
              secret protect FICHIER CLÉ...    force le chiffrement de clés laissées en clair

            Réservé à ton terminal (refusé quand c'est Claude qui lance)
              secret reveal NOM                affiche une valeur
              secret shell                     ouvre un shell avec les secrets du .env injectés
              secret unprotect FICHIER CLÉ     remet une clé en clair, marquée @public
              secret undo [FICHIER | --under DOSSIER] [--since "AAAA-MM-JJ HH:MM"] [--ignore] [--force] [--dry-run]
                                               restaure des .env tels qu'avant leur conversion ; --ignore les
                                               marque pour ne plus être convertis ; --dry-run liste sans rien faire
              secret rm NOM                    supprime un secret du coffre
              secret backup [FICHIER]          sauvegarde chiffrée par phrase de passe
              secret restore FICHIER           réimporte une sauvegarde

            Masquage générique des sorties ([masqué:CLÉ])
              secret config                    réglages actuels
              secret config masking on|off [--here | --project CHEMIN]
                                               allume ou coupe, partout ou pour un dossier (off : terminal seulement)
              secret config allow CLÉ...       ne jamais masquer ces clés (terminal seulement)
              secret config disallow CLÉ...    retire des clés de cette liste
              Pour une session automatisée : lancer Claude Code avec {Settings.EnvSwitch}=off

            Conversion automatique des .env
              secret config convert on|off [--here | --project CHEMIN]
                                               off : ne plus modifier les .env de ce dossier ; Claude ne
                                               pourra plus les lire s'ils contiennent des secrets en clair

            Terminal PowerShell
              secret env                       utilisé par le profil pour charger les secrets d'un projet

            Entretien
              secret migrate [--from DOSSIER]  fusionne les anciens coffres (ou une copie) dans le coffre unique
              secret scrub [--dry-run] [--ask] [--force]
                                               efface les valeurs du coffre des fichiers locaux de Claude Code
              secret doctor                    vérifie l'installation
              secret selftest                  tests internes

            Dans un .env : « # @secret » ou « # @public » en fin de ligne force le choix.
            Coffre : {Vault.FilePath}
            """);
    }

    static int Set(string[] args)
    {
        string? name = null, envPath = null, valueFile = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--env": envPath = Arg(args, ++i, "--env"); break;
                case "--file": valueFile = Arg(args, ++i, "--file"); break;
                default:
                    if (args[i].StartsWith('-')) throw new UserError($"option inconnue : {args[i]}");
                    if (name != null) throw new UserError("un seul nom à la fois.");
                    name = args[i];
                    break;
            }
        }
        if (name == null) throw new UserError("usage : secret set NOM [--env FICHIER] [--file FICHIER_VALEUR]");

        string key;
        if (name.Contains('/'))
        {
            if (!Vault.IsValidName(name)) throw new UserError($"nom invalide : {name} (attendu : espace/CLÉ, espace en minuscules)");
            key = name[(name.IndexOf('/') + 1)..];
        }
        else
        {
            if (!KeyRx().IsMatch(name)) throw new UserError($"nom de variable invalide : {name}");
            key = name;
            envPath ??= Path.Combine(Environment.CurrentDirectory, ".env");
        }
        var envFull = envPath == null ? null : Path.GetFullPath(envPath);

        var value = ReadValue(valueFile);
        if (value.Length == 0) throw new UserError("valeur vide, rien n'a été enregistré.");

        var preferred = envFull != null && File.Exists(envFull) ? Converter.PreferredNamespace(EnvFile.Load(envFull)) : null;
        var full = Vault.Update(d =>
        {
            var n = name.Contains('/') ? name : Vault.NamespaceForFile(d, envFull!, preferred) + "/" + key;
            Vault.Set(d, n, value, envFull);
            return n;
        });
        Console.WriteLine($"« {full} » enregistré dans le coffre.");
        if (envFull != null)
        {
            AddReference(envFull, key, full);
            Console.WriteLine($"Référence écrite dans {envFull} : {key}=secret://{full}");
        }
        return 0;
    }

    static string ReadValue(string? valueFile)
    {
        if (valueFile != null) return File.ReadAllText(valueFile);
        if (Ui.IsInteractive) return Ui.ReadSecret("Valeur (saisie masquée) : ");
        var text = Console.In.ReadToEnd();
        if (text.EndsWith("\r\n")) return text[..^2];
        return text.EndsWith('\n') ? text[..^1] : text;
    }

    static void AddReference(string envPath, string key, string fullName)
    {
        var line = $"{key}=secret://{fullName}";
        if (!File.Exists(envPath))
        {
            File.WriteAllText(envPath, EnvFile.Header + "\n" + line + "\n", new UTF8Encoding(false));
            return;
        }
        var env = EnvFile.Load(envPath);
        var existing = env.Assignments.LastOrDefault(a => a.Key == key);
        var map = new Dictionary<EnvAssignment, string>();
        if (existing != null)
        {
            map[existing] = "secret://" + fullName;
            if (existing.Reference == null) Vault.BackupEnvFile(envPath, env.OriginalBytes);
        }
        EnvFile.WriteInPlace(envPath, env.Render(map, addHeader: true, append: existing == null ? [line] : null));
    }

    static int List(string[] args)
    {
        string? ns = null;
        for (var i = 0; i < args.Length; i++)
            if (args[i] == "--ns") ns = Arg(args, ++i, "--ns");
        var vault = Vault.Load();
        var names = vault.Secrets.Keys
            .Where(k => ns == null || k.StartsWith(ns + "/", StringComparison.Ordinal))
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();
        if (names.Count == 0)
        {
            Console.WriteLine(ns == null ? "Le coffre est vide." : $"Aucun secret dans l'espace « {ns} ».");
            return 0;
        }
        var width = Math.Max(names.Max(n => n.Length) + 2, 6);
        Console.WriteLine("NOM".PadRight(width) + "MODIFIÉ           ORIGINE");
        foreach (var n in names)
        {
            var e = vault.Secrets[n];
            Console.WriteLine(n.PadRight(width) + e.Updated.ToString("yyyy-MM-dd HH:mm") + "  " + (e.Origin ?? ""));
        }
        Console.WriteLine($"{names.Count} secret(s). Les valeurs ne s'affichent jamais ici.");
        return 0;
    }

    static int Status(string[] args)
    {
        var files = args.Where(a => !a.StartsWith('-')).Select(Path.GetFullPath).ToList();
        if (files.Count == 0) files = Paths.FindEnvFiles(Environment.CurrentDirectory, maxDepth: 1);
        if (files.Count == 0)
        {
            Console.WriteLine("Aucun fichier .env dans ce dossier.");
            return 0;
        }
        var vault = Vault.Load();
        foreach (var f in files)
        {
            if (!File.Exists(f)) throw new UserError($"fichier introuvable : {f}");
            var env = EnvFile.Load(f);
            var ns = Converter.PreferredNamespace(env) ?? Vault.FindNamespace(vault, f);
            Console.WriteLine($"{f}  (espace : {ns ?? "pas encore créé"})");
            var width = env.Assignments.Select(a => a.Key.Length).DefaultIfEmpty(0).Max() + 2;
            foreach (var a in env.Assignments)
            {
                string state;
                if (a.Reference is { } reference)
                {
                    state = vault.Secrets.ContainsKey(reference) ? $"chiffré      secret://{reference}" : $"INTROUVABLE  secret://{reference}";
                }
                else
                {
                    var v = Classifier.Classify(a.Key, a.Value, a.Annotation);
                    state = v.Secret ? $"à chiffrer   {v.Reason}" : $"en clair     {v.Reason}";
                }
                Console.WriteLine("  " + a.Key.PadRight(width) + state);
            }
            foreach (var line in env.UnrecognizedLines())
                Console.WriteLine($"  ligne {line + 1} : format non reconnu (ni CLÉ=valeur, ni clé:valeur, ni commentaire), ignorée par le tri");
        }
        return 0;
    }

    // « ssh srv "cat /opt/app/.env" | secret import --stdin » : le contenu passe directement du
    // tuyau au coffre, avec le même lecteur de .env que pour les fichiers locaux (guillemets compris).
    static int ImportStdin(string[] args)
    {
        string? to = null;
        HashSet<string>? only = null;
        var allSecret = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--stdin": break;
                case "--to": to = Arg(args, ++i, "--to"); break;
                case "--only": only = Arg(args, ++i, "--only").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.Ordinal); break;
                case "--secret": allSecret = true; break;
                default: throw new UserError($"option inconnue pour import --stdin : {args[i]}");
            }
        }
        if (!Console.IsInputRedirected)
            throw new UserError("rien sur l'entrée standard. Exemple : ssh root@srv \"cat /opt/app/.env\" | secret import --stdin");

        using var stdin = Console.OpenStandardInput();
        using var ms = new MemoryStream();
        stdin.CopyTo(ms);
        var source = EnvFile.Parse(ms.ToArray());
        var incoming = new Dictionary<string, EnvAssignment>(StringComparer.Ordinal);
        foreach (var a in source.Assignments)
            if (only == null || only.Contains(a.Key)) incoming[a.Key] = a;
        if (only != null && only.Except(incoming.Keys).ToList() is { Count: > 0 } absent)
            Ui.Note("absentes de la source : " + string.Join(", ", absent));
        var skipped = incoming.Values.Where(a => a.Reference != null).Select(a => a.Key).ToList();
        foreach (var k in skipped) incoming.Remove(k);
        if (skipped.Count > 0) Ui.Note("déjà des références secret:// dans la source, ignorées : " + string.Join(", ", skipped));
        if (incoming.Count == 0) throw new UserError("aucune clé à importer.");

        var target = Paths.Normalize(to ?? Path.Combine(Environment.CurrentDirectory, ".env"));
        if (!File.Exists(target)) File.WriteAllText(target, EnvFile.Header + "\n", new UTF8Encoding(false));
        var env = EnvFile.Load(target);
        var verdicts = incoming.Values.ToDictionary(a => a.Key, a => allSecret ? new Verdict(true, "--secret") : Classifier.Classify(a.Key, a.Value, a.Annotation));

        var preferred = Converter.PreferredNamespace(env);
        var ns = Vault.Update(d =>
        {
            var space = Vault.NamespaceForFile(d, target, preferred);
            foreach (var a in incoming.Values.Where(a => verdicts[a.Key].Secret)) Vault.Set(d, $"{space}/{a.Key}", a.Value, target);
            return space;
        });

        var newValues = new Dictionary<EnvAssignment, string>();
        var append = new List<string>();
        foreach (var a in incoming.Values)
        {
            var written = verdicts[a.Key].Secret ? $"secret://{ns}/{a.Key}" : EnvFile.Quote(a.Value);
            var existing = env.Assignments.LastOrDefault(x => x.Key == a.Key);
            if (existing != null) newValues[existing] = written;
            else append.Add($"{a.Key}={written}");
        }
        if (env.Assignments.Count > 0) Vault.BackupEnvFile(target, env.OriginalBytes);
        EnvFile.WriteInPlace(target, env.Render(newValues, addHeader: true, append: append.Count > 0 ? append : null));

        var parts = incoming.Keys.Select(k => $"{k} ({(verdicts[k].Secret ? "chiffrée" : "en clair")})");
        Console.WriteLine($"{incoming.Count} clé(s) importée(s) dans {target} : {string.Join(", ", parts)}.");
        return 0;
    }

    static int Import(string[] args)
    {
        if (args.Contains("--stdin")) return ImportStdin(args);
        var dryRun = args.Contains("--dry-run");
        var targets = args.Where(a => !a.StartsWith('-')).ToList();
        if (targets.Count == 0) targets.Add(Environment.CurrentDirectory);
        var files = new List<string>();
        foreach (var t in targets)
        {
            var full = Path.GetFullPath(t);
            if (Directory.Exists(full)) files.AddRange(Paths.FindEnvFiles(full, maxDepth: 4));
            else if (File.Exists(full)) files.Add(full);
            else throw new UserError($"introuvable : {t}");
        }
        if (files.Count == 0)
        {
            Console.WriteLine("Aucun fichier .env trouvé.");
            return 0;
        }
        if (dryRun) return Status(files.ToArray());
        foreach (var f in files)
        {
            if (EnvFile.HasIgnoreMarker(f))
            {
                Console.WriteLine($"{f} : marqué « {EnvFile.IgnoreMarker} », laissé tel quel");
                continue;
            }
            var r = Converter.Convert(f);
            if (r == null) continue;
            Console.WriteLine(r.Changed
                ? $"{f} : {r.Encrypted.Count} valeur(s) chiffrée(s) dans l'espace {r.Namespace} ({string.Join(", ", r.Encrypted.Select(e => e.Key))}), {r.Clear.Count} laissée(s) en clair"
                : $"{f} : rien à chiffrer ({r.References.Count} déjà protégée(s), {r.Clear.Count} en clair)");
        }
        return 0;
    }

    static int Protect(string[] args)
    {
        if (args.Length < 2) throw new UserError("usage : secret protect FICHIER CLÉ [CLÉ...]");
        var r = Converter.Convert(args[0], args[1..].ToHashSet(StringComparer.Ordinal)) ?? throw new UserError($"fichier introuvable : {args[0]}");
        Console.WriteLine(r.Changed
            ? $"{r.Encrypted.Count} valeur(s) chiffrée(s) : {string.Join(", ", r.Encrypted.Select(e => e.Key))}"
            : "Rien à chiffrer : ces clés sont déjà protégées ou absentes.");
        return 0;
    }

    static int Unprotect(string[] args)
    {
        Ui.RequireInteractive("secret unprotect");
        if (args.Length < 2) throw new UserError("usage : secret unprotect FICHIER CLÉ");
        var file = Path.GetFullPath(args[0]);
        var key = args[1];
        var env = EnvFile.Load(file);
        var a = env.Assignments.LastOrDefault(x => x.Key == key) ?? throw new UserError($"{key} absent de {file}");
        var name = a.Reference ?? throw new UserError($"{key} n'est pas chiffré.");
        var value = Vault.TryGet(Vault.Load(), name) ?? throw new UserError($"secret introuvable : {name}");
        if (!a.Comment.Contains("@public", StringComparison.OrdinalIgnoreCase)) a.Comment += " # @public";
        EnvFile.WriteInPlace(file, env.Render(new Dictionary<EnvAssignment, string> { [a] = EnvFile.Quote(value) }, addHeader: false));
        Console.WriteLine($"{key} est de nouveau en clair dans {file}, marqué @public pour ne plus être chiffré.");
        return 0;
    }

    static int Reveal(string[] args)
    {
        Ui.RequireInteractive("secret reveal");
        var name = args.FirstOrDefault(a => !a.StartsWith('-')) ?? throw new UserError("usage : secret reveal NOM");
        var vault = Vault.Load();
        var full = Vault.Resolve(vault, name, Environment.CurrentDirectory);
        Console.WriteLine(Vault.TryGet(vault, full) ?? throw new UserError($"secret introuvable : {full}"));
        return 0;
    }

    static int Remove(string[] args)
    {
        Ui.RequireInteractive("secret rm");
        var name = args.FirstOrDefault(a => !a.StartsWith('-')) ?? throw new UserError("usage : secret rm NOM");
        var vault = Vault.Load();
        var full = Vault.Resolve(vault, name, Environment.CurrentDirectory);
        if (!vault.Secrets.ContainsKey(full)) throw new UserError($"secret introuvable : {full}");
        if (!Ui.Confirm($"Supprimer « {full} » du coffre ? Les fichiers qui y font référence ne pourront plus s'en servir.")) return 1;
        Vault.Update(d => d.Secrets.Remove(full));
        Console.WriteLine("Supprimé.");
        return 0;
    }

    // Remet des .env tels qu'avant leur conversion, un fichier ou tout un dossier.
    // Avec --since, on reprend la version d'avant la première conversion faite depuis cette date.
    static int Undo(string[] args)
    {
        string? file = null, under = null;
        DateTime? since = null;
        bool force = false, dryRun = false, ignore = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--under": under = Path.TrimEndingDirectorySeparator(Paths.Normalize(Arg(args, ++i, "--under"))); break;
                case "--since":
                    var text = Arg(args, ++i, "--since");
                    if (!DateTime.TryParseExact(text, ["yyyy-MM-dd HH:mm", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd"],
                            CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var date))
                        throw new UserError($"date illisible : {text} (attendu : AAAA-MM-JJ HH:MM)");
                    since = date;
                    break;
                case "--force": force = true; break;
                case "--dry-run": dryRun = true; break;
                case "--ignore": ignore = true; break;
                default:
                    if (args[i].StartsWith('-')) throw new UserError($"option inconnue : {args[i]}");
                    file = Paths.Normalize(args[i]);
                    break;
            }
        }
        if (!dryRun) Ui.RequireInteractive("secret undo");
        if (file == null && under == null) file = Paths.Normalize(".env");

        var plan = new List<(string Path, EnvBackup Chosen, string Status, bool Restore)>();
        foreach (var group in Vault.ListBackups().GroupBy(b => Paths.Normalize(b.Record.Path), StringComparer.OrdinalIgnoreCase))
        {
            var path = group.Key;
            if (file != null && !path.Equals(file, StringComparison.OrdinalIgnoreCase)) continue;
            if (under != null && !path.StartsWith(under + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue;
            var records = group.Select(b => b.Record).OrderBy(r => r.Created).ToList();
            var chosen = since == null ? records[^1] : records.FirstOrDefault(r => r.Created >= since.Value);
            if (chosen == null) continue;
            var lastConversion = records[^1].Created;
            if (!File.Exists(path)) plan.Add((path, chosen, "introuvable, ignoré", false));
            else if (!force && File.GetLastWriteTime(path) > lastConversion.AddSeconds(5))
                plan.Add((path, chosen, "modifié depuis la conversion, ignoré (--force pour le restaurer quand même)", false));
            else plan.Add((path, chosen, "à restaurer", true));
        }
        if (plan.Count == 0)
            throw new UserError(file != null
                ? $"aucune sauvegarde pour {file}"
                : $"aucun fichier converti sous {under}" + (since != null ? $" depuis le {since:dd.MM.yyyy HH:mm}" : ""));

        foreach (var p in plan.OrderBy(p => p.Path, StringComparer.OrdinalIgnoreCase))
            Console.WriteLine($"  {p.Path}  (version du {p.Chosen.Created:dd.MM.yyyy HH:mm}) : {p.Status}");
        var todo = plan.Where(p => p.Restore).ToList();
        if (dryRun || todo.Count == 0)
        {
            Console.WriteLine(dryRun ? $"Simulation : {todo.Count} fichier(s) seraient restaurés." : "Rien à restaurer.");
            return 0;
        }
        if (!Ui.Confirm($"Restaurer {todo.Count} fichier(s) tels qu'avant leur conversion, valeurs en clair comprises ?" +
                        (ignore ? " Ils seront marqués pour ne plus jamais être convertis." : "")))
            return 1;
        foreach (var p in todo)
        {
            var bytes = Vault.RestoreBackup(p.Chosen);
            if (ignore)
            {
                var env = EnvFile.Parse(bytes);
                if (!env.Lines.Any(EnvFile.HasIgnoreMarkerText)) bytes = env.RenderWithFirstLine(EnvFile.IgnoreMarker);
            }
            File.WriteAllBytes(p.Path, bytes);
        }
        Console.WriteLine($"{todo.Count} fichier(s) restauré(s). Leurs secrets restent aussi dans le coffre.");
        if (!ignore)
            Console.WriteLine("Un fichier restauré sera de nouveau chiffré si Claude l'ouvre dans son projet ; --ignore l'évite.");
        return 0;
    }

    static int Config(string[] args)
    {
        var s = Settings.Load();
        var cwd = Environment.CurrentDirectory;
        if (args.Length == 0)
        {
            s.OutputMaskingFor(cwd, out var why);
            Console.WriteLine($"Masquage générique des sorties ici : {why}");
            Console.WriteLine($"  réglage global : {(s.OutputMasking ? "actif" : "coupé")}");
            foreach (var p in s.OutputMaskingOffIn) Console.WriteLine($"  coupé pour : {p}");
            Console.WriteLine($"  clés jamais masquées : {(s.NeverMask.Count == 0 ? "aucune" : string.Join(", ", s.NeverMask))}");
            Console.WriteLine($"Conversion automatique des .env ici : {(s.ConversionDisabledFor(cwd) is { } off ? $"coupée (pour {off})" : "active")}");
            foreach (var p in s.ConversionOffIn) Console.WriteLine($"  coupée pour : {p}");
            Console.WriteLine($"Pour une session automatisée : lancer Claude Code avec {Settings.EnvSwitch}=off.");
            Console.WriteLine("Le masquage des valeurs du coffre ([secret:...]) reste toujours actif.");
            return 0;
        }

        switch (args[0].ToLowerInvariant())
        {
            case "masking":
            {
                if (args.Length < 2 || args[1].ToLowerInvariant() is not ("on" or "off"))
                    throw new UserError("usage : secret config masking on|off [--here | --project CHEMIN]");
                var on = args[1].Equals("on", StringComparison.OrdinalIgnoreCase);
                string? project = null;
                for (var i = 2; i < args.Length; i++)
                {
                    if (args[i] == "--here") project = cwd;
                    else if (args[i] == "--project") project = Arg(args, ++i, "--project");
                    else throw new UserError($"option inconnue : {args[i]}");
                }
                if (!on) Ui.RequireInteractive("secret config masking off");
                if (project != null)
                {
                    var p = Paths.Normalize(project);
                    s.OutputMaskingOffIn.RemoveAll(x => Paths.Normalize(x).Equals(p, StringComparison.OrdinalIgnoreCase));
                    if (!on) s.OutputMaskingOffIn.Add(p);
                    Console.WriteLine($"Masquage générique {(on ? "rétabli" : "coupé")} pour {p} et ses sous-dossiers.");
                }
                else
                {
                    s.OutputMasking = on;
                    Console.WriteLine($"Masquage générique {(on ? "actif" : "coupé")} partout" +
                                      (on && s.OutputMaskingOffIn.Count > 0 ? $", sauf {s.OutputMaskingOffIn.Count} dossier(s) exclu(s)." : "."));
                }
                s.Save();
                Console.WriteLine("Effet immédiat, y compris dans les sessions Claude Code déjà ouvertes.");
                return 0;
            }
            case "convert":
            {
                if (args.Length < 2 || args[1].ToLowerInvariant() is not ("on" or "off"))
                    throw new UserError("usage : secret config convert on|off [--here | --project CHEMIN]");
                var on = args[1].Equals("on", StringComparison.OrdinalIgnoreCase);
                var project = cwd;
                for (var i = 2; i < args.Length; i++)
                {
                    if (args[i] == "--here") project = cwd;
                    else if (args[i] == "--project") project = Arg(args, ++i, "--project");
                    else throw new UserError($"option inconnue : {args[i]}");
                }
                if (!on) Ui.RequireInteractive("secret config convert off");
                var p = Paths.Normalize(project);
                s.ConversionOffIn.RemoveAll(x => Paths.Normalize(x).Equals(p, StringComparison.OrdinalIgnoreCase));
                if (!on) s.ConversionOffIn.Add(p);
                s.Save();
                Console.WriteLine(on
                    ? $"Conversion automatique rétablie pour {p}."
                    : $"Les .env de {p} ne seront plus modifiés automatiquement. Ceux qui contiennent des secrets en clair " +
                      "deviennent illisibles pour Claude ; « secret import » reste possible à la main.");
                return 0;
            }
            case "allow":
                Ui.RequireInteractive("secret config allow");
                if (args.Length < 2) throw new UserError("usage : secret config allow CLÉ [CLÉ...]");
                foreach (var k in args[1..])
                    if (!s.NeverMask.Contains(k, StringComparer.OrdinalIgnoreCase)) s.NeverMask.Add(k);
                s.Save();
                Console.WriteLine($"Jamais masquées dans les sorties : {string.Join(", ", s.NeverMask)}");
                return 0;
            case "disallow":
                if (args.Length < 2) throw new UserError("usage : secret config disallow CLÉ [CLÉ...]");
                s.NeverMask.RemoveAll(k => args[1..].Contains(k, StringComparer.OrdinalIgnoreCase));
                s.Save();
                Console.WriteLine($"Jamais masquées dans les sorties : {(s.NeverMask.Count == 0 ? "aucune" : string.Join(", ", s.NeverMask))}");
                return 0;
            default:
                throw new UserError("usage : secret config [masking on|off [--here|--project CHEMIN] | allow CLÉ... | disallow CLÉ...]");
        }
    }

    // Fusion forcée des anciens coffres, ou d'une copie donnée avec --from, avec compte rendu.
    static int Migrate(string[] args)
    {
        var extra = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--from") extra.Add(Path.GetFullPath(Arg(args, ++i, "--from")));
            else throw new UserError($"option inconnue : {args[i]}");
        }
        Console.WriteLine($"Coffre unique : {Vault.Home}");
        var sources = Legacy.Sources().Concat(extra).ToList();
        if (sources.Count == 0)
        {
            Console.WriteLine("Aucun ancien coffre à fusionner.");
            return 0;
        }
        var report = Legacy.EnsureMerged(force: true, extra: extra);
        if (report.Count == 0) Console.WriteLine("Rien à fusionner : les anciens emplacements ne contiennent pas de coffre.");
        foreach (var line in report) Console.WriteLine("  " + line);
        Console.WriteLine($"{Vault.Load().Secrets.Count} secret(s) dans le coffre unique. Les anciens emplacements sont laissés intacts.");
        return 0;
    }

    static string Arg(string[] args, int i, string option) =>
        i < args.Length ? args[i] : throw new UserError($"valeur manquante après {option}");
}
