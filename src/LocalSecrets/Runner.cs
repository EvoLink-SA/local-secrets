using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace LocalSecrets;

sealed class RunOptions
{
    public List<string> EnvFiles { get; } = new();
    public List<string> Namespaces { get; } = new();
    public List<string> Singles { get; } = new();
    public string? SshPass { get; set; }
    public bool Explicit => EnvFiles.Count > 0 || Namespaces.Count > 0 || Singles.Count > 0 || SshPass != null;
}

sealed class Prepared
{
    public required VaultData Vault { get; init; }
    public required Dictionary<string, string> Env { get; init; }
    public required Dictionary<string, string> ShortNames { get; init; }
    public required List<string> EnvFiles { get; init; }
}

// « secret run » : injecte les secrets en variables d'environnement d'un processus enfant
// et masque leurs valeurs dans tout ce que ce processus affiche.
static partial class Runner
{
    public const string AskpassEnv = "LOCAL_SECRETS_ASKPASS_VALUE";

    [GeneratedRegex(@"secret://(?:(?<ns>[a-z0-9][a-z0-9._\-]*)/)?(?<key>[0-9]*[A-Za-z_][A-Za-z0-9_.\-]*)")]
    private static partial Regex ReferenceRx();

    [GeneratedRegex(@"(?m)^\s*env_file\s*:")]
    private static partial Regex EnvFileDirectiveRx();

    public static int Run(string[] args)
    {
        var (options, command) = Parse(args, allowCommand: true);
        if (command.Length == 0)
            throw new UserError("rien à lancer. Usage : secret run [options] -- <commande> [arguments]");

        var cwd = Environment.CurrentDirectory;
        var prepared = Prepare(options, cwd);
        var finalArgs = command.Select(a => ReferenceRx().Replace(a, m => ResolveReference(m, prepared))).ToArray();
        var patterns = Redactor.BytePatterns(Redactor.Variants(Vault.DecryptAll(prepared.Vault)));

        var (file, list, raw) = ResolveCommand(finalArgs);
        var psi = new ProcessStartInfo(file)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = cwd,
        };
        if (raw != null) psi.Arguments = raw;
        else foreach (var a in list) psi.ArgumentList.Add(a);
        foreach (var (k, v) in prepared.Env) psi.Environment[k] = v;
        Platform.Current.PrepareChildEnvironment(psi, file, prepared.Env.Keys);

        if (options.SshPass != null)
        {
            var name = ResolveName(null, options.SshPass, prepared);
            psi.Environment["SSH_ASKPASS"] = Environment.ProcessPath;
            psi.Environment["SSH_ASKPASS_REQUIRE"] = "force";
            if (!psi.Environment.ContainsKey("DISPLAY")) psi.Environment["DISPLAY"] = "local-secrets:0";
            psi.Environment[AskpassEnv] = Vault.TryGet(prepared.Vault, name);
        }

        WarnComposeEnvFile(command, cwd, prepared.EnvFiles);
        try { Console.CancelKeyPress += (_, e) => e.Cancel = true; } catch { }

        using var process = Process.Start(psi) ?? throw new UserError("lancement impossible : " + file);
        var stdout = Pump(process.StandardOutput.BaseStream, Console.OpenStandardOutput(), patterns);
        var stderr = Pump(process.StandardError.BaseStream, Console.OpenStandardError(), patterns);
        process.WaitForExit();
        Task.WaitAll(stdout, stderr);
        return process.ExitCode;
    }

    // Shell interactif avec les secrets injectés, pour l'utilisateur seulement.
    public static int Shell(string[] args)
    {
        Ui.RequireInteractive("secret shell");
        var (options, _) = Parse(args, allowCommand: false);
        var prepared = Prepare(options, Environment.CurrentDirectory);
        var psi = Platform.Current.InteractiveShell();
        foreach (var (k, v) in prepared.Env) psi.Environment[k] = v;
        psi.Environment["LOCAL_SECRETS_SHELL"] = "1";
        Ui.Note($"shell lancé avec {prepared.Env.Count} variable(s) injectée(s). Tape « exit » pour revenir.");
        using var process = Process.Start(psi)!;
        process.WaitForExit();
        return process.ExitCode;
    }

    static (RunOptions, string[]) Parse(string[] args, bool allowCommand)
    {
        var o = new RunOptions();
        var i = 0;
        while (i < args.Length)
        {
            var a = args[i];
            if (a == "--") { i++; break; }
            if (!a.StartsWith('-'))
            {
                if (!allowCommand) throw new UserError($"argument inattendu : {a}");
                break;
            }
            string Next() => i + 1 < args.Length ? args[++i] : throw new UserError($"valeur manquante après {a}");
            switch (a)
            {
                case "--env-file": case "-e": o.EnvFiles.Add(Next()); break;
                case "--ns": o.Namespaces.Add(Next()); break;
                case "--secret": case "-s": o.Singles.Add(Next()); break;
                case "--ssh-pass": o.SshPass = Next(); break;
                default: throw new UserError($"option inconnue : {a}");
            }
            i++;
        }
        return (o, args[i..]);
    }

    static Prepared Prepare(RunOptions options, string cwd)
    {
        var envFiles = options.EnvFiles.Select(f => Path.GetFullPath(f)).ToList();
        if (!options.Explicit || (options.SshPass != null && envFiles.Count == 0 && options.Namespaces.Count == 0 && options.Singles.Count == 0))
        {
            var def = Path.Combine(cwd, ".env");
            if (File.Exists(def)) envFiles.Add(def);
        }

        // Une valeur restée en clair est chiffrée avant de lancer quoi que ce soit (sauf dossier exclu).
        foreach (var f in envFiles)
        {
            if (!File.Exists(f)) throw new UserError($"fichier introuvable : {f}");
            var report = Converter.AutoConvert(f);
            if (report is { Changed: true })
                Ui.Note($"{Path.GetFileName(f)} : {report.Encrypted.Count} valeur(s) chiffrée(s) avant lancement ({string.Join(", ", report.Encrypted.Select(e => e.Key))})" +
                        (report.UnrecognizedNote is { } note ? ", " + note : ""));
        }

        var vault = Vault.Load();
        var env = new Dictionary<string, string>(Platform.VariableComparer);
        var shortNames = new Dictionary<string, string>(StringComparer.Ordinal);
        var missing = new List<string>();
        foreach (var f in envFiles)
        {
            foreach (var a in EnvFile.Load(f).Assignments)
            {
                if (a.Reference is { } name)
                {
                    var value = Vault.TryGet(vault, name);
                    if (value == null) missing.Add(name);
                    else { env[a.Key] = value; shortNames[a.Key] = name; }
                }
                else
                {
                    env[a.Key] = a.Value;
                }
            }
        }
        foreach (var ns in options.Namespaces)
        {
            var prefix = ns + "/";
            var names = vault.Secrets.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal)).ToList();
            if (names.Count == 0) Ui.Note($"aucun secret dans l'espace « {ns} »");
            foreach (var name in names)
            {
                var key = name[prefix.Length..];
                env[key] = Vault.TryGet(vault, name)!;
                shortNames[key] = name;
            }
        }
        var partial = new Prepared { Vault = vault, Env = env, ShortNames = shortNames, EnvFiles = envFiles };
        foreach (var s in options.Singles)
        {
            var parts = s.Split('=', 2);
            var name = ResolveName(null, parts[0], partial);
            var variable = parts.Length > 1 ? parts[1] : name[(name.LastIndexOf('/') + 1)..];
            env[variable] = Vault.TryGet(vault, name)!;
            shortNames[variable] = name;
        }
        if (missing.Count > 0)
            throw new UserError("références absentes du coffre : " + string.Join(", ", missing.Distinct()) + ". Ajoute-les avec « secret set NOM ».");
        return partial;
    }

    static string ResolveReference(Match m, Prepared p)
    {
        var ns = m.Groups["ns"].Success ? m.Groups["ns"].Value : null;
        var name = ResolveName(ns, m.Groups["key"].Value, p);
        return Vault.TryGet(p.Vault, name) ?? throw new UserError($"secret introuvable : {name}");
    }

    static string ResolveName(string? ns, string key, Prepared p)
    {
        if (key.Contains('/')) return key;
        if (ns != null)
        {
            var full = ns + "/" + key;
            return p.Vault.Secrets.ContainsKey(full) ? full : throw new UserError($"secret introuvable : {full}");
        }
        if (p.ShortNames.TryGetValue(key, out var known)) return known;
        var candidates = p.Vault.Secrets.Keys.Where(k => k.EndsWith("/" + key, StringComparison.Ordinal)).ToList();
        return candidates.Count switch
        {
            1 => candidates[0],
            0 => throw new UserError($"secret introuvable : {key}"),
            _ => throw new UserError($"« {key} » est ambigu ({string.Join(", ", candidates)}) : écris secret://espace/{key}"),
        };
    }

    static async Task Pump(Stream source, Stream target, List<(byte[] Pattern, byte[] Replacement)> patterns)
    {
        var redactor = new StreamRedactor(patterns);
        var buffer = new byte[16384];
        int n;
        while ((n = await source.ReadAsync(buffer.AsMemory(0, buffer.Length))) > 0)
            redactor.Process(buffer, n, target, final: false);
        redactor.Process(buffer, 0, target, final: true);
        await target.FlushAsync();
    }

    public static int Askpass(string value, string[] args)
    {
        var prompt = string.Join(" ", args);
        if (prompt.Contains("yes/no", StringComparison.OrdinalIgnoreCase) || prompt.Contains("fingerprint", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("local-secrets : question d'empreinte SSH refusée. Ajoute -o StrictHostKeyChecking=accept-new " +
                                    "ou connecte-toi une première fois toi-même.");
            return 1;
        }
        using var stdout = Console.OpenStandardOutput();
        stdout.Write(Encoding.UTF8.GetBytes(value + "\n"));
        return 0;
    }

    static (string File, List<string> Args, string? Raw) ResolveCommand(string[] command)
    {
        var path = Platform.Current.FindExecutable(command[0]) ?? throw new UserError($"programme introuvable : {command[0]}");
        return Platform.Current.ResolveCommand(path, command[1..].ToList());
    }

    static void WarnComposeEnvFile(string[] command, string cwd, List<string> envFiles)
    {
        var exe = Path.GetFileNameWithoutExtension(command[0]).ToLowerInvariant();
        var compose = exe == "docker-compose" || (exe == "docker" && command.Skip(1).Contains("compose"));
        if (!compose || !envFiles.Any(Paths.HasReferences)) return;
        foreach (var name in new[] { "compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml" })
        {
            var p = Path.Combine(cwd, name);
            if (File.Exists(p) && EnvFileDirectiveRx().IsMatch(File.ReadAllText(p)))
                Ui.Note($"{name} utilise « env_file: » : les conteneurs recevront les références secret:// au lieu des valeurs. " +
                        "Passe ces variables par « environment: », par exemple DB_PASSWORD: ${DB_PASSWORD}.");
        }
    }
}
