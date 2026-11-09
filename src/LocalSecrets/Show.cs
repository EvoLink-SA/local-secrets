using System.Diagnostics;
using System.Text.Json.Nodes;

namespace LocalSecrets;

// « secret show » : montre des valeurs à l'utilisateur dans une fenêtre à part.
// Lancé par Claude, il ouvre cette fenêtre et ne renvoie qu'un accusé de réception :
// le contenu de la fenêtre ne passe jamais par la sortie de la commande.
static class ShowCmd
{
    public static int Run(string[] args)
    {
        var window = args.Contains("--window");
        // Seule une console créée pour nous (un seul processus attaché, rien de redirigé) peut afficher.
        if (window && (Console.IsInputRedirected || Console.IsOutputRedirected || !Platform.Current.IsDedicatedConsole()))
            throw new UserError("affichage refusé : ce n'est pas une fenêtre dédiée.");
        var targets = args.Where(a => a != "--window").ToList();
        var cwd = Environment.CurrentDirectory;
        var (label, items) = Collect(targets, cwd);
        if (items.Count == 0) throw new UserError($"rien à afficher : aucune valeur chiffrée dans {label}.");

        if (window) return Window(label, items);
        if (Ui.IsInteractive)
        {
            Print(items);
            return 0;
        }
        if (Environment.GetEnvironmentVariable("LOCAL_SECRETS_NO_WINDOW") == "1")
        {
            Console.WriteLine($"(test) fenêtre non ouverte : {items.Count} valeur(s) de {label}");
            return 0;
        }
        Platform.Current.OpenWindow(cwd, new[] { "show", "--window" }.Concat(targets));
        Console.WriteLine($"Une fenêtre s'est ouverte sur l'écran de l'utilisateur pour {items.Count} valeur(s) de {label}, " +
                          "affichées seulement après sa confirmation. Son contenu ne passe pas par cette sortie : tu ne le verras pas, c'est voulu.");
        return 0;
    }

    static int Window(string label, List<(string Key, string Name)> items)
    {
        try { Console.Title = "local-secrets"; } catch { }
        DisplayGuard.Open();
        try
        {
            Console.Write($"local-secrets : afficher {items.Count} valeur(s) secrète(s) de {label} ? [o/N] ");
            var answer = Console.ReadKey();
            Console.WriteLine();
            if (char.ToLowerInvariant(answer.KeyChar) is not ('o' or 'y'))
            {
                Console.WriteLine("Annulé, rien n'a été affiché.");
                Thread.Sleep(1200);
                return 1;
            }
            Console.WriteLine();
            Print(items);
            Console.WriteLine();
            Console.Write("Appuie sur une touche pour fermer. L'écran sera effacé.");
            Console.ReadKey(intercept: true);
            return 0;
        }
        finally
        {
            try { Console.Clear(); Console.Write("\u001b[3J"); } catch { }
            DisplayGuard.Close();
        }
    }

    static void Print(List<(string Key, string Name)> items)
    {
        var vault = Vault.Load();
        var width = items.Max(i => i.Key.Length) + 3;
        foreach (var (key, name) in items)
        {
            var value = Vault.TryGet(vault, name) ?? "(absente du coffre)";
            var lines = value.Replace("\r\n", "\n").Split('\n');
            Console.WriteLine(key.PadRight(width) + lines[0]);
            foreach (var line in lines.Skip(1)) Console.WriteLine(new string(' ', width) + line);
        }
    }

    // Cibles : rien (le .env du dossier), un fichier .env, ou des noms de secrets.
    static (string Label, List<(string Key, string Name)> Items) Collect(List<string> targets, string cwd)
    {
        var items = new List<(string, string)>();
        var labels = new List<string>();
        if (targets.Count == 0) targets = [".env"];
        var vault = Vault.Load();
        foreach (var t in targets)
        {
            var full = Paths.Full(t, cwd);
            if (full != null && File.Exists(full))
            {
                foreach (var a in EnvFile.Load(full).Assignments)
                    if (a.Reference is { } r) items.Add((a.Key, r));
                labels.Add(full);
            }
            else if (t == ".env")
            {
                throw new UserError($"pas de fichier .env dans {cwd}");
            }
            else
            {
                var name = Vault.Resolve(vault, t, cwd);
                items.Add((name, name));
                labels.Add(name);
            }
        }
        return (string.Join(", ", labels), items);
    }
}

// Trace d'un affichage en cours ou récent : pendant ce temps, les hooks bloquent captures
// d'écran et lecture du presse-papiers par Claude.
static class DisplayGuard
{
    static string FilePath => Path.Combine(Vault.Home, "display.json");
    static readonly TimeSpan ClipboardDelay = TimeSpan.FromMinutes(10);

    public static void Open() => Write(new JsonObject { ["pid"] = Environment.ProcessId, ["opened"] = DateTime.UtcNow });

    public static void Close() => Write(new JsonObject { ["pid"] = Environment.ProcessId, ["closed"] = DateTime.UtcNow });

    public static (bool Open, bool Recent) State()
    {
        try
        {
            if (!File.Exists(FilePath)) return (false, false);
            var o = JsonNode.Parse(File.ReadAllText(FilePath)) as JsonObject;
            if (o?["closed"] is { } closed) return (false, DateTime.UtcNow - closed.GetValue<DateTime>() < ClipboardDelay);
            var pid = (int?)o?["pid"] ?? 0;
            if (IsAlive(pid)) return (true, true);
            return (false, DateTime.UtcNow - File.GetLastWriteTimeUtc(FilePath) < ClipboardDelay);
        }
        catch
        {
            return (false, false);
        }
    }

    static bool IsAlive(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return !p.HasExited; }
        catch { return false; }
    }

    static void Write(JsonObject o)
    {
        try
        {
            Paths.CreatePrivateDirectory(Vault.Home);
            Paths.WritePrivate(FilePath, o.ToJsonString());
        }
        catch
        {
            // sans trace, les hooks ne bloquent simplement pas les captures
        }
    }
}

// « secret env » : pour le chargement automatique dans le terminal de l'utilisateur (profil du shell).
// Renvoie en JSON les secrets du projet du dossier courant ; la sortie part dans une variable du
// profil, jamais à l'écran. Refusé depuis Claude Code et depuis une entrée redirigée.
static class EnvCmd
{
    public static int Run(string[] args)
    {
        if (Ui.FromClaude || Console.IsInputRedirected)
            throw new UserError("« secret env » est réservé au chargement automatique de ton terminal.");
        var dir = Environment.CurrentDirectory;
        for (var i = 0; i < args.Length; i++)
            if (args[i] == "--dir" && i + 1 < args.Length) dir = args[++i];

        // Lecture seule : entrer dans un dossier ne convertit jamais rien.
        var file = FindProjectEnv(dir);
        if (file == null) return 0;

        var vault = Vault.Load();
        var vars = new JsonObject();
        foreach (var a in EnvFile.Load(file).Assignments)
            if (a.Reference is { } name && vault.Secrets.ContainsKey(name))
                vars[a.Key] = Vault.TryGet(vault, name);
        if (vars.Count == 0) return 0;

        var stamp = $"{File.GetLastWriteTimeUtc(file).Ticks}-{(File.Exists(Vault.FilePath) ? File.GetLastWriteTimeUtc(Vault.FilePath).Ticks : 0)}";
        var o = new JsonObject { ["dir"] = Path.GetDirectoryName(file), ["file"] = file, ["stamp"] = stamp, ["vars"] = vars };
        // Encodeur par défaut : tout caractère non ASCII est échappé, la sortie se relit quel que soit l'encodage.
        Console.Out.Write(o.ToJsonString());
        return 0;
    }

    // Le .env le plus proche en remontant, comme le cherche docker compose depuis un sous-dossier.
    public static string? FindProjectEnv(string dir)
    {
        var d = Paths.Normalize(dir);
        for (var i = 0; i < 8 && !string.IsNullOrEmpty(d); i++)
        {
            if (Paths.IsBroad(d)) return null;
            var candidate = Path.Combine(d, ".env");
            if (File.Exists(candidate)) return candidate;
            d = Path.GetDirectoryName(d);
        }
        return null;
    }
}
