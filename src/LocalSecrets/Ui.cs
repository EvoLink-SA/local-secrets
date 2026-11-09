using System.Text;

namespace LocalSecrets;

sealed class UserError(string message) : Exception(message);

static class Ui
{
    // Claude Code pose CLAUDECODE=1 dans les shells de ses outils.
    public static bool FromClaude => Environment.GetEnvironmentVariable("CLAUDECODE") == "1";

    // Claude lance ses commandes avec l'entrée et la sortie redirigées, depuis un shell marqué
    // CLAUDECODE=1 : c'est ce qui sépare l'utilisateur dans son terminal d'un appel de l'agent.
    public static bool IsInteractive => !Console.IsInputRedirected && !Console.IsOutputRedirected && !FromClaude;

    public static void Init()
    {
        var utf8 = new UTF8Encoding(false);
        if (Console.IsOutputRedirected)
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), utf8) { AutoFlush = true });
        if (Console.IsErrorRedirected)
            Console.SetError(new StreamWriter(Console.OpenStandardError(), utf8) { AutoFlush = true });
    }

    public static void Note(string message) => Console.Error.WriteLine("local-secrets : " + message);

    public static void Error(string message) => Console.Error.WriteLine("local-secrets : " + message);

    public static void RequireInteractive(string what)
    {
        if (!IsInteractive)
            throw new UserError($"« {what} » ne fonctionne que tapé directement dans ton terminal, hors Claude Code. " +
                                "Claude ne peut pas l'utiliser, c'est voulu. Pour voir des valeurs : « secret show ».");
    }

    public static string ReadSecret(string prompt)
    {
        Console.Error.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var k = Console.ReadKey(intercept: true);
            if (k.Key == ConsoleKey.Enter) break;
            if (k.Key == ConsoleKey.Escape) { Console.Error.WriteLine(); throw new UserError("saisie annulée."); }
            if (k.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0) { sb.Length--; Console.Error.Write("\b \b"); }
                continue;
            }
            if (k.KeyChar == '\0' || char.IsControl(k.KeyChar)) continue;
            sb.Append(k.KeyChar);
            Console.Error.Write('*');
        }
        Console.Error.WriteLine();
        return sb.ToString();
    }

    public static bool Confirm(string question)
    {
        Console.Error.Write(question + " [o/N] ");
        var answer = Console.ReadLine()?.Trim().ToLowerInvariant();
        return answer is "o" or "oui" or "y" or "yes";
    }
}

static class Log
{
    // Ne jamais y écrire de valeur : uniquement des noms, des chemins et des actions.
    public static void Write(string line)
    {
        try
        {
            Paths.CreatePrivateDirectory(Vault.Home);
            var path = Path.Combine(Vault.Home, "local-secrets.log");
            var info = new FileInfo(path);
            if (info.Exists && info.Length > 1_000_000) File.Move(path, path + ".1", overwrite: true);
            var created = !File.Exists(path);
            File.AppendAllText(path, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{Environment.ProcessId}] {line}{Environment.NewLine}");
            if (created) Paths.RestrictToOwner(path);
        }
        catch
        {
            // le journal ne doit jamais faire échouer une commande
        }
    }
}
