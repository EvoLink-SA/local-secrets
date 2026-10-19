using System.Diagnostics;

namespace LocalSecrets;

static class Doctor
{
    public static int Run()
    {
        var problems = 0;
        void Ok(string m) => Console.WriteLine("  OK   " + m);
        void Bad(string m) { Console.WriteLine("  !!   " + m); problems++; }

        Console.WriteLine($"secret (local-secrets) {Commands.Version}");
        Console.WriteLine($"  exécutable : {Environment.ProcessPath}");
        Console.WriteLine($"  coffre     : {Vault.FilePath}");

        try
        {
            Native.Unprotect(Native.Protect([1, 2, 3], [7]), [7]);
            Ok("DPAPI disponible pour ce compte");
        }
        catch (Exception e)
        {
            Bad("DPAPI : " + e.Message);
        }

        var vault = Vault.Load();
        var all = Vault.DecryptAll(vault);
        var readable = all.Count;
        if (readable == vault.Secrets.Count) Ok($"{readable} secret(s) dans le coffre, tous déchiffrables");
        else Bad($"{vault.Secrets.Count - readable} secret(s) illisible(s) sous ce compte Windows (coffre copié depuis ailleurs ?)");

        var weak = all.Where(s => Classifier.IsWeakSecret(s.Value)).Select(s => s.Name).ToList();
        if (weak.Count > 0) Bad($"{weak.Count} secret(s) à valeur faible (mot courant ou trop court), à changer : {string.Join(", ", weak)}");

        var legacy = Legacy.Sources().Where(s => File.Exists(Path.Combine(s, "vault.json"))).ToList();
        foreach (var s in legacy) Console.WriteLine($"  ..   ancien coffre fusionné automatiquement, laissé intact : {s}");

        var onPath = Runner.FindExecutable("secret");
        if (onPath != null) Ok($"« secret » trouvé dans le PATH : {onPath}");
        else Bad("« secret » absent du PATH de ce terminal : lance install.ps1");

        var installed = Path.Combine(Paths.UserProfile, ".claude", "plugins", "installed_plugins.json");
        if (File.Exists(installed) && File.ReadAllText(installed).Contains("local-secrets", StringComparison.OrdinalIgnoreCase))
            Ok("plugin Claude Code installé");
        else
            Bad("plugin Claude Code non détecté : claude plugin install local-secrets@local-secrets");

        var config = Capture("sc.exe", "qc ssh-agent");
        var state = Capture("sc.exe", "query ssh-agent");
        if (config.Contains("DISABLED")) Bad("service ssh-agent désactivé (utile pour les clés SSH, voir README)");
        else if (state.Contains("RUNNING")) Ok("service ssh-agent démarré");
        else Bad("service ssh-agent arrêté");

        Console.WriteLine(problems == 0 ? "Tout est en ordre." : $"{problems} point(s) à regarder.");
        return problems == 0 ? 0 : 1;
    }

    static string Capture(string file, string arguments)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, arguments) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true })!;
            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            return text;
        }
        catch
        {
            return "";
        }
    }
}
