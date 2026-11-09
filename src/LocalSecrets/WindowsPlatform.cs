using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace LocalSecrets;

sealed partial class WindowsPlatform : IPlatform
{
    public string ProtectionName => "DPAPI";

    public string ProtectionId => "dpapi";

    public string ExecutableName => "secret.exe";

    public string InstallScript => "install.ps1";

    public string PluginName => "local-secrets";

    public string ProtectionDescription => "DPAPI Windows";

    public string ShellHints(string exe) =>
        $"Si « secret » est introuvable (outil PowerShell notamment), appelle-le par son chemin : & '{exe}' run -- <commande>. " +
        "Dans l'outil Bash (Git Bash), un argument qui commence par / est converti en chemin : écris //c au lieu de /c. ";

    public string BackupHint =>
        "Sans elle, un changement de PC ou de mot de passe Windows peut tout rendre illisible. Dans ton terminal : secret backup D:\\coffre.lsbackup";

    public string SshAgentName => "l'agent ssh de Windows";

    public string UnreadableHint => "Le coffre a peut-être été créé sous un autre compte Windows : l'utilisateur lance « secret doctor » dans son terminal.";

    // DPAPI, portée utilisateur courant : seul ce compte Windows sur cette machine peut relire.
    public byte[] Protect(byte[] data, byte[] entropy) => Native.Protect(data, entropy);

    public byte[] Unprotect(byte[] data, byte[] entropy) => Native.Unprotect(data, entropy);

    public bool CanDecrypt => true;

    // Mutex nommé de la session : sous Windows, il est commun à tous les processus de l'utilisateur.
    public IDisposable? LockVault(TimeSpan timeout)
    {
        var mutex = new Mutex(false, @"Local\local-secrets-vault");
        bool owned;
        try { owned = mutex.WaitOne(timeout); }
        catch (AbandonedMutexException) { owned = true; }
        if (owned) return new MutexLock(mutex);
        mutex.Dispose();
        return null;
    }

    sealed class MutexLock(Mutex mutex) : IDisposable
    {
        public void Dispose()
        {
            mutex.ReleaseMutex();
            mutex.Dispose();
        }
    }

    [GeneratedRegex(@"^/([a-zA-Z])(/|$)")]
    private static partial Regex MsysDriveRx();

    // /c/tools (Git Bash) devient C:\tools.
    public string FromShellPath(string path) => MsysDriveRx().Replace(path, m => m.Groups[1].Value.ToUpperInvariant() + @":\");

    // C:\Users\PRENOM~1.ABC\... devient C:\Users\prenom.nom.ABC\...
    public string? LongPath(string path) => path.Contains('~') ? Native.LongPath(path) : null;

    // Code page ANSI, OEM et celle de la console : une sortie de programme peut être dans chacune.
    public IEnumerable<int> OutputCodePages() => new[] { Native.GetACP(), Native.GetOEMCP(), Native.GetConsoleOutputCP() }.Distinct();

    // Un seul processus attaché à la console : une fenêtre ouverte rien que pour nous.
    public bool IsDedicatedConsole() => Native.ConsoleProcessCount() == 1;

    // UseShellExecute ouvre une nouvelle console pour secret.exe.
    public void OpenWindow(string cwd, IEnumerable<string> args) =>
        Process.Start(new ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = true,
            WorkingDirectory = cwd,
            Arguments = string.Join(" ", args.Select(QuoteArg)),
        });

    // Règles de découpage de CommandLineToArgvW.
    static string QuoteArg(string a)
    {
        if (a.Length > 0 && a.IndexOfAny([' ', '\t', '"']) < 0) return a;
        var sb = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var c in a)
        {
            if (c == '\\') { backslashes++; continue; }
            if (c == '"') sb.Append('\\', backslashes * 2 + 1);
            else sb.Append('\\', backslashes);
            sb.Append(c);
            backslashes = 0;
        }
        sb.Append('\\', backslashes * 2).Append('"');
        return sb.ToString();
    }

    public string? FindExecutable(string name)
    {
        var extensions = (Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD")
            .Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Append(".ps1")
            .ToList();
        IEnumerable<string> Candidates(string basePath)
        {
            if (Path.HasExtension(basePath)) yield return basePath;
            foreach (var ext in extensions) yield return basePath + ext;
        }

        if (name.Contains('\\') || name.Contains('/'))
        {
            var full = Paths.Full(name, Environment.CurrentDirectory);
            return full == null ? null : Candidates(full).FirstOrDefault(File.Exists);
        }
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            string basePath;
            try { basePath = Path.Combine(dir.Trim().Trim('"'), name); }
            catch { continue; }
            var found = Candidates(basePath).FirstOrDefault(File.Exists);
            if (found != null) return found;
        }
        return null;
    }

    public (string File, List<string> Args, string? Raw) ResolveCommand(string path, List<string> args)
    {
        switch (Path.GetExtension(path).ToLowerInvariant())
        {
            case ".exe":
            case ".com":
                return (path, args, null);
            case ".cmd":
            case ".bat":
                var comspec = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe";
                var line = "/d /s /c \"" + string.Join(" ", new[] { path }.Concat(args).Select(CmdQuote)) + "\"";
                return (comspec, new List<string>(), line);
            case ".ps1":
                var ps = FindExecutable("pwsh") ?? FindExecutable("powershell") ?? throw new UserError("PowerShell introuvable");
                var psArgs = new List<string> { "-NoProfile", "-File", path };
                psArgs.AddRange(args);
                return (ps, psArgs, null);
            default:
                throw new UserError($"type de programme non géré : {path}");
        }
    }

    static string CmdQuote(string arg)
    {
        if (arg.Length == 0) return "\"\"";
        if (arg.IndexOfAny([' ', '\t', '"', '&', '|', '<', '>', '^', '(', ')', '%', '!', ',', ';', '=']) < 0) return arg;
        return "\"" + arg.Replace("\"", "\"\"") + "\"";
    }

    // WSL ne reprend pas l'environnement Windows : il faut lui nommer les variables à transmettre.
    public void PrepareChildEnvironment(ProcessStartInfo psi, string file, ICollection<string> keys)
    {
        if (!IsWsl(file) || keys.Count == 0) return;
        var existing = psi.Environment.TryGetValue("WSLENV", out var w) && !string.IsNullOrEmpty(w) ? w + ":" : "";
        psi.Environment["WSLENV"] = existing + string.Join(":", keys);
    }

    static bool IsWsl(string file)
    {
        var name = Path.GetFileName(file).ToLowerInvariant();
        if (name == "wsl.exe") return true;
        var dir = Path.GetDirectoryName(file) ?? "";
        return name == "bash.exe" && (dir.EndsWith("System32", StringComparison.OrdinalIgnoreCase)
                                      || dir.EndsWith("Sysnative", StringComparison.OrdinalIgnoreCase)
                                      || dir.EndsWith("SysWOW64", StringComparison.OrdinalIgnoreCase));
    }

    public ProcessStartInfo InteractiveShell()
    {
        var shell = FindExecutable("pwsh") ?? FindExecutable("powershell") ?? Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe";
        var psi = new ProcessStartInfo(shell) { UseShellExecute = false };
        if (Path.GetFileNameWithoutExtension(shell).StartsWith("p", StringComparison.OrdinalIgnoreCase)) psi.ArgumentList.Add("-NoLogo");
        return psi;
    }

    // Jusqu'à la 0.1.2, le coffre était dans %LOCALAPPDATA%\local-secrets. Lancé depuis Claude Desktop
    // (paquet MSIX), Windows redirigeait ses écritures vers une copie privée du paquet.
    public IEnumerable<string> LegacyVaultDirs()
    {
        var list = new List<string>();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        list.Add(Path.Combine(local, "local-secrets"));
        var packages = Path.Combine(local, "Packages");
        try
        {
            if (Directory.Exists(packages))
                foreach (var p in Directory.EnumerateDirectories(packages))
                {
                    var d = Path.Combine(p, "LocalCache", "Local", "local-secrets");
                    if (File.Exists(Path.Combine(d, "vault.json"))) list.Add(d);
                }
        }
        catch
        {
            // dossier des paquets illisible : seul l'emplacement classique est fusionné
        }
        return list;
    }

    public IEnumerable<(bool Problem, string Message)> DoctorChecks()
    {
        var config = Capture("sc.exe", "qc ssh-agent");
        var state = Capture("sc.exe", "query ssh-agent");
        if (config.Contains("DISABLED")) yield return (true, "service ssh-agent désactivé (utile pour les clés SSH, voir README)");
        else if (state.Contains("RUNNING")) yield return (false, "service ssh-agent démarré");
        else yield return (true, "service ssh-agent arrêté");
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
