namespace LocalSecrets;

// Efface des fichiers locaux de Claude Code (transcripts, historique, instantanés)
// les valeurs du coffre qui y auraient atterri avant d'être protégées.
static class Scrub
{
    static readonly string[] Targets = ["projects", "file-history", "paste-cache", "shell-snapshots", "debug", "todos", "tasks", "plans", "history.jsonl"];
    const long MaxFileSize = 512L * 1024 * 1024;

    public static int Run(string[] args)
    {
        var dryRun = args.Contains("--dry-run");
        var ask = args.Contains("--ask");
        var force = args.Contains("--force");

        var secrets = Vault.DecryptAll(Vault.Load());
        if (ask)
        {
            Ui.RequireInteractive("secret scrub --ask");
            for (var n = 1; ; n++)
            {
                var v = Ui.ReadSecret($"Valeur supplémentaire à effacer n°{n} (Entrée vide pour terminer) : ");
                if (v.Length == 0) break;
                secrets.Add(($"saisie-{n}", v));
            }
        }
        if (secrets.Count == 0)
        {
            Console.WriteLine("Rien à chercher : le coffre est vide.");
            return 0;
        }

        var patterns = Redactor.BytePatterns(Redactor.Variants(secrets), allEncodings: false);
        var root = Path.Combine(Paths.UserProfile, ".claude");
        var recent = DateTime.Now.AddMinutes(-5);
        int scanned = 0, changed = 0, totalHits = 0;
        var skipped = new List<string>();

        foreach (var file in Files(root))
        {
            FileInfo info;
            try { info = new FileInfo(file); } catch { continue; }
            if (info.Length == 0 || info.Length > MaxFileSize) continue;
            scanned++;
            byte[] bytes;
            try { bytes = File.ReadAllBytes(file); }
            catch { continue; }

            var redactor = new StreamRedactor(patterns);
            using var output = new MemoryStream();
            redactor.Process(bytes, bytes.Length, output, final: true);
            if (redactor.Hits == 0) continue;

            if (!force && info.LastWriteTime > recent)
            {
                skipped.Add(file);
                continue;
            }
            totalHits += redactor.Hits;
            changed++;
            Console.WriteLine($"{(dryRun ? "à nettoyer" : "nettoyé")} : {Path.GetRelativePath(root, file)} ({redactor.Hits} occurrence(s))");
            if (dryRun) continue;
            var lastWrite = info.LastWriteTimeUtc;
            var tmp = file + ".scrub.tmp";
            Paths.WritePrivate(tmp, output.ToArray());
            File.Move(tmp, file, overwrite: true);
            File.SetLastWriteTimeUtc(file, lastWrite);
        }

        Console.WriteLine($"{scanned} fichier(s) examiné(s), {changed} {(dryRun ? "à nettoyer" : "nettoyé(s)")}, {totalHits} occurrence(s).");
        if (skipped.Count > 0)
        {
            Console.WriteLine($"{skipped.Count} fichier(s) modifié(s) il y a moins de 5 minutes, laissés de côté (session en cours ?) :");
            foreach (var s in skipped) Console.WriteLine("  " + Path.GetRelativePath(root, s));
            Console.WriteLine("Ferme les sessions Claude Code concernées puis relance, ou ajoute --force.");
        }
        return 0;
    }

    static IEnumerable<string> Files(string root)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var target in Targets)
        {
            var path = Path.Combine(root, target);
            if (File.Exists(path)) yield return path;
            else if (Directory.Exists(path))
                foreach (var f in Directory.EnumerateFiles(path, "*", options))
                    if (!f.EndsWith(".scrub.tmp", StringComparison.OrdinalIgnoreCase))
                        yield return f;
        }
    }
}
