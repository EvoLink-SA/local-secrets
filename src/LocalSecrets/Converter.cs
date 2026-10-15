namespace LocalSecrets;

sealed record ConversionReport(
    string FilePath,
    string? Namespace,
    List<(string Key, string Reason)> Encrypted,
    List<(string Key, string Reason)> Clear,
    List<string> References,
    bool Changed);

static class Converter
{
    const long MaxSize = 2_000_000;

    public static ConversionReport? Analyze(string path) => Run(path, dryRun: true, force: null);

    public static ConversionReport? Convert(string path, ISet<string>? force = null) => Run(path, dryRun: false, force);

    // Dossier exclu par l'utilisateur (secret config convert off) : on ne touche pas au fichier.
    public static bool IsExcluded(string path) =>
        Path.GetDirectoryName(Paths.Normalize(path)) is { } dir && Settings.Load().ConversionDisabledFor(dir) != null;

    // Conversion déclenchée sans demande explicite (hooks, secret run, secret env).
    public static ConversionReport? AutoConvert(string path) => IsExcluded(path) ? Analyze(path) : Convert(path);

    public static string? PreferredNamespace(EnvFile env) =>
        env.Assignments
            .Select(a => a.Reference)
            .OfType<string>()
            .Select(r => r[..r.IndexOf('/')])
            .GroupBy(ns => ns)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault();

    static ConversionReport? Run(string path, bool dryRun, ISet<string>? force)
    {
        var full = Paths.Normalize(path);
        var info = new FileInfo(full);
        if (!info.Exists || info.Length > MaxSize) return null;

        var env = EnvFile.Load(full);
        var toEncrypt = new List<(EnvAssignment A, string Reason)>();
        var clear = new List<(string, string)>();
        var refs = new List<string>();
        foreach (var a in env.Assignments)
        {
            if (a.Reference != null) { refs.Add(a.Key); continue; }
            var verdict = force != null && force.Contains(a.Key)
                ? new Verdict(true, "forcé")
                : Classifier.Classify(a.Key, a.Value, a.Annotation);
            if (verdict.Secret) toEncrypt.Add((a, verdict.Reason));
            else clear.Add((a.Key, verdict.Reason));
        }

        var encrypted = toEncrypt.Select(t => (t.A.Key, t.Reason)).ToList();
        var preferred = PreferredNamespace(env);
        if (toEncrypt.Count == 0 || dryRun)
            return new(full, preferred ?? Vault.FindNamespace(Vault.Load(), full), encrypted, clear, refs, false);

        var (ns, values) = Vault.Update(d =>
        {
            var space = Vault.NamespaceForFile(d, full, preferred);
            var map = new Dictionary<EnvAssignment, string>();
            var taken = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var (a, _) in toEncrypt)
            {
                // Même clé deux fois dans le fichier avec deux valeurs : la seconde prend un suffixe.
                var name = $"{space}/{a.Key}";
                for (var n = 2; taken.TryGetValue(name, out var existing) && existing != a.Value; n++)
                    name = $"{space}/{a.Key}.{n}";
                taken[name] = a.Value;
                Vault.Set(d, name, a.Value, full);
                map[a] = "secret://" + name;
            }
            return (space, map);
        });

        Vault.BackupEnvFile(full, env.OriginalBytes);
        EnvFile.WriteInPlace(full, env.Render(values, addHeader: true));

        // Vérification : mêmes clés dans le même ordre, et chaque valeur relisible dans le coffre.
        var check = EnvFile.Load(full);
        var data = Vault.Load();
        var ok = check.Assignments.Select(a => a.Key).SequenceEqual(env.Assignments.Select(a => a.Key));
        foreach (var (a, reference) in values)
            if (Vault.TryGet(data, reference["secret://".Length..]) != a.Value) ok = false;
        if (!ok)
        {
            EnvFile.WriteInPlace(full, env.OriginalBytes);
            throw new InvalidOperationException($"vérification après conversion échouée pour {full}, fichier d'origine remis en place");
        }

        Log.Write($"converti {full} : {values.Count} valeur(s) chiffrée(s) dans l'espace {ns}");
        return new(full, ns, encrypted, clear, refs, true);
    }
}
