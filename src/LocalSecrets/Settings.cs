using System.Text;
using System.Text.Json;

namespace LocalSecrets;

// Réglages de l'utilisateur, à côté du coffre (donc illisibles et non modifiables par Claude).
sealed class Settings
{
    public const string EnvSwitch = "LOCAL_SECRETS_OUTPUT_MASKING";

    public bool OutputMasking { get; set; } = true;
    public List<string> OutputMaskingOffIn { get; set; } = new();
    public List<string> NeverMask { get; set; } = new();
    public List<string> ConversionOffIn { get; set; } = new();

    public static string FilePath => Path.Combine(Vault.Home, "config.json");

    static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    // Un fichier illisible redonne les réglages par défaut, c'est-à-dire tout actif.
    public static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath)) return JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath), Json) ?? new Settings();
        }
        catch (Exception e)
        {
            Log.Write("réglages illisibles, valeurs par défaut : " + e.Message);
        }
        return new Settings();
    }

    public void Save()
    {
        Directory.CreateDirectory(Vault.Home);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Json), new UTF8Encoding(false));
    }

    // La variable d'environnement, posée par l'utilisateur au lancement de Claude Code, l'emporte
    // sur le fichier : c'est l'interrupteur des sessions automatisées.
    public bool OutputMaskingFor(string? dir, out string why)
    {
        var env = Environment.GetEnvironmentVariable(EnvSwitch)?.Trim();
        if (!string.IsNullOrEmpty(env))
        {
            var on = env.ToLowerInvariant() is not ("0" or "off" or "false" or "non" or "no");
            why = $"{(on ? "actif" : "coupé")} par la variable {EnvSwitch}={env}";
            return on;
        }
        if (!OutputMasking)
        {
            why = "coupé partout (secret config masking off)";
            return false;
        }
        if (dir != null && Under(OutputMaskingOffIn, dir) is { } project)
        {
            why = $"coupé pour {project}";
            return false;
        }
        why = "actif";
        return true;
    }

    public string? ConversionDisabledFor(string dir) => Under(ConversionOffIn, dir);

    static string? Under(List<string> roots, string dir)
    {
        var d = Path.TrimEndingDirectorySeparator(Paths.Normalize(dir));
        foreach (var p in roots)
        {
            var n = Path.TrimEndingDirectorySeparator(Paths.Normalize(p));
            if (d.Equals(n, StringComparison.OrdinalIgnoreCase) || d.StartsWith(n + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return p;
        }
        return null;
    }
}
