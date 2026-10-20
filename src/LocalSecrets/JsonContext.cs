using System.Text.Json.Serialization;

namespace LocalSecrets;

// Sérialisation générée à la compilation : indispensable pour Native AOT (pas de réflexion).
// Noms en camelCase, comme les fichiers écrits par les versions précédentes.
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(VaultData))]
[JsonSerializable(typeof(EnvBackup))]
[JsonSerializable(typeof(Settings))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal partial class JsonContext : JsonSerializerContext;
