using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace LocalSecrets;

// « secret wsl-key » : côté Windows du pont WSL, appelé par secret sous Linux, jamais à la main.
// wrap   : reçoit la clé privée du coffre WSL sur l'entrée standard, renvoie son blob DPAPI.
// unwrap : reçoit ce blob et une clé publique éphémère, renvoie la clé privée chiffrée pour cette
//          clé éphémère (ECIES) : la sortie ne la montre jamais en clair.
[SupportedOSPlatform("windows")]
static class WslKeyCmd
{
    static readonly byte[] Entropy = Encoding.UTF8.GetBytes("local-secrets/wsl-bridge");

    // Pas de refus sur CLAUDECODE ici : lancé depuis WSL, ce processus hérite de l'environnement Windows
    // de la fenêtre qui a ouvert WSL, pas de celui de l'appelant Linux. La protection tient au garde-fou
    // (Claude ne peut pas citer « wsl-key ») et à la réponse d'unwrap, chiffrée pour une clé éphémère.
    public static int Run(string[] args)
    {
        if (!Console.IsInputRedirected)
            throw new UserError("« secret wsl-key » sert au pont avec WSL : c'est secret, sous Linux, qui l'appelle (secret unlock --remember).");
        var input = Console.In.ReadToEnd().Trim();
        switch (args.FirstOrDefault())
        {
            case "wrap":
            {
                var pkcs8 = Convert.FromBase64String(input);
                try
                {
                    Console.Out.Write(Convert.ToBase64String(Native.Protect(pkcs8, Entropy)));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pkcs8);
                }
                return 0;
            }
            case "unwrap":
            {
                var request = JsonNode.Parse(input) as JsonObject ?? throw new UserError("requête illisible");
                var blob = Convert.FromBase64String((string?)request["blob"] ?? throw new UserError("blob absent"));
                var point = Convert.FromBase64String((string?)request["point"] ?? throw new UserError("clé éphémère absente"));
                var pkcs8 = Native.Unprotect(blob, Entropy);
                try
                {
                    Console.Out.Write(Convert.ToBase64String(Ecies.Encrypt(point, pkcs8, Entropy)));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(pkcs8);
                }
                return 0;
            }
            default:
                throw new UserError("usage : secret wsl-key wrap|unwrap (appelé par secret sous WSL)");
        }
    }
}
