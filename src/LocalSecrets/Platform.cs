using System.Diagnostics;

namespace LocalSecrets;

// Ce qui dépend du système d'exploitation : protection des valeurs, console, lancement de
// programmes, anciens emplacements, contrôles de « secret doctor ». Le reste du code ne passe
// que par Platform.Current. Seul Windows est implémenté pour l'instant.
interface IPlatform
{
    // Nom de la protection des valeurs, pour doctor et les autotests (DPAPI sous Windows).
    string ProtectionName { get; }

    // Chiffre pour ce compte sur cette machine. L'entropie lie la valeur à son nom : relue sous
    // un autre nom, elle ne se déchiffre pas.
    byte[] Protect(byte[] data, byte[] entropy);
    byte[] Unprotect(byte[] data, byte[] entropy);

    // Chemin tel qu'un shell du système l'écrit, ramené à la forme native (/c/... de Git Bash).
    string FromShellPath(string path);

    // Forme longue d'un chemin existant (noms courts 8.3 sous Windows), null si rien à changer.
    string? LongPath(string path);

    // Encodages possibles des sorties de programmes, en plus d'UTF-8 et UTF-16.
    IEnumerable<int> OutputCodePages();

    // Console ouverte rien que pour nous : condition pour afficher des valeurs dans « secret show ».
    bool IsDedicatedConsole();

    // Relance secret avec ces arguments dans une fenêtre à part, sur l'écran de l'utilisateur.
    void OpenWindow(string cwd, IEnumerable<string> args);

    // Chemin complet d'un programme, comme le trouverait le shell, ou null.
    string? FindExecutable(string name);

    // Programme réellement lancé pour ce fichier, avec ses arguments (Raw : ligne déjà construite).
    (string File, List<string> Args, string? Raw) ResolveCommand(string path, List<string> args);

    // Ajustements de l'environnement d'un enfant qui reçoit ces variables (WSLENV sous Windows).
    void PrepareChildEnvironment(ProcessStartInfo psi, string file, ICollection<string> keys);

    // Shell interactif de « secret shell ».
    ProcessStartInfo InteractiveShell();

    // Anciens emplacements du coffre, fusionnés automatiquement.
    IEnumerable<string> LegacyVaultDirs();

    // Contrôles propres au système, pour « secret doctor » : (problème ?, message).
    IEnumerable<(bool Problem, string Message)> DoctorChecks();

    // Nom de l'exécutable livré dans bin\ et du script d'installation.
    string ExecutableName { get; }
    string InstallScript { get; }
}

static class Platform
{
    static readonly IPlatform? current = OperatingSystem.IsWindows() ? new WindowsPlatform() : null;

    public static IPlatform Current => current ?? throw new UserError("local-secrets ne fonctionne pour l'instant que sous Windows.");

    // Noms de variables d'environnement : insensibles à la casse sous Windows, sensibles ailleurs.
    public static readonly StringComparer VariableComparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
}
