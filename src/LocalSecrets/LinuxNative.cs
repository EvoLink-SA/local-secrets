using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Text;

namespace LocalSecrets;

// Appels natifs Linux (x86_64), utilisés seulement par LinuxPlatform et KeyStore.
// Trousseau noyau par appels système directs : pas de dépendance à libkeyutils.
[SupportedOSPlatform("linux")]
static class LinuxNative
{
    const long SysAddKey = 248;
    const long SysKeyctl = 250;

    // Trousseau de l'utilisateur (@u) : commun à toutes ses sessions, donc aux hooks de Claude
    // comme à son terminal, et vidé au redémarrage.
    const long UserKeyring = -4;

    // Trousseau du processus : la clé y naît, possédée par nous, le temps d'en régler les droits.
    const long ProcessKeyring = -2;

    const long KeyctlSetPerm = 5;
    const long KeyctlLink = 8;
    const long KeyctlSearch = 10;
    const long KeyctlRead = 11;
    const long KeyctlSetTimeout = 15;
    const long KeyctlInvalidate = 21;

    // Possesseur : tout ; même utilisateur : voir, lire, chercher. Sans les droits « utilisateur »,
    // un processus d'une autre session (hook, nouveau terminal) ne retrouverait pas la clé.
    const ulong KeyPerm = 0x3f000000 | 0x00010000 | 0x00020000 | 0x00080000;

    const int ENOKEY = 126;
    const int EKEYEXPIRED = 127;
    const int EKEYREVOKED = 128;

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    static extern long AddKey(long number, byte[] type, byte[] description, byte[] payload, nuint length, long keyring);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    static extern long KeyctlFind(long number, long operation, long keyring, byte[] type, byte[] description, long destination);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    static extern long KeyctlReadInto(long number, long operation, long key, byte[] buffer, nuint length);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true)]
    static extern long Keyctl(long number, long operation, long key, ulong argument);

    [DllImport("libc", EntryPoint = "isatty")]
    static extern int IsATty(int fd);

    public static bool IsTerminal(int fd) => IsATty(fd) == 1;

    static byte[] CString(string s) => Encoding.UTF8.GetBytes(s + "\0");

    static long Find(string description) =>
        KeyctlFind(SysKeyctl, KeyctlSearch, UserKeyring, CString("user"), CString(description), 0);

    // Trousseau noyau utilisable ? Faux dans un conteneur Docker (seccomp) ou un noyau sans clés.
    public static bool KeyringAvailable(out string error)
    {
        error = "";
        if (Find("local-secrets:sonde") >= 0) return true;
        var errno = Marshal.GetLastPInvokeError();
        if (errno is ENOKEY or EKEYEXPIRED or EKEYREVOKED) return true;
        error = new System.ComponentModel.Win32Exception(errno).Message;
        return false;
    }

    // Range (ou remplace) une valeur dans le trousseau de l'utilisateur, pour une durée limitée.
    // La clé est créée dans le trousseau du processus, qu'on possède toujours : ajoutée directement à
    // @u, elle ne serait pas « possédée » sans session de connexion (conteneur, certains SSH), et ses
    // droits ne pourraient pas être réglés. Elle est ensuite reliée à @u, où elle remplace l'ancienne.
    public static void Store(string description, byte[] payload, TimeSpan lifetime)
    {
        var key = AddKey(SysAddKey, CString("user"), CString(description), payload, (nuint)payload.Length, ProcessKeyring);
        if (key < 0) throw Failure("ajout au trousseau noyau");
        if (Keyctl(SysKeyctl, KeyctlSetPerm, key, KeyPerm) < 0) throw Failure("droits de la clé");
        if (Keyctl(SysKeyctl, KeyctlSetTimeout, key, (ulong)Math.Max(1, lifetime.TotalSeconds)) < 0) throw Failure("durée de la clé");
        if (Keyctl(SysKeyctl, KeyctlLink, key, unchecked((ulong)UserKeyring)) < 0) throw Failure("rattachement au trousseau de l'utilisateur");
    }

    // Valeur rangée sous ce nom, ou null si elle n'existe pas ou a expiré.
    public static byte[]? Read(string description)
    {
        var key = Find(description);
        if (key < 0) return null;
        var buffer = new byte[4096];
        var n = KeyctlReadInto(SysKeyctl, KeyctlRead, key, buffer, (nuint)buffer.Length);
        if (n < 0) return null;
        var result = buffer[..(int)n];
        Array.Clear(buffer);
        return result;
    }

    public static void Drop(string description)
    {
        var key = Find(description);
        if (key >= 0) Keyctl(SysKeyctl, KeyctlInvalidate, key, 0);
    }

    // Durée restante, lue dans /proc/keys (colonne d'expiration : « 59s », « 7h », « 2d », « perm »).
    public static TimeSpan? Remaining(string description)
    {
        var key = Find(description);
        if (key < 0) return null;
        try
        {
            var id = key.ToString("x8");
            var line = File.ReadLines("/proc/keys").FirstOrDefault(l => l.StartsWith(id, StringComparison.Ordinal));
            var expiry = line?.Split(' ', StringSplitOptions.RemoveEmptyEntries)[3];
            if (expiry == null || expiry.Length < 2 || !int.TryParse(expiry[..^1], out var n)) return null;
            return expiry[^1] switch
            {
                's' => TimeSpan.FromSeconds(n),
                'm' => TimeSpan.FromMinutes(n),
                'h' => TimeSpan.FromHours(n),
                'd' => TimeSpan.FromDays(n),
                'w' => TimeSpan.FromDays(7 * n),
                _ => null,
            };
        }
        catch
        {
            return null;
        }
    }

    static UserError Failure(string what) =>
        new($"{what} impossible : {new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()).Message}");
}
