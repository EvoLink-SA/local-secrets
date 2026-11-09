using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LocalSecrets;

// Appels natifs Windows, utilisés seulement par WindowsPlatform.
static class Native
{
    [StructLayout(LayoutKind.Sequential)]
    struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptProtectData(ref DataBlob dataIn, string? description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptUnprotectData(ref DataBlob dataIn, IntPtr description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr mem);

    [DllImport("kernel32.dll")]
    public static extern int GetACP();

    [DllImport("kernel32.dll")]
    public static extern int GetOEMCP();

    [DllImport("kernel32.dll")]
    public static extern int GetConsoleOutputCP();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int GetLongPathNameW(string shortPath, char[] buffer, int bufferLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint GetConsoleProcessList(uint[] processList, uint processCount);

    // Nombre de processus attachés à notre console : 1 dans une fenêtre ouverte rien que pour nous.
    public static int ConsoleProcessCount()
    {
        var list = new uint[32];
        return (int)GetConsoleProcessList(list, (uint)list.Length);
    }

    // C:\Users\PRENOM~1.ABC\... devient C:\Users\prenom.nom.ABC\... (le chemin doit exister).
    public static string? LongPath(string path)
    {
        var buffer = new char[1024];
        var n = GetLongPathNameW(path, buffer, buffer.Length);
        if (n > buffer.Length)
        {
            buffer = new char[n];
            n = GetLongPathNameW(path, buffer, buffer.Length);
        }
        return n > 0 && n <= buffer.Length ? new string(buffer, 0, n) : null;
    }

    const int UiForbidden = 0x1;

    // DPAPI, portée utilisateur courant : seul ce compte Windows sur cette machine peut relire.
    public static byte[] Protect(byte[] data, byte[] entropy) => Dpapi(data, entropy, protect: true);

    public static byte[] Unprotect(byte[] data, byte[] entropy) => Dpapi(data, entropy, protect: false);

    static byte[] Dpapi(byte[] data, byte[] entropy, bool protect)
    {
        var hData = GCHandle.Alloc(data, GCHandleType.Pinned);
        var hEntropy = GCHandle.Alloc(entropy, GCHandleType.Pinned);
        var output = new DataBlob();
        try
        {
            var input = new DataBlob { Size = data.Length, Data = hData.AddrOfPinnedObject() };
            var ent = new DataBlob { Size = entropy.Length, Data = hEntropy.AddrOfPinnedObject() };
            var ok = protect
                ? CryptProtectData(ref input, "local-secrets", ref ent, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, ref ent, IntPtr.Zero, IntPtr.Zero, UiForbidden, out output);
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
            var result = new byte[output.Size];
            Marshal.Copy(output.Data, result, 0, output.Size);
            return result;
        }
        finally
        {
            if (output.Data != IntPtr.Zero)
            {
                Marshal.Copy(new byte[output.Size], 0, output.Data, output.Size);
                LocalFree(output.Data);
            }
            hData.Free();
            hEntropy.Free();
        }
    }
}
