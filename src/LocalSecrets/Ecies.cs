using System.Security.Cryptography;
using System.Text;

namespace LocalSecrets;

// ECIES sur P-256 : clé éphémère, accord ECDH avec la clé publique du destinataire, HKDF-SHA256,
// AES-256-GCM. L'entropie est la donnée associée : relu avec une autre entropie, le blob est refusé.
// Format : version (1) | point éphémère (65) | nonce (12) | tag (16) | chiffré.
// Sert au coffre Linux (KeyStore) et au pont WSL, des deux côtés (Windows et Linux).
static class Ecies
{
    const byte BlobVersion = 1;
    const int PointLength = 65;   // point P-256 non compressé : 0x04, X, Y
    static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("local-secrets/ecies-v1");

    public static ECDiffieHellman NewKey() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    public static byte[] Encrypt(byte[] recipientPoint, byte[] data, byte[] entropy)
    {
        using var recipient = FromPoint(recipientPoint);
        using var ephemeral = NewKey();
        var ephemeralPoint = Point(ephemeral);
        var key = DeriveKey(ephemeral.DeriveRawSecretAgreement(recipient.PublicKey), ephemeralPoint, recipientPoint);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[data.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, data, cipher, tag, entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return [BlobVersion, .. ephemeralPoint, .. nonce, .. tag, .. cipher];
    }

    public static byte[] Decrypt(ECDiffieHellman privateKey, byte[] blob, byte[] entropy)
    {
        const int header = 1 + PointLength + 12 + 16;
        if (blob.Length < header || blob[0] != BlobVersion)
            throw new CryptographicException("format de valeur inconnu (coffre créé par une autre protection ?)");
        var ephemeralPoint = blob[1..(1 + PointLength)];
        var nonce = blob[(1 + PointLength)..(1 + PointLength + 12)];
        var tag = blob[(1 + PointLength + 12)..header];
        var cipher = blob[header..];
        using var ephemeral = FromPoint(ephemeralPoint);
        var key = DeriveKey(privateKey.DeriveRawSecretAgreement(ephemeral.PublicKey), ephemeralPoint, Point(privateKey));
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plain, entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
        return plain;
    }

    static byte[] DeriveKey(byte[] shared, byte[] ephemeralPoint, byte[] recipientPoint)
    {
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, [.. ephemeralPoint, .. recipientPoint], HkdfInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
        }
    }

    public static byte[] Point(ECDiffieHellman key)
    {
        var q = key.ExportParameters(false).Q;
        return [0x04, .. q.X!, .. q.Y!];
    }

    static ECDiffieHellman FromPoint(byte[] point)
    {
        if (point.Length != PointLength || point[0] != 0x04) throw new CryptographicException("clé publique invalide");
        return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = point[1..33], Y = point[33..] },
        });
    }
}
