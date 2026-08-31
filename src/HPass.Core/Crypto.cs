using System.Security.Cryptography;

namespace HPass.Core;

public readonly record struct SealedBox(string Nonce, string Ct);

public static class Crypto
{
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;          // AES-256
    public const int DekSize = 32;
    public const int SaltSize = 16;
    public const int RsaKeyBits = 3072;

    public static byte[] RandomBytes(int n) => RandomNumberGenerator.GetBytes(n);

    public static byte[] DeriveKey(string passphrase, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA512, KeySize);

    /// <summary>AES-256-GCM 加密，返回 base64(nonce) 与 base64(ciphertext||tag)。</summary>
    public static SealedBox Seal(byte[] key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        var nonce = RandomBytes(NonceSize);
        var ct = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ct, tag, aad);
        var ctAndTag = new byte[ct.Length + tag.Length];
        ct.AsSpan().CopyTo(ctAndTag);
        tag.AsSpan().CopyTo(ctAndTag.AsSpan(ct.Length));
        return new SealedBox(Convert.ToBase64String(nonce), Convert.ToBase64String(ctAndTag));
    }

    /// <summary>解密；认证失败（篡改/密钥错误）抛 VaultException。</summary>
    public static byte[] Unseal(byte[] key, in SealedBox box, ReadOnlySpan<byte> aad)
    {
        var nonce = Convert.FromBase64String(box.Nonce);
        var ctAndTag = Convert.FromBase64String(box.Ct);
        if (ctAndTag.Length < TagSize)
            throw new VaultException("密文长度非法，数据可能已损坏");
        var ct = ctAndTag.AsSpan(0, ctAndTag.Length - TagSize);
        var tag = ctAndTag.AsSpan(ctAndTag.Length - TagSize);
        var pt = new byte[ct.Length];
        using var aes = new AesGcm(key, TagSize);
        try
        {
            aes.Decrypt(nonce, ct, tag, pt, aad);
        }
        catch (CryptographicException)
        {
            throw new VaultException("解密失败：数据被篡改，或口令/密钥不正确");
        }
        return pt;
    }

    public static RSA GenerateIdentity() => RSA.Create(RsaKeyBits);

    public static byte[] WrapDek(RSA rsa, byte[] dek) =>
        rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);

    public static byte[] UnwrapDek(RSA rsa, byte[] wrapped)
    {
        try
        {
            return rsa.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException)
        {
            throw new VaultException("解密失败：数据被篡改，或口令/密钥不正确");
        }
    }

    public static byte[] ExportPrivateKey(RSA rsa) =>
        rsa.ExportPkcs8PrivateKey();

    public static RSA ImportPrivateKey(byte[] pkcs8)
    {
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8, out _);
        return rsa;
    }

    public static byte[] ExportPublicKey(RSA rsa) => rsa.ExportSubjectPublicKeyInfo();

    public static RSA ImportPublicKey(byte[] spki)
    {
        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spki, out _);
        return rsa;
    }
}
