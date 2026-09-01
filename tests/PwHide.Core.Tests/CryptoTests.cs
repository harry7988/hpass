using System.Security.Cryptography;
using System.Text;
using PwHide.Core;
using Xunit;

namespace PwHide.Core.Tests;

public class CryptoTests
{
    [Fact]
    public void SealUnseal_RoundTrip()
    {
        var key = Crypto.RandomBytes(Crypto.KeySize);
        var aad = Encoding.UTF8.GetBytes("entry|password");
        var box = Crypto.Seal(key, "p@ss w0rd 中文 🔐"u8, aad);
        var pt = Crypto.Unseal(key, box, aad);
        Assert.Equal("p@ss w0rd 中文 🔐", Encoding.UTF8.GetString(pt));
    }

    [Fact]
    public void TamperedCiphertext_Fails()
    {
        var key = Crypto.RandomBytes(Crypto.KeySize);
        var aad = Encoding.UTF8.GetBytes("a");
        var box = Crypto.Seal(key, "secret"u8, aad);
        var raw = Convert.FromBase64String(box.Ct);
        raw[0] ^= 0xFF;
        var tampered = box with { Ct = Convert.ToBase64String(raw) };
        Assert.Throws<VaultException>(() => Crypto.Unseal(key, tampered, aad));
    }

    [Fact]
    public void WrongAad_Fails()
    {
        var key = Crypto.RandomBytes(Crypto.KeySize);
        var box = Crypto.Seal(key, "secret"u8, "entry-a|password"u8);
        Assert.Throws<VaultException>(() => Crypto.Unseal(key, box, "entry-b|password"u8));
    }

    [Fact]
    public void WrongKey_Fails()
    {
        var box = Crypto.Seal(Crypto.RandomBytes(Crypto.KeySize), "secret"u8, "a"u8);
        Assert.Throws<VaultException>(() => Crypto.Unseal(Crypto.RandomBytes(Crypto.KeySize), box, "a"u8));
    }

    [Fact]
    public void Pbkdf2_DeterministicAndSaltSensitive()
    {
        var salt = Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAA==");
        var k1 = Crypto.DeriveKey("password", salt, 1000);
        var k2 = Crypto.DeriveKey("password", salt, 1000);
        var k3 = Crypto.DeriveKey("password", Convert.FromBase64String("BBBBBBBBBBBBBBBBBBBBBB=="), 1000);
        Assert.Equal(k1, k2);
        Assert.NotEqual(k1, k3);
        Assert.Equal(Crypto.KeySize, k1.Length);
    }

    [Fact]
    public void RsaWrapUnwrap_RoundTrip()
    {
        using var rsa = Crypto.GenerateIdentity();
        var dek = Crypto.RandomBytes(Crypto.DekSize);
        var wrapped = Crypto.WrapDek(rsa, dek);
        Assert.NotEqual(dek, wrapped);
        Assert.Equal(dek, Crypto.UnwrapDek(rsa, wrapped));
    }

    [Fact]
    public void TamperedWrappedDek_Fails()
    {
        using var rsa = Crypto.GenerateIdentity();
        var wrapped = Crypto.WrapDek(rsa, Crypto.RandomBytes(Crypto.DekSize));
        wrapped[5] ^= 0x55;
        Assert.Throws<VaultException>(() => Crypto.UnwrapDek(rsa, wrapped));
    }
}
