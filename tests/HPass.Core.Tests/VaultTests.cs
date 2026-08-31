using System.Text.Json;
using HPass.Core;
using Xunit;

namespace HPass.Core.Tests;

public sealed class TempHome : IDisposable
{
    public string Dir { get; } = Path.Combine(Path.GetTempPath(), "hpass-test-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(Dir, recursive: true); } catch { }
    }
}

public class VaultTests : IDisposable
{
    private readonly TempHome _home = new();

    public void Dispose() => _home.Dispose();

    private Vault CreateVault()
    {
        using var v = Vault.Create(_home.Dir, "correct horse battery");
        return Vault.Open(_home.Dir);
    }

    [Fact]
    public void Create_WritesFilesWithTightPermissions()
    {
        using var _ = Vault.Create(_home.Dir, "correct horse battery");
        Assert.True(File.Exists(Path.Combine(_home.Dir, "vault.json")));
        Assert.True(File.Exists(Path.Combine(_home.Dir, "master.key")));
        Assert.True(Directory.Exists(Path.Combine(_home.Dir, "run")));
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(_home.Dir, "vault.json")));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(_home.Dir, "master.key")));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(_home.Dir));
        }
    }

    [Fact]
    public void RoundTrip_PasswordAndFields()
    {
        using var vault = CreateVault();
        vault.Unlock("correct horse battery");
        var e = vault.GetOrAdd("db", "database", "root", "prod");
        vault.SetPassword(e, "S3cret!");
        vault.SetField(e, "host", "127.0.0.1");
        vault.SetField(e, "api_key", "key-42");
        vault.Save();

        using var reopened = Vault.Open(_home.Dir);
        reopened.Unlock("correct horse battery");
        var entry = reopened.Find("db")!;
        Assert.Equal("S3cret!", reopened.DecryptPassword(entry));
        Assert.Equal("127.0.0.1", reopened.DecryptField(entry, "host"));
        Assert.Equal("key-42", reopened.DecryptField(entry, "api_key"));
    }

    [Fact]
    public void WrongPassphrase_Throws()
    {
        using var _ = Vault.Create(_home.Dir, "correct horse battery");
        using var vault = Vault.Open(_home.Dir);
        Assert.Throws<VaultException>(() => vault.Unlock("wrong pass phrase"));
    }

    [Fact]
    public void TamperedVaultFile_DecryptFails()
    {
        using (var vault = CreateVault())
        {
            vault.Unlock("correct horse battery");
            var e = vault.GetOrAdd("db", null, null, null);
            vault.SetPassword(e, "S3cret!");
            vault.Save();
        }

        // 篡改条目密文（注意不能动 wrappedDek，否则 Unlock 阶段就会失败）
        var path = Path.Combine(_home.Dir, "vault.json");
        var json = JsonSerializer.Deserialize<VaultFile>(File.ReadAllText(path), HPassJsonContext.Default.VaultFile)!;
        var entry = json.Entries.Single(x => x.Name == "db");
        var ct = Convert.FromBase64String(entry.Ct);
        ct[0] ^= 0xFF;
        entry.Ct = Convert.ToBase64String(ct);
        File.WriteAllText(path, JsonSerializer.Serialize(json, HPassJsonContext.Default.VaultFile));

        using var reopened = Vault.Open(_home.Dir);
        reopened.Unlock("correct horse battery");
        Assert.Throws<VaultException>(() => reopened.DecryptPassword(reopened.Find("db")!));
    }

    [Fact]
    public void EntryCiphertextSwap_DetectedByAad()
    {
        using var vault = CreateVault();
        vault.Unlock("correct horse battery");
        var a = vault.GetOrAdd("a", null, null, null);
        var b = vault.GetOrAdd("b", null, null, null);
        vault.SetPassword(a, "password-a");
        vault.SetPassword(b, "password-b");
        vault.Save();

        // 交换两个条目的密文（模拟攻击者互换条目）
        var json = JsonSerializer.Deserialize<VaultFile>(File.ReadAllText(Path.Combine(_home.Dir, "vault.json")), HPassJsonContext.Default.VaultFile)!;
        var ea = json.Entries.First(x => x.Name == "a");
        var eb = json.Entries.First(x => x.Name == "b");
        (ea.Nonce, eb.Nonce) = (eb.Nonce, ea.Nonce);
        (ea.Ct, eb.Ct) = (eb.Ct, ea.Ct);
        File.WriteAllText(Path.Combine(_home.Dir, "vault.json"),
            JsonSerializer.Serialize(json, HPassJsonContext.Default.VaultFile));

        using var reopened = Vault.Open(_home.Dir);
        reopened.Unlock("correct horse battery");
        Assert.Throws<VaultException>(() => reopened.DecryptPassword(reopened.Find("a")!));
        Assert.Throws<VaultException>(() => reopened.DecryptPassword(reopened.Find("b")!));
    }

    [Fact]
    public void FieldCiphertextSwap_DetectedByAad()
    {
        using var vault = CreateVault();
        vault.Unlock("correct horse battery");
        var e = vault.GetOrAdd("db", null, null, null);
        vault.SetField(e, "f1", "value-1");
        vault.SetField(e, "f2", "value-2");
        vault.Save();

        var json = JsonSerializer.Deserialize<VaultFile>(File.ReadAllText(Path.Combine(_home.Dir, "vault.json")), HPassJsonContext.Default.VaultFile)!;
        var entry = json.Entries[0];
        var f1 = entry.Fields.First(f => f.Name == "f1");
        var f2 = entry.Fields.First(f => f.Name == "f2");
        (f1.Ct, f2.Ct) = (f2.Ct, f1.Ct);
        (f1.Nonce, f2.Nonce) = (f2.Nonce, f1.Nonce);
        File.WriteAllText(Path.Combine(_home.Dir, "vault.json"),
            JsonSerializer.Serialize(json, HPassJsonContext.Default.VaultFile));

        using var reopened = Vault.Open(_home.Dir);
        reopened.Unlock("correct horse battery");
        Assert.Throws<VaultException>(() => reopened.DecryptField(reopened.Find("db")!, "f1"));
    }

    [Fact]
    public void Rename_ReencryptsUnderNewAad()
    {
        using var vault = CreateVault();
        vault.Unlock("correct horse battery");
        var e = vault.GetOrAdd("old", "db", "u", "t");
        vault.SetPassword(e, "S3cret!");
        vault.SetField(e, "host", "h1");
        vault.Rename("old", "new");
        vault.Save();

        using var reopened = Vault.Open(_home.Dir);
        reopened.Unlock("correct horse battery");
        var entry = reopened.Find("new")!;
        Assert.Equal("S3cret!", reopened.DecryptPassword(entry));
        Assert.Equal("h1", reopened.DecryptField(entry, "host"));
        Assert.Null(reopened.Find("old"));
    }

    [Fact]
    public void Rotate_EntriesStillDecrypt()
    {
        using var vault = CreateVault();
        vault.Unlock("correct horse battery");
        var e = vault.GetOrAdd("db", null, null, null);
        vault.SetPassword(e, "S3cret!");
        var oldWrapped = vault.Data.WrappedDek.Ct;
        vault.Rotate("correct horse battery");
        vault.Save();
        Assert.NotEqual(oldWrapped, vault.Data.WrappedDek.Ct);

        using var reopened = Vault.Open(_home.Dir);
        reopened.Unlock("correct horse battery");
        Assert.Equal("S3cret!", reopened.DecryptPassword(reopened.Find("db")!));
    }

    [Fact]
    public void ValidateName_Rules()
    {
        Assert.Throws<UsageException>(() => Vault.ValidateName("a.b", "条目名"));
        Assert.Throws<UsageException>(() => Vault.ValidateName("a b", "条目名"));
        Assert.Throws<UsageException>(() => Vault.ValidateName("", "条目名"));
        Assert.Throws<UsageException>(() => Vault.ValidateName("-x", "条目名"));
        Assert.Throws<UsageException>(() => Vault.ValidateName(new string('a', 65), "条目名"));
        Vault.ValidateName("db-local_01", "条目名");
        Vault.ValidateName("A", "条目名");
    }

    [Fact]
    public void SetField_RejectsReservedNames()
    {
        using var vault = CreateVault();
        vault.Unlock("correct horse battery");
        var e = vault.GetOrAdd("db", null, null, null);
        Assert.Throws<UsageException>(() => vault.SetField(e, "user", "x"));
        Assert.Throws<UsageException>(() => vault.SetField(e, "tenant", "x"));
    }

    [Fact]
    public void UnlockWithoutPasswordRefused_LazyUnlockWorks()
    {
        using var vault = CreateVault();
        // 未解锁时解密必须失败
        Assert.Throws<VaultException>(vault.EnsureUnlocked);
        // 元数据操作（list）不需要解锁：可直接读条目数
        Assert.Equal(0, vault.Data.Entries.Count);
    }

    [Fact]
    public void Open_MissingVault_Throws()
    {
        Assert.False(Vault.Exists(_home.Dir));
        Assert.Throws<VaultException>(() => Vault.Open(_home.Dir));
    }
}
