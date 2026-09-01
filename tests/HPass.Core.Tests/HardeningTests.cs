using HPass.Core;
using Xunit;

namespace HPass.Core.Tests;

public class HardeningTests : IDisposable
{
    private readonly string _tmp = Path.Combine(Path.GetTempPath(), "hpass-harden-" + Guid.NewGuid().ToString("N"));
    private static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();
    private static bool Mac => OperatingSystem.IsMacOS();

    public HardeningTests() => Directory.CreateDirectory(_tmp);
    public void Dispose()
    {
        foreach (var f in Directory.GetFiles(_tmp)) Hardening.ClearImmutable(f);
        try { Directory.Delete(_tmp, true); } catch { }
    }

    private string Touch(string name, string content = "x")
    {
        var p = Path.Combine(_tmp, name);
        File.WriteAllText(p, content);
        return p;
    }

    [Fact]
    public void UserImmutable_RoundTrip()
    {
        if (!Mac) return;
        var p = Touch("imm.txt");
        Assert.False(Hardening.IsImmutable(p));
        Hardening.SetImmutable(p);
        Assert.True(Hardening.IsImmutable(p));
        Assert.True(Hardening.IsProtected(p));
        Hardening.ClearImmutable(p);
        Assert.False(Hardening.IsImmutable(p));
        Assert.True(Hardening.IsUserWritable(p));
    }

    [Fact]
    public void IsUserWritable_ReflectsMode()
    {
        if (!Unix) return;
        var p = Touch("w.txt");
        Assert.True(Hardening.IsUserWritable(p));
        File.SetUnixFileMode(p, UnixFileMode.UserRead);
        Assert.False(Hardening.IsUserWritable(p));
        Assert.True(Hardening.IsProtected(p));
        File.SetUnixFileMode(p, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Assert.True(Hardening.IsUserWritable(p));
    }

    [Fact]
    public void GetLevel_Matrix()
    {
        if (!Unix) return;
        // None：缺文件
        var none = Path.Combine(_tmp, "home-none");
        Assert.Equal(Hardening.Level.None, Hardening.GetLevel(none));

        // 用假核心文件构造各等级（0444 模拟"属主不可写"的保护效果，跨 mac/linux 可用）
        foreach (var (name, modes) in new[]
                 {
                     ("home-basic", (int)0), ("home-hardened", 0b11), ("home-interrupted", 0b01),
                 })
        {
            var home = Path.Combine(_tmp, name);
            Directory.CreateDirectory(home);
            foreach (var f in Hardening.CoreFiles) File.WriteAllText(Path.Combine(home, f), "{}");
            var idx = 0;
            foreach (var f in Hardening.CoreFiles)
            {
                if ((modes & (1 << idx)) != 0)
                    File.SetUnixFileMode(Path.Combine(home, f), UnixFileMode.UserRead);
                idx++;
            }
        }
        Assert.Equal(Hardening.Level.Basic, Hardening.GetLevel(Path.Combine(_tmp, "home-basic")));
        Assert.Equal(Hardening.Level.Hardened, Hardening.GetLevel(Path.Combine(_tmp, "home-hardened")));
        Assert.Equal(Hardening.Level.Interrupted, Hardening.GetLevel(Path.Combine(_tmp, "home-interrupted")));
    }

    [Fact]
    public void CleanStaging_RemovesLeftovers()
    {
        var home = Path.Combine(_tmp, "home-clean");
        var staging = Path.Combine(home, "run", "staging");
        Directory.CreateDirectory(staging);
        var a = Path.Combine(staging, "vault.json.aaa");
        var b = Path.Combine(staging, "vault.json.bbb");
        File.WriteAllText(a, "ct");
        File.WriteAllText(b, "ct");
        File.SetLastWriteTimeUtc(a, DateTime.UtcNow.AddMinutes(-5));
        File.SetLastWriteTimeUtc(b, DateTime.UtcNow.AddMinutes(-5));
        Assert.Equal(2, Hardening.CleanStaging(home));
        Assert.Empty(Directory.GetFiles(staging));
        Assert.Equal(0, Hardening.CleanStaging(home));

        // 60s 内的新鲜暂存不清理（可能是并发 set 正在等待提权搬运）
        var fresh = Path.Combine(staging, "vault.json.fresh");
        File.WriteAllText(fresh, "ct");
        Assert.Equal(0, Hardening.CleanStaging(home));
        Assert.True(File.Exists(fresh));
    }

    [Fact]
    public void InstallStaged_PlainFile_AtomicReplace()
    {
        var final = Touch("final.json", "old");
        var staged = Touch("vault.json.stg1", "new-content");
        SecureFile.InstallStaged(staged, final, _tmp);
        Assert.Equal("new-content", File.ReadAllText(final));
        Assert.False(File.Exists(staged));
    }

    [Fact]
    public void InstallStaged_ImmutableFile_ClearMoveReprotect()
    {
        if (!Mac) return;
        var final = Touch("final-imm.json", "old");
        Hardening.SetImmutable(final);
        var staged = Touch("vault.json.stg2", "new-content-2");

        SecureFile.InstallStaged(staged, final, _tmp);

        Assert.Equal("new-content-2", File.ReadAllText(final));
        Assert.True(Hardening.IsImmutable(final), "安装后必须重新加保护（I6）");
    }

    [Fact]
    public void InstallStaged_RootStyleProtection_ThrowsNeedsElevation()
    {
        if (!Unix) return;
        var prev = Environment.GetEnvironmentVariable("HPASS_NO_SUDO");
        Environment.SetEnvironmentVariable("HPASS_NO_SUDO", "1");
        try
        {
            var final = Touch("final-root.json", "old");
            File.SetUnixFileMode(final, UnixFileMode.UserRead); // 属主不可写：模拟 root 属主
            var staged = Touch("vault.json.stg3", "new-content-3");

            var ex = Assert.Throws<NeedsElevationException>(() => SecureFile.InstallStaged(staged, final, _tmp));
            Assert.Equal(staged, ex.StagingPath);
            Assert.Equal(final, ex.FinalPath);
            Assert.Contains("_install-staged", ex.Message);
            // 失败不产生半写：最终文件与暂存文件都保持原状
            Assert.Equal("old", File.ReadAllText(final));
            Assert.True(File.Exists(staged));
        }
        finally
        {
            Environment.SetEnvironmentVariable("HPASS_NO_SUDO", prev);
            File.SetUnixFileMode(Path.Combine(_tmp, "final-root.json"), UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
