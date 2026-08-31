using HPass.Core;
using Xunit;

namespace HPass.IntegrationTests;

/// <summary>
/// M3 特权加固全链路（用户级路径本地可测；管理员级 root+schg 流程由 CI 的 AOT 冒烟
/// 以真实 sudo 覆盖，见 .github/workflows/ci.yml 的 root harden flow 段）。
/// </summary>
[Collection("sequential")]
public class HardeningFlowTests
{
    private static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();
    private static bool Mac => OperatingSystem.IsMacOS();
    private readonly CliFixture F;

    public HardeningFlowTests(CliFixture f) => F = f;

    private string NewHome(string prefix)
    {
        var home = Path.Combine(Path.GetTempPath(), $"hpass-it-{prefix}-" + Guid.NewGuid().ToString("N"));
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", "init-pass-123");
        try
        {
            Assert.Equal(0, F.RunIn(home, null, "init", "--no-harden").Exit);
            Assert.Equal(0, F.RunIn(home, "hard-pw-1", "set", "seed", "-u", "u0", "--password-stdin").Exit);
        }
        finally { Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null); }
        return home;
    }

    private void DeleteHome(string home)
    {
        foreach (var f in Hardening.CoreFiles) Hardening.ClearImmutable(Path.Combine(home, f));
        try { Directory.Delete(home, true); } catch { }
    }

    [Fact]
    public void Set_UnderUserImmutableProtection_AutoClearAndReprotect()
    {
        if (!Mac) return; // 用户级 uchg 仅 macOS；Linux 普通用户无法设置不可变
        var home = NewHome("uchg");
        try
        {
            foreach (var f in Hardening.CoreFiles) Hardening.SetImmutable(Path.Combine(home, f));
            Assert.True(Hardening.GetLevel(home) == Hardening.Level.Hardened);

            Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", "init-pass-123");
            var (exit, _, stderr) = F.RunIn(home, "uchg-pw-9", "set", "second", "--password-stdin");
            Assert.Equal(0, exit);

            // 清保护 → 覆盖 → 重新加保护：新内容生效且文件仍不可变
            Assert.True(Hardening.IsImmutable(Path.Combine(home, "vault.json")), "vault.json 安装后必须重新加保护");
            Assert.True(Hardening.IsImmutable(Path.Combine(home, "master.key")));

            var (execExit, stdout, _) = F.RunIn(home, null, "exec", "--allow-echo", "--", "/bin/echo", "{{second}}");
            Assert.Equal(0, execExit);
            Assert.Equal("{{second}}\n", stdout);
            Assert.DoesNotContain("uchg-pw-9", stderr);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null);
            DeleteHome(home);
        }
    }

    [Fact]
    public void Set_RootStyleProtection_NeedsElevation_CleanFailure()
    {
        if (!Unix) return;
        var home = NewHome("rootstyle");
        try
        {
            var vaultPath = Path.Combine(home, "vault.json");
            var before = File.ReadAllBytes(vaultPath);
            // 模拟管理员级保护效果：属主失去写位（清保护后仍不可写 → 走提权路径 → 测试环境禁用 sudo → 拒绝）
            File.SetUnixFileMode(vaultPath, UnixFileMode.UserRead);

            Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", "init-pass-123");
            var (exit, _, stderr) = F.RunIn(home, "elev-pw-9", "set", "third", "--password-stdin");
            Assert.Equal(ExitCodes.Vault, exit);
            Assert.Contains("_install-staged", stderr);
            Assert.DoesNotContain("elev-pw-9", stderr);

            // I6：失败不产生半写状态 —— 最终文件未变
            Assert.Equal(before, File.ReadAllBytes(vaultPath));
            // 暂存密文保留（供 sudo 手动搬运），且不含明文密码
            var stagingDir = Path.Combine(home, "run", "staging");
            var staged = Directory.GetFiles(stagingDir, "vault.json.*");
            Assert.NotEmpty(staged);
            Assert.DoesNotContain("elev-pw-9", File.ReadAllText(staged[0]));
        }
        finally
        {
            Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null);
            File.SetUnixFileMode(Path.Combine(home, "vault.json"), UnixFileMode.UserRead | UnixFileMode.UserWrite);
            DeleteHome(home);
        }
    }

    [Fact]
    public void Doctor_CleansStagingLeftover()
    {
        if (!Unix) return;
        var home = NewHome("stale");
        try
        {
            var stagingDir = Path.Combine(home, "run", "staging");
            Directory.CreateDirectory(stagingDir);
            File.WriteAllText(Path.Combine(stagingDir, "vault.json.deadbeef"), "{\"version\":1,\"entries\":[]}");

            var (exit, stdout, _) = F.RunIn(home, null, "doctor");
            Assert.Equal(0, exit);
            Assert.Contains("中断残留", stdout);
            Assert.Contains("1", stdout);
            Assert.Empty(Directory.GetFiles(stagingDir));
        }
        finally { DeleteHome(home); }
    }

    [Fact]
    public void Doctor_RepairsInterruptedProtection()
    {
        if (!Mac) return; // 用户级自动补齐仅 macOS
        var home = NewHome("half");
        try
        {
            // 只保护 vault.json（模拟"清保护 → 覆盖 → 重新加保护"之间被打断）
            Hardening.SetImmutable(Path.Combine(home, "vault.json"));
            Assert.Equal(Hardening.Level.Interrupted, Hardening.GetLevel(home));

            var (exit, stdout, _) = F.RunIn(home, null, "doctor");
            Assert.Equal(0, exit);
            Assert.Contains("中断的加固", stdout);
            Assert.Contains("已自动补齐", stdout);
            Assert.True(Hardening.IsImmutable(Path.Combine(home, "master.key")), "doctor 应补齐缺失的保护");
            Assert.True(Hardening.IsImmutable(Path.Combine(home, "vault.json")));
        }
        finally { DeleteHome(home); }
    }

    [Fact]
    public void Doctor_ReportsHardenedLevel()
    {
        if (!Mac) return;
        var home = NewHome("lvl");
        try
        {
            foreach (var f in Hardening.CoreFiles) Hardening.SetImmutable(Path.Combine(home, f));
            var (exit, stdout, _) = F.RunIn(home, null, "doctor");
            Assert.Equal(0, exit);
            Assert.Contains("已加固", stdout);
            Assert.Contains("uchg", stdout);
        }
        finally { DeleteHome(home); }
    }

    [Fact]
    public void InstallStagedCmd_EndToEnd_UserImmutable()
    {
        if (!Mac) return;
        var home = NewHome("istage");
        try
        {
            var vaultPath = Path.Combine(home, "vault.json");
            var backup = File.ReadAllBytes(vaultPath);
            Hardening.SetImmutable(vaultPath);

            var stagingDir = Path.Combine(home, "run", "staging");
            Directory.CreateDirectory(stagingDir);
            var staged = Path.Combine(stagingDir, "vault.json." + Guid.NewGuid().ToString("N"));
            File.WriteAllBytes(staged, "{\"version\":1,\"entries\":[]}"u8.ToArray());

            // 内部搬运命令：清保护 → 原子覆盖 → 重新加保护（即 sudo 子进程执行的逻辑）
            var (exit, _, stderr) = F.RunIn(home, null, "_install-staged", staged, vaultPath);
            Assert.Equal(0, exit);
            Assert.Equal("{\"version\":1,\"entries\":[]}"u8.ToArray(), File.ReadAllBytes(vaultPath));
            Assert.True(Hardening.IsImmutable(vaultPath), "安装后必须重新加保护");
        }
        finally
        {
            DeleteHome(home); // 内部先 ClearImmutable 再删目录
        }
    }

    [Fact]
    public void InstallStagedCmd_RejectsPathsOutsideVault()
    {
        if (!Unix) return;
        var home = NewHome("guard");
        try
        {
            var evilStaging = Path.GetTempFileName();
            var (exit, _, stderr) = F.RunIn(home, null, "_install-staged", evilStaging, Path.Combine(home, "vault.json"));
            Assert.Equal(ExitCodes.Usage, exit);
            Assert.Contains("安全限制", stderr);

            var (exit2, _, _) = F.RunIn(home, null, "_install-staged",
                Path.Combine(home, "run", "staging", "vault.json.x"), Path.GetTempFileName());
            Assert.Equal(ExitCodes.Usage, exit2);
        }
        finally { DeleteHome(home); }
    }

}
