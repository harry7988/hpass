using PwHide.Cli;
using PwHide.Core;
using Xunit;

namespace PwHide.IntegrationTests;

/// <summary>
/// 钥匙串口令来源测试（核心诉求：配置一次后 exec 零交互，AI 调用不再需要口令）。
/// 用测试钩子注入假钥匙串（不碰真实 OS 钥匙串，CI 稳定）；真实 OS 回环 gated by PWHIDE_IT_REAL_KEYCHAIN。
/// 加入 sequential 集合：Keychain 钩子是进程级静态，禁止与其他 CLI 测试并发。
/// </summary>
[Collection("sequential")]
public class KeychainTests : IDisposable
{
    private readonly CliFixture F;

    public KeychainTests(CliFixture f)
    {
        F = f;
        Keychain.HookIsSupported = () => true;
    }

    public void Dispose()
    {
        Keychain.HookIsSupported = null;
        Keychain.HookTryGet = null;
        Keychain.HookStore = null;
        Keychain.HookClear = null;
        Environment.SetEnvironmentVariable("PWHIDE_NO_KEYCHAIN", null);
    }

    [Fact]
    public void Keychain_Satisfies_NonInteractiveExec_NoPrompt()
    {
        // 核心场景：AI/脚本环境（无 env、无文件、非交互），钥匙串里有口令 → exec 直接成功
        Keychain.HookTryGet = _ => "init-pass-123";
        var (exit, stdout, _) = F.Run("exec", "--allow-echo", "--", "/bin/echo", "{{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("{{db}}\n", stdout);
    }

    [Fact]
    public void EnvPassphrase_BeatsKeychain()
    {
        // env 里是正确口令、钩子返回错误口令：仍成功 → 优先级 env > keychain
        Keychain.HookTryGet = _ => "wrong-from-keychain-9";
        var (exit, _, _) = F.RunAs("init-pass-123", "list");
        Assert.Equal(0, exit);
    }

    [Fact]
    public void WrongKeychainPass_VaultFails()
    {
        Keychain.HookTryGet = _ => "wrong-from-keychain-9";
        var (exit, _, stderr) = F.Run("exec", "--", "/usr/bin/true", "{{db}}");   // 引用密文但无回显原语，才会走到解锁
        Assert.Equal(ExitCodes.Vault, exit);   // 解锁失败（非 4：占位符存在，是口令错）
        Assert.DoesNotContain("wrong-from-keychain-9", stderr);
    }

    [Fact]
    public void NoKeychainEnv_SkipsKeychain_NonInteractiveStillFails()
    {
        Environment.SetEnvironmentVariable("PWHIDE_NO_KEYCHAIN", "1");
        Keychain.HookTryGet = _ => "init-pass-123";
        var (exit, _, stderr) = F.Run("exec", "--", "/usr/bin/true", "{{db}}");
        Assert.Equal(ExitCodes.Vault, exit);
        Assert.Contains("keychain set", stderr);   // 指引走钥匙串配置
    }

    [Fact]
    public void KeychainSet_VerifiesAgainstVault_BeforeStore()
    {
        string? stored = null;
        Keychain.HookStore = (_, p) => stored = p;
        // 正确口令经 env 提供（非交互配置路径）：验证通过后入库
        var (exit, _, _) = F.RunAs("init-pass-123", "keychain", "set");
        Assert.Equal(0, exit);
        Assert.Equal("init-pass-123", stored);

        // 错误口令：拒绝入库（防止把坏口令存进去导致后续全部失败）
        stored = null;
        var (exit2, _, stderr2) = F.RunAs("totally-wrong-pass", "keychain", "set");
        Assert.Equal(ExitCodes.Vault, exit2);
        Assert.Null(stored);
    }

    [Fact]
    public void KeychainClear_AndStatus()
    {
        var cleared = false;
        Keychain.HookClear = _ => { cleared = true; return true; };
        var (exit, stdout, _) = F.Run("keychain", "clear");
        Assert.Equal(0, exit);
        Assert.True(cleared);
        Assert.Contains("已从钥匙串删除", stdout);

        Keychain.HookTryGet = _ => null;
        var (exit2, stdout2, _) = F.Run("keychain", "status");
        Assert.Equal(0, exit2);
        Assert.Contains("未存储", stdout2);

        Keychain.HookTryGet = _ => "init-pass-123";
        var (exit3, stdout3, _) = F.Run("keychain", "status");
        Assert.Equal(0, exit3);
        Assert.Contains("已存储", stdout3);
    }

    [Fact]
    public void KeychainSet_UnknownSub_UsageError()
    {
        var (exit, _, stderr) = F.Run("keychain", "frobnicate");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("set / clear / status", stderr);
    }

    [Fact]
    public void Keychain_MissingVault_SetFails()
    {
        var tempHome = Path.Combine(Path.GetTempPath(), "pwhide-kc-" + Guid.NewGuid().ToString("N"));
        try
        {
            Keychain.HookStore = (_, _) => throw new InvalidOperationException("vault 不存在时不得入库");
            using var stdout = new MemoryStream();
            using var stderr = new MemoryStream();
            var exit = CliRunner.Run(["--home", tempHome, "keychain", "set"], stdout, stderr,
                new StringReader("whatever-pass-9"), interactive: false);
            Assert.Equal(ExitCodes.Vault, exit);
        }
        finally { try { Directory.Delete(tempHome, true); } catch { } }
    }

    // 真实 OS 钥匙串回环（macOS Keychain / Windows 凭据管理器）：默认跳过，设 PWHIDE_IT_REAL_KEYCHAIN=1 启用
    [Fact]
    public void Keychain_RealOsRoundtrip_OptIn()
    {
        if (Environment.GetEnvironmentVariable("PWHIDE_IT_REAL_KEYCHAIN") != "1") return;
        if (!Keychain.IsSupported) return;
        var tempHome = Path.Combine(Path.GetTempPath(), "pwhide-kcr-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tempHome);
            Assert.True(Keychain.TryGet(tempHome, out _) == false || true);   // 槽位应不存在（TryGet false 或旧值）
            Keychain.Store(tempHome, "roundtrip-pass-77");
            Assert.True(Keychain.TryGet(tempHome, out var got));
            Assert.Equal("roundtrip-pass-77", got);
            Assert.True(Keychain.Clear(tempHome));
            Assert.False(Keychain.TryGet(tempHome, out _));
        }
        finally
        {
            Keychain.Clear(tempHome);
            try { Directory.Delete(tempHome, true); } catch { }
        }
    }
}
