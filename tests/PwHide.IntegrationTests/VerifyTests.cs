using System.Text;
using PwHide.Cli;
using PwHide.Core;
using Xunit;

namespace PwHide.IntegrationTests;

/// <summary>
/// --verify 人类验证通道测试。
/// 契约：非交互/重定向环境硬拒绝（密文绝不进管道/AI 上下文）；真实终端（钩子模拟）下强制手输主口令
/// （忽略 env/钥匙串），inspect 解密显示、exec 执行前确认（拒绝则不执行），执行输出脱敏照常。
/// </summary>
[Collection("sequential")]
public class VerifyTests : IDisposable
{
    private static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();
    private readonly CliFixture F;
    public VerifyTests(CliFixture f) => F = f;
    public void Dispose() => Commands.HookIsHumanTerminal = null;

    /// <summary>交互式运行（钩子模拟真实终端）+ 可选错误口令 env（证明 --verify 忽略 env）。</summary>
    private (int Exit, string Stdout, string Stderr) TerminalRun(string? stdin, string? envPass, params string[] args)
    {
        Commands.HookIsHumanTerminal = () => true;
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", envPass);
        try
        {
            using var stdout = new MemoryStream();
            using var stderr = new MemoryStream();
            using var stdinReader = new StringReader(stdin ?? "");
            var exit = CliRunner.Run(new[] { "--home", F.Home }.Concat(args).ToArray(), stdout, stderr, stdinReader, interactive: true);
            var enc = new UTF8Encoding(false);
            return (exit, enc.GetString(stdout.ToArray()), enc.GetString(stderr.ToArray()));
        }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    [Fact]
    public void Verify_NonInteractive_HardRefused()
    {
        // AI/脚本环境加 --verify 想读密码：必须硬拒绝（这是通道存在的前提）
        var (iexit, _, ierr) = F.Run("inspect", "db", "--verify");
        Assert.Equal(ExitCodes.Usage, iexit);
        Assert.Contains("硬性限制", ierr);

        var (eexit, _, eerr) = F.Run("exec", "--verify", "--", "/bin/echo", "{{db}}");
        Assert.Equal(ExitCodes.Usage, eexit);
        Assert.Contains("硬性限制", eerr);
    }

    [Fact]
    public void Verify_RedirectedStdout_Refused()
    {
        // stdout 被管道接走（重定向到文件/tee/AI 采集）也不行——即使 stdin 是终端
        Commands.HookIsHumanTerminal = null;
        using var stdout = new MemoryStream();   // CliRunner 显式传流 = stdout 重定向语义
        using var stderr = new MemoryStream();
        var exit = CliRunner.Run(new[] { "--home", F.Home, "inspect", "db", "--verify" },
            stdout, stderr, new StringReader("init-pass-123\n"), interactive: true);
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("硬性限制", new UTF8Encoding(false).GetString(stderr.ToArray()));
    }

    [Fact]
    public void InspectVerify_ForcesPrompt_IgnoresEnvPassphrase()
    {
        if (!Unix) return;
        // env 放错误口令、stdin 手输正确口令：成功 → 证明 --verify 用的是手输而非 env/钥匙串
        var (exit, stdout, _) = TerminalRun("init-pass-123\n", "totally-wrong-pass", "inspect", "db", "--verify");
        Assert.Equal(0, exit);
        Assert.Contains(CliFixture.DbPassword, stdout);
        Assert.Contains("root", stdout);            // 账号一并显示
        Assert.Contains("[--verify 解密显示", stdout);
    }

    [Fact]
    public void InspectVerify_WrongPassphrase_VaultError()
    {
        var (exit, _, _) = TerminalRun("totally-wrong-pass\n", null, "inspect", "db", "--verify");
        Assert.Equal(ExitCodes.Vault, exit);
    }

    [Fact]
    public void InspectVerify_WithJson_Rejected()
    {
        var (exit, _, stderr) = TerminalRun(null, null, "inspect", "db", "--verify", "--json");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("不能同时使用", stderr);
    }

    [Fact]
    public void ExecVerify_ShowsDecrypted_ConfirmRuns_RedactionStillOn()
    {
        if (!Unix) return;
        // 展示解密值 → 确认 y → 执行；输出侧脱敏照常（通道只影响"执行前的显示"，不影响 I3）
        var (exit, stdout, stderr) = TerminalRun("init-pass-123\ny\n", "totally-wrong-pass",
            "exec", "--allow-echo", "--verify", "--", "/bin/echo", "{{db}}");
        Assert.Equal(0, exit);
        Assert.Contains(CliFixture.DbPassword, stdout);   // 核对区展示真实密码
        Assert.Contains("确认执行", stderr);                // 确认提问在 stderr
        Assert.EndsWith("{{db}}\n", stdout);              // 末行为子进程输出（已脱敏回占位符）
    }

    [Fact]
    public void ExecVerify_Declined_DoesNotExecute()
    {
        if (!Unix) return;
        var marker = Path.Combine(Path.GetTempPath(), "pwhide-verify-" + Guid.NewGuid().ToString("N"));
        try
        {
            var (exit, stdout, stderr) = TerminalRun("init-pass-123\nn\n", null,
                "exec", "--verify", "--", "/bin/sh", "-c", $"echo x > {marker}");
            Assert.Equal(ExitCodes.Usage, exit);
            Assert.Contains("已取消", stderr);
            Assert.False(File.Exists(marker));            // 拒绝确认 → 子进程绝不启动
        }
        finally { try { File.Delete(marker); } catch { } }
    }

    [Fact]
    public void ExecVerify_ScriptMode_PreviewAndConfirm()
    {
        if (!Unix) return;
        var script = Path.Combine(Path.GetTempPath(), "pwhide-verify-s-" + Guid.NewGuid().ToString("N") + ".sh");
        File.WriteAllText(script, "#!/bin/sh\necho pw={{db}}\n");
        try
        {
            var (exit, stdout, _) = TerminalRun("init-pass-123\ny\n", null,
                "exec", "--allow-echo", "--verify", "-f", script, "--shell", "sh");
            Assert.Equal(0, exit);
            Assert.Contains("echo pw=" + CliFixture.DbPassword, stdout);   // 预览区显示解析后脚本
            Assert.EndsWith("pw={{db}}\n", stdout);                        // 实际输出脱敏
        }
        finally { try { File.Delete(script); } catch { } }
    }
}
