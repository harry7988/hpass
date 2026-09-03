using System.Text;
using PwHide.Cli;
using PwHide.Core;
using Xunit;

namespace PwHide.IntegrationTests;

/// <summary>
/// 每命令帮助（-h/--help、help &lt;cmd&gt;）与使用步骤引导测试。
/// 契约：所有公开命令 -h 退出码 0 且无 CJK（en 默认）；exec 在 -- 之后不拦截
/// （子命令自己的 --help 透传）；init/set 成功输出含下一步引导。
/// </summary>
[Collection("sequential")]
public class HelpTests
{
    private readonly CliFixture F;
    private readonly string? _prevLang;
    public HelpTests(CliFixture f)
    {
        F = f;
        _prevLang = Environment.GetEnvironmentVariable("PWHIDE_LANG");
    }

    /// <summary>en 断言用：临时切 en（fixture 默认钉 zh），退出恢复。</summary>
    private (int Exit, string Stdout, string Stderr) RunEn(params string[] args)
    {
        Environment.SetEnvironmentVariable("PWHIDE_LANG", "en");
        try { return F.Run(args); }
        finally { Environment.SetEnvironmentVariable("PWHIDE_LANG", _prevLang); }
    }

    private static string[] AllPublic = ["init", "set", "list", "inspect", "delete", "rename",
        "exec", "verify", "rotate", "harden", "doctor", "keychain", "language", "version"];

    [Fact]
    public void EveryCommand_H_Exit0_NoCjk()
    {
        foreach (var cmd in AllPublic)
        {
            // init/verify 等带交互的命令：-h 在任何业务逻辑之前拦截，无需口令/终端
            var (exit, stdout, stderr) = RunEn(cmd, "-h");
            Assert.True(exit == 0, $"{cmd} -h 应退出 0，实际 {exit}：{stderr}");
            Assert.False(Loc.ContainsCjk(stdout + stderr), $"{cmd} -h en 模式输出含中文");
            if (cmd != "version") Assert.Contains("usage", stdout + stderr);
        }
    }

    [Fact]
    public void EveryCommand_HelpFlag_DoubleDash()
    {
        foreach (var cmd in AllPublic)
        {
            var (exit, stdout, _) = RunEn(cmd, "--help");
            Assert.True(exit == 0, $"{cmd} --help 应退出 0");
            Assert.False(Loc.ContainsCjk(stdout), $"{cmd} --help en 模式输出含中文");
        }
    }

    [Fact]
    public void HelpCommand_ShowsPerCommandHelp()
    {
        foreach (var cmd in new[] { "exec", "set", "doctor", "keychain" })
        {
            var (exit, stdout, stderr) = RunEn("help", cmd);
            Assert.Equal(0, exit);
            Assert.False(Loc.ContainsCjk(stdout + stderr));
        }
        var (_, out2, _) = F.Run("help", "exec");
        Assert.Contains("{{name.user}}", out2);   // exec 帮助含占位符语法
    }

    [Fact]
    public void Exec_DashDash_PassesHelpThroughToChild()
    {
        if (!(OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())) return;
        // exec -- echo --help：--help 属于子命令，pwhide 不拦截
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--", "/bin/echo", "--help");
        Assert.Equal(0, exit);
        Assert.Equal("--help\n", stdout);
    }

    [Fact]
    public void Init_AndSet_PrintNextStepHints()
    {
        var home = Path.Combine(Path.GetTempPath(), "pwhide-hint-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "hint-pass-99");
            try
            {
                var (iexit, istdout, _) = F.RunIn(home, "hint-pass-99\nhint-pass-99\n", "init", "--no-harden");
                Assert.Equal(0, iexit);
                Assert.Contains("下一步", istdout);   // fixture 钉 zh；引导行在 stdout
                Assert.Contains("keychain set", istdout);

                var (sexit, sstdout, _) = F.RunIn(home, "hint-pw-77\n", "set", "svc", "--password-stdin");
                Assert.Equal(0, sexit);
                Assert.Contains("下一步：pwhide inspect svc", sstdout);   // 引导行在 stdout
                Assert.Contains("{{svc}}", sstdout);
            }
            finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
        }
        finally { try { Directory.Delete(home, true); } catch { } }
    }

    [Fact]
    public void Doctor_ShowsLanguageAndKeychainLines()
    {
        var (exit, stdout, stderr) = F.Run("doctor");   // fixture home：vault 已初始化 → exit 0
        Assert.Equal(0, exit);
        var text = stdout + stderr;                      // fixture zh：中文诊断行
        Assert.Contains("语言", text);
        Assert.Contains("钥匙串", text);
    }
}
