using System.Text;
using PwHide.Cli;
using PwHide.Core;
using Xunit;

namespace PwHide.IntegrationTests;

/// <summary>
/// 语言本地化测试：默认英文、zh 切换、持久化、来源优先级，以及"en 模式输出无 CJK"的翻译完整性电池。
/// 注意：本类不依赖 CliFixture（fixture 会钉死 zh），用独立 home + 显式清理 PWHIDE_LANG。
/// </summary>
[Collection("sequential")]
public class LanguageTests : IDisposable
{
    private static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();
    private readonly string _home = Path.Combine(Path.GetTempPath(), "pwhide-lang-" + Guid.NewGuid().ToString("N"));

    private readonly string? _prevLang;

    public LanguageTests()
    {
        _prevLang = Environment.GetEnvironmentVariable("PWHIDE_LANG");   // 同集合后续类依赖 fixture 的 zh：退出时恢复
        Environment.SetEnvironmentVariable("PWHIDE_LANG", null);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("PWHIDE_LANG", _prevLang);
        try { Directory.Delete(_home, true); } catch { }
    }

    private (int Exit, string Stdout, string Stderr) Run(params string[] args)
    {
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var exit = CliRunner.Run(new[] { "--home", _home }.Concat(args).ToArray(), stdout, stderr, new StringReader(""), interactive: false);
        var enc = new UTF8Encoding(false);
        return (exit, enc.GetString(stdout.ToArray()), enc.GetString(stderr.ToArray()));
    }

    private static void AssertNoCjk(params string[] texts)
    {
        foreach (var t in texts)
            Assert.False(Loc.ContainsCjk(t), $"en 模式输出仍含中文：{t}");
    }

    [Fact]
    public void Default_Is_English()
    {
        var (exit, stdout, _) = Run("version");
        Assert.Equal(0, exit);
        Assert.StartsWith("pwhide ", stdout);
        AssertNoCjk(stdout);
    }

    [Fact]
    public void DefaultEnglish_NoVaultError_InEnglish()
    {
        var (exit, _, stderr) = Run("list");
        Assert.Equal(ExitCodes.Vault, exit);
        Assert.Contains("vault not found", stderr);
        Assert.Contains("pwhide init", stderr);
        AssertNoCjk(stderr);
    }

    [Fact]
    public void DefaultEnglish_UsageBlock_Translated()
    {
        var (_, _, stderr) = Run("help");   // usage 块输出在 stderr；"usage:" 行仅在错误路径出现
        Assert.Contains("local password proxy executor", stderr);
        Assert.Contains("exec options:", stderr);
        AssertNoCjk(stderr);
    }

    [Fact]
    public void DefaultEnglish_UnknownCommand_InEnglish()
    {
        var (exit, _, stderr) = Run("frobnicate");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("unknown command:", stderr);
    }

    [Fact]
    public void DefaultEnglish_KeychainStatusUnsupportedPlatform_NoCjk()
    {
        // 模拟 Linux 无 secret-tool / 任意"不可用"平台：Describe 输出必须已双语（CI 三平台的差异面）
        var prev = Keychain.HookIsSupported;
        Keychain.HookIsSupported = () => false;
        try
        {
            var (_, stdout, _) = Run("keychain", "status");
            AssertNoCjk(stdout);
        }
        finally { Keychain.HookIsSupported = prev; }
    }

    [Fact]
    public void DefaultEnglish_DoctorAndKeychainStatus_NoCjk()
    {
        var (_, stdout, _) = Run("doctor");
        Assert.Contains("output encoding :", stdout);
        AssertNoCjk(stdout);
        var (_, stdout2, _) = Run("keychain", "status");
        AssertNoCjk(stdout2);
    }

    [Fact]
    public void DefaultEnglish_ExecUsageAndUnknownOption_InEnglish()
    {
        var (e1, _, s1) = Run("exec");
        Assert.Equal(ExitCodes.Usage, e1);
        Assert.Contains("missing command", s1);
        AssertNoCjk(s1);
        var (e2, _, s2) = Run("exec", "--bogus", "--", "x");
        Assert.Equal(ExitCodes.Usage, e2);
        Assert.Contains("unknown pwhide option", s2);
        AssertNoCjk(s2);
    }

    [Fact]
    public void LanguageCmd_SwitchesToZh_Persists_AppliesToNextCommand()
    {
        var (setExit, stdout, _) = Run("language", "zh");
        Assert.Equal(0, setExit);
        Assert.StartsWith("语言已切换为 zh", stdout);
        Assert.Equal("zh", File.ReadAllText(Path.Combine(_home, "language")).Trim());

        // 不设环境变量：文件生效，下一条命令即中文
        var (_, _, stderr) = Run("list");
        Assert.Contains("未找到 vault", stderr);
    }

    [Fact]
    public void LanguageCmd_BackToEn()
    {
        Run("language", "zh");
        var (exit, stdout, _) = Run("language", "en");
        Assert.Equal(0, exit);
        Assert.StartsWith("language set to en", stdout);
        var (_, _, stderr) = Run("list");
        Assert.Contains("vault not found", stderr);
    }

    [Fact]
    public void LanguageCmd_Invalid_UsageError()
    {
        var (exit, _, stderr) = Run("language", "fr");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("unknown language", stderr);
    }

    [Fact]
    public void LanguageStatus_ShowsCurrentAndSource()
    {
        var (exit, stdout, _) = Run("language");
        Assert.Equal(0, exit);
        Assert.Contains("language : en (source: default en)", stdout);
    }

    [Fact]
    public void EnvLang_BeatsFile()
    {
        Run("language", "zh");
        Environment.SetEnvironmentVariable("PWHIDE_LANG", "en");
        var (_, _, stderr) = Run("list");
        Assert.Contains("vault not found", stderr);   // env en 覆盖文件 zh
    }

    [Fact]
    public void EnMode_SetAndExecFlow_NoCjk()
    {
        if (!Unix) return;
        // 完整流：init（stdin 口令）→ set（密码/字段）→ list --json → exec 脱敏输出，全程 en 无中文
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "lang-pass-99");
        var exit = CliRunner.Run(
            ["--home", _home, "init", "--no-harden"], stdout, stderr, new StringReader("lang-pass-99\nlang-pass-99\n"), interactive: true);
        Assert.Equal(0, exit);
        AssertNoCjk(Encoding.UTF8.GetString(stderr.ToArray()));
        // PWHIDE_PASSPHRASE 在方法尾 finally 清理

        using var stdout2 = new MemoryStream();
        using var stderr2 = new MemoryStream();
        exit = CliRunner.Run(["--home", _home, "set", "svc", "-u", "root", "-pf", "host=10.0.0.1", "--password-stdin"],
            stdout2, stderr2, new StringReader("svc-pw-77\n"), interactive: false);
        Assert.Equal(0, exit);
        Assert.Contains("saved entry svc", Encoding.UTF8.GetString(stdout2.ToArray()));
        AssertNoCjk(Encoding.UTF8.GetString(stdout2.ToArray()), Encoding.UTF8.GetString(stderr2.ToArray()));

        var (lexit, lstdout, _) = Run("list", "--json");
        Assert.Equal(0, lexit);
        AssertNoCjk(lstdout);

        try
        {
            var (eexit, estdout, _) = Run("exec", "--allow-echo", "--", "/bin/echo", "{{svc}}");
            Assert.Equal(0, eexit);
            Assert.Equal("{{svc}}\n", estdout);
        }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    [Fact]
    public void EnMode_InspectTextMode_NoCjk()
    {
        if (!Unix) return;
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "lang-pass-99");
        try
        {
            Assert.Equal(0, Run("init", "--no-harden").Exit);
            Assert.Equal(0, RunStdin("svc-pw-77\n", "set", "svc", "-u", "root", "-pf", "host=1.2.3.4", "--password-stdin").Exit);
            var (exit, stdout, _) = Run("inspect", "svc");
            Assert.Equal(0, exit);
            Assert.Contains("name: svc", stdout);
            Assert.Contains("type:", stdout);
            Assert.Contains("password: set (injected only via {{svc}})", stdout);
            Assert.Contains("plain fields (non-sensitive, visible in metadata): host=1.2.3.4", stdout);
            AssertNoCjk(stdout);
        }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    [Fact]
    public void EnMode_UnknownPlaceholder_InEnglish()
    {
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "lang-pass-99");
        try
        {
            Assert.Equal(0, Run("init", "--no-harden").Exit);
            var (exit, _, stderr) = Run("exec", "--", "/bin/true", "{{svc.nope}}");
            Assert.Equal(ExitCodes.UnknownPlaceholder, exit);
            Assert.Contains("unknown placeholder", stderr);
            AssertNoCjk(stderr);
        }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    [Fact]
    public void EnMode_WeakPasswordRefusal_InEnglish()
    {
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "lang-pass-99");
        try
        {
            Assert.Equal(0, Run("init", "--no-harden").Exit);
            var (exit, _, stderr) = RunStdin("12345678\n", "set", "svc", "--password-stdin");
            Assert.Equal(ExitCodes.Usage, exit);
            Assert.Contains("refusing weak password", stderr);
            AssertNoCjk(stderr);
        }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    private (int Exit, string Stdout, string Stderr) RunStdin(string? stdin, params string[] args)
    {
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var exit = CliRunner.Run(new[] { "--home", _home }.Concat(args).ToArray(), stdout, stderr, new StringReader(stdin ?? ""), interactive: false);
        var enc = new UTF8Encoding(false);
        return (exit, enc.GetString(stdout.ToArray()), enc.GetString(stderr.ToArray()));
    }

    // ---------- Loc 单元行为 ----------

    [Fact]
    public void Tr_ExactAndWildcard()
    {
        Loc.SetLang("en");
        try
        {
            Assert.Equal("entry not found: db", Loc.Tr("条目不存在：db"));
            Assert.Equal("zh-only passthrough", Loc.Tr("zh-only passthrough"));   // 无 CJK 直通
            Loc.SetLang("zh");
            Assert.Equal("条目不存在：db", Loc.Tr("条目不存在：db"));
        }
        finally { Loc.SetLang("en"); }
    }

    [Fact]
    public void Tr_WildcardDynamicPartsPreserved()
    {
        Loc.SetLang("en");
        try
        {
            // 动态段（含密文形态的任意文本）必须原样保留在对应位置
            Assert.Equal("saved entry db (3 entries total)", Loc.Tr("已保存条目 db（3 个条目）"));
            Assert.Equal("pwhide: timed out (5s); process tree killed", Loc.Tr("pwhide: 执行超时（5s），已终止进程树"));
        }
        finally { Loc.SetLang("en"); }
    }
}
