using System.Text;
using PwHide.Cli;
using PwHide.Core;
using Xunit;

namespace PwHide.IntegrationTests;

/// <summary>
/// 明文字段（-pf / 交互式自选不加密）与录入 Trim 行为测试。
/// 明文字段语义：值在 list --json 元数据可见（AI 免解锁组装命令）；占位符照常填充；不参与脱敏、不触发解锁与回显探测。
/// </summary>
[Collection("sequential")]
public class PlainFieldTests
{
    private static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();
    private readonly CliFixture F;
    public PlainFieldTests(CliFixture f) => F = f;

    private string TempHome()
    {
        var h = Path.Combine(Path.GetTempPath(), "pwhide-pf-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(h);
        return h;
    }

    private const string Pass = "pf-init-pass-99";

    /// <summary>带主口令 env 的运行（需要解锁的操作用）；stdin 供 --password-stdin/交互读取。</summary>
    private (int Exit, string Stdout, string Stderr) Env(string home, string? stdin, params string[] args)
    {
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", Pass);
        try { return F.RunIn(home, stdin, args); }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    /// <summary>交互式运行（interactive:true 才会触发字段加密询问）；带口令 env 免主口令提示。</summary>
    private (int Exit, string Stdout, string Stderr) EnvInteractive(string home, string? stdin, params string[] args)
    {
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", Pass);
        try
        {
            using var stdout = new MemoryStream();
            using var stderr = new MemoryStream();
            using var stdinReader = new StringReader(stdin ?? "");
            var exit = CliRunner.Run(new[] { "--home", home }.Concat(args).ToArray(), stdout, stderr, stdinReader, interactive: true);
            var enc = new UTF8Encoding(false);
            return (exit, enc.GetString(stdout.ToArray()), enc.GetString(stderr.ToArray()));
        }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    private int Init(string home)
    {
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", Pass);
        try { return F.RunIn(home, null, "init", "--no-harden").Exit; }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    [Fact]
    public void PlainField_VisibleInListJson_EncryptedStillHidden()
    {
        var home = TempHome();
        try
        {
            Assert.Equal(0, Init(home));
            // 非交互：-f 恒加密（现状不变）、-pf 显式明文
            var (exit, _, _) = Env(home, "svc-pw-77\n", "set", "svc", "-u", "root",
                "-pf", "host=10.0.0.8", "-pf", "proto=https", "-f", "api_key=ak-secret-9",
                "--password-stdin");
            Assert.Equal(0, exit);

            var (lexit, stdout, _) = F.RunIn(home, null, "list", "--json");
            Assert.Equal(0, lexit);
            Assert.Contains("\"host\": \"10.0.0.8\"", stdout);
            Assert.Contains("\"proto\": \"https\"", stdout);
            Assert.DoesNotContain("ak-secret-9", stdout);   // 加密字段值仍不可见
            Assert.Contains("{{svc.host}}", stdout);        // 明文字段也有占位符
            Assert.Contains("{{svc.api_key}}", stdout);
        }
        finally { try { Directory.Delete(home, true); } catch { } }
    }

    [Fact]
    public void PlainField_ExecFillsWithoutUnlock()
    {
        if (!Unix) return;
        var home = TempHome();
        try
        {
            Assert.Equal(0, Init(home));
            Assert.Equal(0, Env(home, "svc-pw-77\n", "set", "svc", "-pf", "host=10.0.0.8", "--password-stdin").Exit);

            // 无口令来源（无 env/文件/钥匙串）+ 非交互：仅引用明文字段 → 不需要解锁，直接执行
            var (exit, stdout, _) = F.RunIn(home, null, "exec", "--", "/bin/echo", "host={{svc.host}}");
            Assert.Equal(0, exit);
            Assert.Equal("host=10.0.0.8\n", stdout);

            // 明文字段不算密文：echo 回显不触发探测拦截
            var (exit2, stdout2, _) = F.RunIn(home, null, "exec", "--", "/bin/echo", "{{svc.host}}");
            Assert.Equal(0, exit2);
            Assert.Equal("10.0.0.8\n", stdout2);
        }
        finally { try { Directory.Delete(home, true); } catch { } }
    }

    [Fact]
    public void PlainField_MixedWithSecret_StillRedactsSecret()
    {
        if (!Unix) return;
        var home = TempHome();
        try
        {
            Assert.Equal(0, Init(home));
            Assert.Equal(0, Env(home, "svc-pw-77\n", "set", "svc", "-pf", "host=10.0.0.8", "--password-stdin").Exit);

            // 密码 + 明文字段混用：仍需解锁；密码脱敏、明文字段原样
            var (exit, stdout, _) = Env(home, null, "exec", "--allow-echo", "--",
                "/bin/sh", "-c", "echo {{svc.host}} {{svc}}");
            Assert.Equal(0, exit);
            Assert.Equal("10.0.0.8 {{svc}}\n", stdout);
        }
        finally { try { Directory.Delete(home, true); } catch { } }
    }

    [Fact]
    public void Set_InteractiveAsk_FieldEncryption()
    {
        var home = TempHome();
        try
        {
            Assert.Equal(0, Init(home));
            // 交互式 set：行序 = 密码(stdin)、host 值、n(明文)、note 值、y(加密)、api_key 值、回车(敏感名默认加密)
            var (exit, _, stderr) = EnvInteractive(home,
                "svc-pw-77\n1.2.3.4\nn\njust-a-note\ny\nraw-token-x\n\n",
                "set", "svc", "-f", "host", "-f", "note", "-f", "api_key", "--password-stdin");
            Assert.Equal(0, exit);
            Assert.Contains("是否敏感、需要加密存储", stderr);

            var (_, stdout, _) = F.RunIn(home, null, "list", "--json");
            Assert.Contains("\"host\": \"1.2.3.4\"", stdout);   // n → 明文，值可见
            Assert.DoesNotContain("just-a-note", stdout);      // y → 加密，值不可见
            Assert.DoesNotContain("raw-token-x", stdout);      // 回车（敏感默认）→ 加密
        }
        finally { try { Directory.Delete(home, true); } catch { } }
    }

    [Fact]
    public void Set_DuplicateFieldName_Rejected()
    {
        var home = TempHome();
        try
        {
            Assert.Equal(0, Init(home));
            var (exit, _, stderr) = Env(home, "svc-pw-77\n", "set", "svc",
                "-f", "host=a", "-pf", "host=b", "--password-stdin");
            Assert.Equal(ExitCodes.Usage, exit);
            Assert.Contains("不能重复", stderr);
        }
        finally { try { Directory.Delete(home, true); } catch { } }
    }

    [Fact]
    public void Set_PasswordTrimmed()
    {
        if (!Unix) return;
        var home = TempHome();
        try
        {
            Assert.Equal(0, Init(home));
            // 首尾带空白（模拟粘贴/文件尾换行）：入库前清除
            var (exit, _, _) = Env(home, "  spaced-pw-77  \n", "set", "svc", "--password-stdin");
            Assert.Equal(0, exit);

            // 注入的是去空格后的值：echo 出来被精确脱敏（若未 Trim，输出会带空格或泄露原值）
            var (exit2, stdout2, _) = Env(home, null, "exec", "--allow-echo", "--", "/bin/echo", "{{svc}}");
            Assert.Equal(0, exit2);
            Assert.Equal("{{svc}}\n", stdout2);
        }
        finally { try { Directory.Delete(home, true); } catch { } }
    }

    [Fact]
    public void Set_FieldValueTrimmed()
    {
        var home = TempHome();
        try
        {
            Assert.Equal(0, Init(home));
            var (exit, _, _) = Env(home, "svc-pw-77\n", "set", "svc", "-pf", "host=  10.0.0.9\t", "--password-stdin");
            Assert.Equal(0, exit);
            var (_, stdout, _) = F.RunIn(home, null, "list", "--json");
            Assert.Contains("\"host\": \"10.0.0.9\"", stdout);
        }
        finally { try { Directory.Delete(home, true); } catch { } }
    }
}
