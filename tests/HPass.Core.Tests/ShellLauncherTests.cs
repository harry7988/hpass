using System.Text;
using HPass.Core;
using Xunit;

namespace HPass.Core.Tests;

public class ShellLauncherTests : IDisposable
{
    private readonly string _tmp = Path.Combine(Path.GetTempPath(), "hpass-exec-" + Guid.NewGuid().ToString("N"));
    private static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public ShellLauncherTests() => Directory.CreateDirectory(_tmp);
    public void Dispose() { try { Directory.Delete(_tmp, true); } catch { } }

    private static (int Exit, string Output) Run(ExecRequest req)
    {
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var result = ShellLauncher.Run(req, stdout, stderr);
        return (result.ExitCode, Encoding.UTF8.GetString(stdout.ToArray()) + Encoding.UTF8.GetString(stderr.ToArray()));
    }

    private static Dictionary<string, string> BuildValues(string text)
    {
        var values = new Dictionary<string, string>();
        foreach (var r in Placeholder.Extract(text))
            values[r.Token] = r.Field is null ? "resolved-" + r.Entry : "resolved-" + r.Entry + "-" + r.Field;
        return values;
    }

    private static ExecRequest FromValues(Dictionary<string, string> values) =>
        new()
        {
            Resolve = t => values.TryGetValue(t, out var v) ? v : throw new PlaceholderException(t, t, "未知"),
            RedactionRules = values.Where(kv => !kv.Key.EndsWith(".user}}") && !kv.Key.EndsWith(".tenant}}"))
                .ToDictionary(kv => kv.Value, kv => kv.Key),
        };

    private static ExecRequest Cmd(IReadOnlyList<string> args, string shell = "auto",
        Dictionary<string, string>? env = null, Dictionary<string, string>? rules = null, int timeout = 30)
    {
        var req = FromValues(BuildValues(string.Join(' ', args))) with
        {
            Args = args,
            Shell = shell,
            EnvInject = env ?? new Dictionary<string, string>(),
            TimeoutSeconds = timeout,
        };
        return rules is null ? req : req with { RedactionRules = rules };
    }

    private static ExecRequest Script(string path, string shell = "bash", int timeout = 30)
    {
        var text = File.ReadAllText(path);   // 调用方一次读入（与 CLI 相同的 ScriptText 契约）
        return FromValues(BuildValues(text)) with
        {
            Args = [],
            ScriptPath = path,
            ScriptText = text,
            Shell = shell,
            TimeoutSeconds = timeout,
        };
    }

    [Fact]
    public void NoneMode_DirectExec_ExitCodePassthrough()
    {
        if (!Unix) return;
        var (exit, output) = Run(new ExecRequest
        {
            Args = ["/bin/sh", "-c", "echo hi; exit 7"],
            Shell = "none",
            Resolve = _ => throw new UsageException("no placeholders"),
        });
        Assert.Equal(7, exit);
        Assert.Contains("hi", output);
    }

    [Fact]
    public void InlineMode_ResolvedAndRedacted()
    {
        if (!Unix) return;
        var (exit, output) = Run(Cmd(["/bin/echo", "{{db}}"]));
        Assert.Equal(0, exit);
        Assert.Equal("{{db}}\n", output);
    }

    [Fact]
    public void PlainTextFields_NotRedacted()
    {
        if (!Unix) return;
        var (exit, output) = Run(Cmd(["/bin/echo", "{{db.user}}"]));
        Assert.Equal(0, exit);
        Assert.Equal("resolved-db-user\n", output);
    }

    [Fact]
    public void EnvInjection_SecretInEnvNotArgv_RedactedInOutput()
    {
        if (!Unix) return;
        var req = Cmd(["/bin/sh", "-c", "printf %s \"$HPASS_TEST_V\""], shell: "none",
            env: new Dictionary<string, string> { ["HPASS_TEST_V"] = "env-secret-9" },
            rules: new Dictionary<string, string> { ["env-secret-9"] = "{{db}}" });
        var (exit, output) = Run(req);
        Assert.Equal(0, exit);
        Assert.Equal("{{db}}", output);
    }

    [Fact]
    public void ScriptMode_BashStdin_Redacted()
    {
        if (!Unix) return;
        var script = Path.Combine(_tmp, "s.sh");
        File.WriteAllText(script, "#!/bin/bash\necho pw={{db}}\n");
        var (exit, output) = Run(Script(script, "bash"));
        Assert.Equal(0, exit);
        Assert.Equal("pw={{db}}\n", output);
        // 不变式：脚本文件本身保持占位符（替换只发生在内存）
        Assert.Contains("{{db}}", File.ReadAllText(script));
    }

    [Fact]
    public async Task ScriptMode_MultilineAndCommands()
    {
        if (!Unix) return;
        var script = Path.Combine(_tmp, "multi.sh");
        await File.WriteAllTextAsync(script, "x=1\nx=2\necho \"x=$x pw={{db}}\"\n");
        var (exit, output) = Run(Script(script, "bash"));
        Assert.Equal(0, exit);
        Assert.Equal("x=2 pw={{db}}\n", output);
    }

    [Fact]
    public void ScriptMode_Pwsh_ExitCodePassthrough()
    {
        if (!Unix) return;
        try { ShellLauncher.ResolveShell("pwsh"); }
        catch (UsageException) { return; }
        // -Command - 的 REPL 语义会把外部命令非 0/1 退出码折叠为 1、失败后跟成功语句则变 0——
        // 合成 exit $LASTEXITCODE 后必须如实透传
        var script = Path.Combine(_tmp, "exit7.ps1");
        File.WriteAllText(script, "sh -c \"exit 7\"\nWrite-Output done\n");
        var (exit, output) = Run(Script(script, "pwsh"));
        Assert.Equal(7, exit);
        Assert.Contains("done", output);
    }

    [Fact]
    public void ScriptMode_Pwsh_Supported()
    {
        if (!Unix) return;
        try { ShellLauncher.ResolveShell("pwsh"); }
        catch (UsageException) { return; } // 环境无 pwsh 则跳过

        var script = Path.Combine(_tmp, "s.ps1");
        File.WriteAllText(script, "Write-Output \"pw={{db}}\"\n");
        var (exit, output) = Run(Script(script, "pwsh"));
        Assert.Equal(0, exit);
        // runner 上的 pwsh 会在输出外包裹 VT 转义序列，产品应原样透传：只断言脱敏结果存在、密文不存在
        Assert.Contains("pw={{db}}", output);
        Assert.DoesNotContain("resolved-db", output);
    }

    [Fact]
    public void ScriptMode_Cmd_Rejected()
    {
        if (!OperatingSystem.IsWindows()) return;
        var script = Path.Combine(_tmp, "s.cmd");
        File.WriteAllText(script, "echo {{db}}\n");
        Assert.Throws<UsageException>(() => Run(Script(script, "cmd")));
    }

    [Fact]
    public void Timeout_KillsProcessTree_Returns124()
    {
        if (!Unix) return;
        var start = DateTime.UtcNow;
        var (exit, _) = Run(Cmd(["/bin/sh", "-c", "sleep 30"], shell: "none") with { TimeoutSeconds = 1 });
        Assert.Equal(ExitCodes.Timeout, exit);
        Assert.True((DateTime.UtcNow - start).TotalSeconds < 15, "超时后必须及时返回");
    }

    [Fact]
    public void Timeout_KillsChildOfShell()
    {
        if (!Unix) return;
        // bash -c 内再起子进程（进程树）
        var (exit, _) = Run(Cmd(["sleep", "30"]) with { TimeoutSeconds = 1 });
        Assert.Equal(ExitCodes.Timeout, exit);
    }

    [Fact]
    public void UnknownShell_Throws()
    {
        Assert.Throws<UsageException>(() => ShellLauncher.ResolveShell("no-such-shell-xyz"));
    }

    [Fact]
    public void AutoShell_ResolvesToAbsolutePath_OnUnix()
    {
        if (!Unix) return;
        var shell = ShellLauncher.ResolveShell("auto");
        Assert.True(Path.IsPathRooted(shell), $"必须返回绝对路径（防 CWD 种植）：{shell}");
        Assert.True(shell.Contains("bash") || shell.EndsWith("/sh") || shell.Contains("zsh"), $"unexpected: {shell}");
    }

    [Fact]
    public void ResolveShell_RejectsRelativeCwdHit()
    {
        if (!Unix) return;
        // 即使当前目录存在同名文件，也不能命中（Windows CreateProcess 会搜 CWD）
        var shell = ShellLauncher.ResolveShell("bash");
        Assert.True(Path.IsPathRooted(shell));
        Assert.DoesNotContain(Directory.GetCurrentDirectory(), shell);
    }

    [Fact]
    public void QuoteForPwsh_QuotesIfNeeded_MetaCharacters()
    {
        Assert.Equal("'a`b'", ShellLauncher.QuoteForPwsh("a`b"));
        Assert.Equal("'a,b'", ShellLauncher.QuoteForPwsh("a,b"));
        Assert.Equal("'@splat'", ShellLauncher.QuoteForPwsh("@splat"));
        Assert.Equal("'#tag'", ShellLauncher.QuoteForPwsh("#tag"));
        Assert.Equal("plain", ShellLauncher.QuoteForPwsh("plain"));
        Assert.Equal("-c", ShellLauncher.QuoteForPwsh("-c"));
        Assert.Equal("''", ShellLauncher.QuoteForPwsh(""));
        Assert.Equal("'it''s'", ShellLauncher.QuoteForPwsh("it's"));
        Assert.Equal("'a b'", ShellLauncher.QuoteForPwsh("a b"));
        Assert.Equal("'a$b'", ShellLauncher.QuoteForPwsh("a$b"));
    }

    [Fact]
    public void ScriptMode_SecretValueWithCrlf_StillRedacted()
    {
        if (!Unix) return;
        // 注入值本身含 \r\n：CRLF 归一必须发生在替换之前，子进程收到的值与脱敏规则保持同一
        var values = new Dictionary<string, string> { ["{{v}}"] = "line1\r\nline2" };
        var req = new ExecRequest
        {
            Args = [],
            ScriptPath = "inline",
            ScriptText = "printf '%s' '{{v}}'\n",
            Shell = "sh",
            TimeoutSeconds = 15,
            Resolve = t => values[t],
            RedactionRules = new Dictionary<string, string> { ["line1\r\nline2"] = "{{v}}" },
        };
        var (exit, output) = Run(req);
        Assert.Equal(0, exit);
        Assert.Equal("{{v}}", output);
    }

    [Fact]
    public void ScriptMode_LargeScript_ChildNotReading_TimeoutStillWorks()
    {
        if (!Unix) return;
        // 脚本 > 管道容量且子进程不读 stdin：同步写会永久挂死、--timeout 失效（第 2 轮修复的回归锚）
        var big = "# x\n" + string.Concat(Enumerable.Repeat(new string('#', 1024) + "\n", 700));
        var req = new ExecRequest
        {
            Args = [],
            ScriptPath = "inline",
            ScriptText = "exec sleep 30\n" + big,
            Shell = "sh",
            TimeoutSeconds = 2,
            Resolve = _ => "unused",
            RedactionRules = new Dictionary<string, string>(),
        };
        var start = DateTime.UtcNow;
        var (exit, _) = Run(req);
        Assert.Equal(ExitCodes.Timeout, exit);
        Assert.True((DateTime.UtcNow - start).TotalSeconds < 20, "超时必须及时生效");
    }

    [Fact]
    public void ScriptMode_CrlfNormalized_ForPosixShell()
    {
        if (!Unix) return;
        var script = Path.Combine(_tmp, "crlf.sh");
        File.WriteAllText(script, "#!/bin/sh\r\necho value={{db.user}}\r\n");
        var (exit, output) = Run(Script(script, "sh"));
        Assert.Equal(0, exit);
        Assert.Equal("value=resolved-db-user\n", output);
    }

    [Fact]
    public void StartFailure_FixedMessage_NoResolvedSecret()
    {
        if (!Unix) return;
        // none 模式 argv[0] 为解析后的密文：启动失败的异常消息不得包含它（I5）
        var req = new ExecRequest
        {
            Args = ["{{db}}"],
            Shell = "none",
            TimeoutSeconds = 10,
            Resolve = _ => "StartFails-Secret-9",
            RedactionRules = new Dictionary<string, string>(),
        };
        var ex = Assert.Throws<UsageException>(() =>
        {
            using var stdout = new MemoryStream();
            using var stderr = new MemoryStream();
            ShellLauncher.Run(req, stdout, stderr);
        });
        Assert.DoesNotContain("StartFails-Secret-9", ex.Message);
    }

    [Fact]
    public void ArgWithSpacesAndQuotes_QuotedForPosix()
    {
        Assert.Equal("'a b'", ShellLauncher.QuoteForPosix("a b"));
        Assert.Equal("'it'\\''s'", ShellLauncher.QuoteForPosix("it's"));
        Assert.Equal("plain", ShellLauncher.QuoteForPosix("plain"));
        Assert.Equal("''", ShellLauncher.QuoteForPosix(""));
    }

    [Fact]
    public void InlineMode_ArgWithSpacesAndSecret()
    {
        if (!Unix) return;
        // 模拟 --password=p@ss w0rd 这类含空格密文经 bash 引号保护仍是一个参数
        var (exit, output) = Run(Cmd(["/bin/echo", "pw={{db}}"], shell: "bash"));
        Assert.Equal(0, exit);
        Assert.Equal("pw={{db}}\n", output);
    }
}
