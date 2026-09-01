using PwHide.Core;
using Xunit;

namespace PwHide.Core.Tests;

public class EchoProbeTests
{
    [Theory]
    [InlineData("echo {{db}}")]
    [InlineData("/bin/echo {{db}}")]
    [InlineData("echo pw={{db}}")]
    [InlineData("printf '%s' {{db}}")]
    [InlineData("Write-Output \"pw={{db}}\"")]
    [InlineData("sh -c 'echo {{db}}'")]
    [InlineData("echo {{db.host}}")]
    [InlineData("echo first; echo {{db}}")]
    [InlineData("echo done && mysql -p{{db}} -e x")]        // 新语义：回显进度+使用密码共现也拦（--allow-echo 放行）
    [InlineData("echo x && printf {{db}}")]
    public void EchoWithSecretPlaceholder_Detected(string command)
    {
        Assert.True(EchoProbe.IsProbe(command, out var token), $"应检出：{command}");
        Assert.StartsWith("{{", token);
    }

    [Theory]
    [InlineData("mysql -u root -p{{db}} -e 'select 1'")]   // 密码作为参数，非回显
    [InlineData("grep '{{db.user}}' app.log")]              // 明文字段回显不拦
    [InlineData("echo {{db.user}} {{db.tenant}}")]          // 明文字段
    [InlineData("echo user={{db.user}}")]
    [InlineData("printf '%s' \"$PWHIDE_V\"")]                // 环境变量注入模式
    [InlineData("echo-backup {{db}}")]                      // echo- 开头的文件名不误伤（原语后需空白）
    [InlineData("tar czf out.tgz {{db.host}}")]             // 字段值为密文但无回显原语
    [InlineData("echo hello world")]
    [InlineData("printenv PATH")]
    public void NormalCommands_NotFlagged(string command)
    {
        Assert.False(EchoProbe.IsProbe(command, out _), $"不应误报：{command}");
    }

    [Fact]
    public void MultiLineScript_CooccurrenceDetected()
    {
        // 全文共现语义：脚本里既有回显又有密文占位符 → 拦截（无论语序/分隔符）
        var script = "#!/bin/sh\nmysql -p{{db}} -e 'select 1'\necho done\n";
        Assert.True(EchoProbe.IsProbe(script, out _));

        // 只有回显、无密文占位符 → 放行
        var clean = "#!/bin/sh\necho start\nmysql -u root -e 'select 1'\necho done\n";
        Assert.False(EchoProbe.IsProbe(clean, out _));

        // 只有占位符、无回显原语 → 放行
        var noEcho = "#!/bin/sh\nmysql -p{{db}} -e 'select 1'\n";
        Assert.False(EchoProbe.IsProbe(noEcho, out _));
    }

    [Fact]
    public void DenyMessage_ContainsGuidance()
    {
        Assert.Contains("--allow-echo", EchoProbe.DenyMessage("{{db}}"));
        Assert.Contains("{{db}}", EchoProbe.DenyMessage("{{db}}"));
    }
}

public class RedactorCountTests
{
    [Fact]
    public void ReplacementCounts_Tracked()
    {
        var rules = new Dictionary<string, string> { ["alpha-1"] = "{{a}}", ["beta-2"] = "{{b}}" };
        var redactor = new StreamRedactor(rules);
        redactor.Process("alpha-1 alpha-1 beta-2 x"u8);
        redactor.Flush();

        var counts = redactor.ReplacementCounts;
        Assert.Equal(2, counts["{{a}}"]);
        Assert.Equal(1, counts["{{b}}"]);
    }
}
