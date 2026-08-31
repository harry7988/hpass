using HPass.Core;
using Xunit;

namespace HPass.Core.Tests;

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
    [InlineData("printf '%s' \"$HPASS_V\"")]                // 环境变量注入模式
    [InlineData("echo-backup {{db}}")]                      // echo- 开头的文件名不误伤（原语后需空白）
    [InlineData("echo done && mysql -p{{db}} -e x")]        // echo 与占位符被 && 分隔，非同语句
    [InlineData("tar czf out.tgz {{db.host}}")]             // 字段值为密文但无回显原语
    [InlineData("echo hello world")]
    [InlineData("printenv PATH")]
    public void NormalCommands_NotFlagged(string command)
    {
        Assert.False(EchoProbe.IsProbe(command, out _), $"不应误报：{command}");
    }

    [Fact]
    public void MultiLineScript_PerLineChecked()
    {
        var script = "#!/bin/sh\necho start\nmysql -p{{db}} -e 'select 1'\necho done\n";
        Assert.False(EchoProbe.IsProbe(script, out _));

        var probeScript = "#!/bin/sh\necho start\necho pw={{db}}\n";
        Assert.True(EchoProbe.IsProbe(probeScript, out _));
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
