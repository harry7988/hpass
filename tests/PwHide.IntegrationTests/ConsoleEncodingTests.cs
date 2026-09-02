using System.Text;
using PwHide.Cli;
using Xunit;

namespace PwHide.IntegrationTests;

/// <summary>
/// 控制台编码策略测试（Windows 中文 cmd 乱码修复：WriteConsoleW / UTF-8 双通道）。
/// 真实 Windows 交互控制台的 WriteConsoleW 渲染无法在 CI（输出重定向）中自动化，
/// 这里锁定的是可跨平台验证的契约：显式流恒 UTF-8、非控制台句柄绝不走控制台通道。
/// </summary>
public class ConsoleEncodingTests
{
    [Fact]
    public void ExplicitStreams_AlwaysUtf8NoBom_ChineseRoundtrip()
    {
        using var ms = new MemoryStream();
        var ctx = new CliContext { Out = ms, Err = new MemoryStream(), In = new StringReader(""), Interactive = false };
        ctx.OutText.WriteLine("未找到 vault（C:\\Users\\shenh\\.pwhide\\vault.json）。请先运行 pwhide init");
        // 精确字节等价：既证明 UTF-8 解码正确，也证明无 BOM 前缀（BOM 会解码出 \uFEFF）。
        // NewLine 跟随平台（TextWriter 默认 Environment.NewLine），不是编码契约的一部分
        Assert.Equal("未找到 vault（C:\\Users\\shenh\\.pwhide\\vault.json）。请先运行 pwhide init" + Environment.NewLine,
            new UTF8Encoding(false).GetString(ms.ToArray()));
    }

    [Fact]
    public void ConsoleHintFalse_NeverUsesConsoleChannel()
    {
        using var ms = new MemoryStream();
        Assert.False(WindowsConsoleWriter.TryCreate(ms, isConsoleHint: false, stderr: false, out _));
        Assert.False(WindowsConsoleWriter.TryCreate(ms, isConsoleHint: false, stderr: true, out _));
    }

    [Fact]
    public void NonWindows_NeverUsesConsoleChannel()
    {
        if (OperatingSystem.IsWindows()) return;
        using var ms = new MemoryStream();
        Assert.False(WindowsConsoleWriter.TryCreate(ms, isConsoleHint: true, stderr: false, out _));
    }

    [Fact]
    public void Windows_RedirectedHandle_NeverUsesConsoleChannel()
    {
        // CI（含 Windows runner）输出均被重定向：句柄非 FILE_TYPE_CHAR，必须回退 UTF-8 通道
        if (!OperatingSystem.IsWindows() || !Console.IsOutputRedirected) return;
        using var ms = new MemoryStream();
        Assert.False(WindowsConsoleWriter.TryCreate(ms, isConsoleHint: true, stderr: false, out _));
    }
}
