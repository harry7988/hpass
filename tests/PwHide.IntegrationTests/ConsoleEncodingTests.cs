using System.Text;
using PwHide.Core;
using PwHide.Cli;
using Xunit;

namespace PwHide.IntegrationTests;

/// <summary>
/// 输出通道/编码策略测试（Windows 中文控制台乱码的完整修复链）。
/// 真实 Windows 交互控制台的 WriteConsoleW/管道转码渲染无法在 CI（输出重定向）中自动化，
/// 这里锁定跨平台可验证的契约：覆盖链（env &gt; 文件 &gt; auto）、各模式的字节形态、
/// doctor 全局指定、GBK 编码可用性（CodePages 提供程序）。
/// </summary>
public class ConsoleEncodingTests : IDisposable
{
    private readonly string _home = Path.Combine(Path.GetTempPath(), "pwhide-enc-" + Guid.NewGuid().ToString("N"));
    private static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(OutputChannel.EnvVar, null);
        try { Directory.Delete(_home, recursive: true); } catch { }
    }

    /// <summary>在独立 home 上以内存流运行 CLI（显式流 = OutIsStd=false，不受真实句柄影响）。</summary>
    private (int Exit, byte[] Out, byte[] Err) RunHome(params string[] args)
    {
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var full = new[] { "--home", _home }.Concat(args).ToArray();
        var exit = CliRunner.Run(full, stdout, stderr, new StringReader(""), interactive: false);
        return (exit, stdout.ToArray(), stderr.ToArray());
    }

    [Fact]
    public void Auto_ExplicitStreams_Utf8NoBom()
    {
        var (exit, outBytes, _) = RunHome("version");
        Assert.Equal(0, exit);
        var text = new UTF8Encoding(false).GetString(outBytes);
        Assert.StartsWith("pwhide ", text);   // 精确解码成立即证明 UTF-8 无 BOM（BOM 会带 \uFEFF 前缀）
    }

    [Fact]
    public void Auto_ChineseMessage_Utf8Exact()
    {
        var (_, _, errBytes) = RunHome("list");   // 未初始化的 home → 中文错误消息
        Assert.Equal("pwhide: 未找到 vault（" + Path.Combine(_home, "vault.json") + "）。请先运行 pwhide init" + Environment.NewLine,
            new UTF8Encoding(false).GetString(errBytes));
    }

    [Fact]
    public void EnvOverride_Utf16_WritesUtf16Le()
    {
        Environment.SetEnvironmentVariable(OutputChannel.EnvVar, "utf16");
        var (_, outBytes, _) = RunHome("version");
        Assert.StartsWith("pwhide ", Encoding.Unicode.GetString(outBytes));   // 按 UTF-16LE 可正确解码
    }

    [Fact]
    public void EnvOverride_Invalid_Ignored_FallsBackAuto()
    {
        Environment.SetEnvironmentVariable(OutputChannel.EnvVar, "banana");
        var (_, outBytes, _) = RunHome("version");
        Assert.StartsWith("pwhide ", new UTF8Encoding(false).GetString(outBytes));
    }

    [Fact]
    public void EnvBeatsFile_WhenBothSet()
    {
        Directory.CreateDirectory(_home);
        File.WriteAllText(Path.Combine(_home, OutputChannel.FileName), "json");
        Environment.SetEnvironmentVariable(OutputChannel.EnvVar, "utf16");
        var (_, outBytes, _) = RunHome("version");
        Assert.StartsWith("pwhide ", Encoding.Unicode.GetString(outBytes));
    }

    [Fact]
    public void FileOverride_Json_AsciiOnly_EscapesChinese()
    {
        Directory.CreateDirectory(_home);
        File.WriteAllText(Path.Combine(_home, OutputChannel.FileName), "json");
        var (_, _, errBytes) = RunHome("list");
        var text = Encoding.ASCII.GetString(errBytes);   // 纯 ASCII：任何解码器下都不乱码
        Assert.Contains("pwhide: ", text);
        Assert.Contains(@"\u", text);                     // 中文已转义
        Assert.DoesNotContain("未找到", text);
    }

    [Fact]
    public void Doctor_SetOutputEncoding_PersistsAndApplies()
    {
        var (exit, outBytes, _) = RunHome("doctor", "--output-encoding", "utf16");
        Assert.Equal(ExitCodes.Vault, exit);   // 空 home 上 doctor 正常报告"未初始化"（退出码 3），编码写入仍生效
        Assert.Equal("utf16", File.ReadAllText(Path.Combine(_home, OutputChannel.FileName)).Trim());
        // 确认消息在写入文件之后才首次用到 OutText（懒创建）→ 立即按新编码 utf16 输出
        Assert.Contains("已全局指定为 utf16", Encoding.Unicode.GetString(outBytes));

        Environment.SetEnvironmentVariable(OutputChannel.EnvVar, null);
        var (_, outBytes2, _) = RunHome("version");
        Assert.StartsWith("pwhide ", Encoding.Unicode.GetString(outBytes2));   // 文件覆盖已对新命令生效
    }

    [Fact]
    public void Doctor_RevertToAuto_Works()
    {
        RunHome("doctor", "--output-encoding", "utf16");
        var (exit, outBytes, _) = RunHome("doctor", "--output-encoding", "auto");
        Assert.Equal(ExitCodes.Vault, exit);   // 同上：空 home
        var (_, outBytes2, _) = RunHome("version");
        Assert.StartsWith("pwhide ", new UTF8Encoding(false).GetString(outBytes2));
    }

    [Fact]
    public void Doctor_InvalidEncoding_UsageError()
    {
        var (exit, _, errBytes) = RunHome("doctor", "--output-encoding", "utf-8-err");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("无效的输出编码", new UTF8Encoding(false).GetString(errBytes));
    }

    [Fact]
    public void Doctor_ReportsChannelDiagnostics()
    {
        var (exit, outBytes, _) = RunHome("doctor");
        Assert.Equal(ExitCodes.Vault, exit);   // 空 home：doctor 报告未初始化
        var text = new UTF8Encoding(false).GetString(outBytes);
        Assert.Contains("输出编码 :", text);
        Assert.Contains("输出通道 :", text);
    }

    [Fact]
    public void GbkCodepage_Available_ViaProvider()
    {
        // InvariantGlobalization 内置编码不含 GBK；注册 CodePages 提供程序后必须可用（管道自动转码与 gbk 覆盖的前提）
        Assert.NotNull(Encoding.GetEncoding(936));
        var gbk = Encoding.GetEncoding(936);
        Assert.Equal("未找到", gbk.GetString(gbk.GetBytes("未找到")));
    }

    [Fact]
    public void ConsoleWriter_NonStdHandle_NeverUsesStdChannel()
    {
        // 显式流（isStdHandle=false）永不触碰标准句柄通道（Windows 真实控制台下也恒 UTF-8/覆盖）
        Assert.False(WindowsConsoleWriter.TryCreate(new MemoryStream(), isStdHandle: false, stderr: false, out _));
        Assert.False(WindowsConsoleWriter.TryCreate(new MemoryStream(), isStdHandle: false, stderr: true, out _));
    }

    [Fact]
    public void ConsoleWriter_NonWindows_NeverUsesStdChannel()
    {
        if (OperatingSystem.IsWindows()) return;
        Assert.False(WindowsConsoleWriter.TryCreate(new MemoryStream(), isStdHandle: true, stderr: false, out _));
    }

    [Fact]
    public void ConsoleWriter_Windows_RedirectedHandle_NeverUsesStdChannel()
    {
        // CI（含 Windows runner）输出均被重定向：句柄非 FILE_TYPE_CHAR，必须走管道/文件通道
        if (!OperatingSystem.IsWindows() || !Console.IsOutputRedirected) return;
        Assert.False(WindowsConsoleWriter.TryCreate(new MemoryStream(), isStdHandle: true, stderr: false, out _));
    }
}
