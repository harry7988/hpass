using System.Runtime.InteropServices;
using System.Text;

namespace PwHide.Cli;

/// <summary>
/// pwhide 自身消息的输出通道（exec 子进程字节流不经此处，保持原样）。
///
/// 优先级：PWHIDE_OUTPUT_ENCODING 环境变量 &gt; home/output-encoding 文件（doctor --output-encoding 写入）&gt; 自动。
/// 取值：auto | utf8 | utf16 | gbk(=cp936) | json(=ascii，非 ASCII 一律转义为 \uXXXX，任何终端可读)。
///
/// 自动策略（Windows，以句柄真实类型为准，而非 IsOutputRedirected——PowerShell 会把子进程
/// stdout 接管为管道再用 [Console]::OutputEncoding 解码，恰与会话控制台代码页一致）：
///   控制台句柄   → WriteConsoleW 直写 UTF-16（与代码页无关、无损）
///   管道句柄     → 按 GetConsoleOutputCP() 转码（UTF-8 字节直进 GBK/Unicode 解码器都会乱码）
///   文件/其他    → UTF-8（落盘无代码页语义）
/// 非 Windows：恒 UTF-8。
/// </summary>
public static class OutputChannel
{
    public const string EnvVar = "PWHIDE_OUTPUT_ENCODING";
    public const string FileName = "output-encoding";

    private static readonly UTF8Encoding Utf8NoBom = new(false);

    static OutputChannel() =>
        // InvariantGlobalization 下内置编码只有 UTF 系列；注册 CodePages 提供程序后
        // GBK(936) 等纯托管实现的代码页编码即可用（不依赖 ICU/NLS）
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

    /// <summary>规范化用户取值；无效返回 null。空串视为未指定（null）。</summary>
    public static string? NormalizeOverride(string? raw) => raw switch
    {
        null or "" => null,
        "auto" => "auto",
        "utf8" or "utf-8" => "utf8",
        "utf16" or "utf16le" or "unicode" => "utf16",
        "gbk" or "cp936" or "gb2312" or "936" => "gbk",
        "json" or "ascii" => "json",
        _ => null,
    };

    private static Encoding EncodingFor(string mode) => mode switch
    {
        "utf16" => Encoding.Unicode,
        "gbk" => Encoding.GetEncoding(936),
        _ => Utf8NoBom,
    };

    /// <summary>创建 pwhide 消息写入器。isStdHandle：该流是否为进程标准输出/错误句柄（测试内存流恒 false）。</summary>
    public static TextWriter Create(Stream stream, bool stderr, bool isStdHandle, string home)
    {
        var (mode, _) = ResolveOverride(home);
        if (mode is not null and not "auto")
        {
            try
            {
                return mode == "json"
                    ? new AsciiEscapeWriter(new StreamWriter(stream, Utf8NoBom, 1024, leaveOpen: true) { AutoFlush = true })
                    : new StreamWriter(stream, EncodingFor(mode), 1024, leaveOpen: true) { AutoFlush = true };
            }
            catch (ArgumentException)
            {
                // 覆盖值所需编码在当前运行时不可用（理论不可达，CodePages 已注册）：回退自动
            }
        }

        if (!isStdHandle || !OperatingSystem.IsWindows()) return Utf8(stream);

        var handle = WindowsConsoleWriter.StdHandle(stderr);
        if (handle == 0 || handle == -1) return Utf8(stream);
        var fileType = WindowsConsoleWriter.FileType(handle);
        if (fileType == WindowsConsoleWriter.FileTypeChar)
            return new WindowsConsoleWriter(handle, stream);

        if (fileType == WindowsConsoleWriter.FileTypePipe)
        {
            // 管道消费者（PowerShell）按会话控制台代码页解码；无控制台会话（CP=0）或不可映射代码页时回退 UTF-8
            var cp = GetConsoleOutputCP();
            if (cp != 0)
            {
                try
                {
                    var enc = cp == 65001 ? Utf8NoBom : Encoding.GetEncoding((int)cp);
                    return new StreamWriter(stream, enc, 1024, leaveOpen: true) { AutoFlush = true };
                }
                catch (ArgumentException) { }
            }
        }
        return Utf8(stream);
    }

    private static StreamWriter Utf8(Stream s) =>
        new(s, Utf8NoBom, 1024, leaveOpen: true) { AutoFlush = true };

    /// <summary>解析覆盖配置（环境变量优先于文件）。返回 (规范值或 null, 来源描述)。</summary>
    public static (string? Mode, string Source) ResolveOverride(string home)
    {
        var env = Environment.GetEnvironmentVariable(EnvVar);
        var normalized = NormalizeOverride(env);
        if (env is not null && normalized is null)
            return (null, $"环境变量 {EnvVar}={env} 无效（可用 auto|utf8|utf16|gbk|json），已忽略");
        if (normalized is not null)
            return (normalized, $"环境变量 {EnvVar}={normalized}");
        try
        {
            var file = Path.Combine(home, FileName);
            if (File.Exists(file))
            {
                normalized = NormalizeOverride(File.ReadAllText(file).Trim());
                if (normalized is not null)
                    return (normalized, $"配置文件 {file}：{normalized}");
                return (null, $"配置文件 {file} 内容无效，已忽略");
            }
        }
        catch (IOException) { }
        return (null, "自动");
    }

    /// <summary>doctor 用的输出通道诊断行。</summary>
    public static List<string> Describe(string home, bool stderr = false)
    {
        var lines = new List<string>();
        var (mode, source) = ResolveOverride(home);
        lines.Add($"输出编码 : {source}");
        if (mode is not null and not "auto")
        {
            lines.Add($"输出通道 : 手工指定（{mode}）");
            return lines;
        }
        if (!OperatingSystem.IsWindows())
        {
            lines.Add("输出通道 : UTF-8（非 Windows 恒 UTF-8）");
            return lines;
        }
        var handle = WindowsConsoleWriter.StdHandle(stderr);
        var ft = handle == 0 || handle == -1 ? 0 : WindowsConsoleWriter.FileType(handle);
        var cp = GetConsoleOutputCP();
        var channel = ft switch
        {
            WindowsConsoleWriter.FileTypeChar => "控制台 → WriteConsoleW 直写（与代码页无关）",
            WindowsConsoleWriter.FileTypePipe when cp != 0 => $"管道 → 按控制台代码页 {cp} 转码（PowerShell 按 [Console]::OutputEncoding 解码）",
            WindowsConsoleWriter.FileTypePipe => "管道 → UTF-8（无控制台会话，无法取代码页）",
            _ => "文件重定向 → UTF-8",
        };
        lines.Add($"输出通道 : {channel}");
        return lines;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleOutputCP();
}

/// <summary>
/// json/ascii 模式：非 ASCII 与控制字符一律转义为 \uXXXX，纯 ASCII 字节流在任何终端/管道下都不会乱码（终极兜底）。
/// 换行与制表符保持字面，保证可读性。
/// </summary>
public sealed class AsciiEscapeWriter(TextWriter inner) : TextWriter
{
    public override Encoding Encoding => inner.Encoding;

    public override void Write(char value)
    {
        if (value is '\n' or '\t') { inner.Write(value); return; }
        if (value < 0x20 || value > 0x7E)
        {
            inner.Write("\\u");
            inner.Write(((int)value).ToString("x4"));
        }
        else inner.Write(value);
    }

    public override void Write(string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        foreach (var ch in value) Write(ch);
    }

    public override void Write(char[] buffer, int index, int count)
    {
        for (var i = index; i < index + count; i++) Write(buffer[i]);
    }
}
