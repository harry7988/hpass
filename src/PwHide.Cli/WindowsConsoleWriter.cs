using System.Runtime.InteropServices;
using System.Text;

namespace PwHide.Cli;

/// <summary>
/// Windows 控制台输出写入口：WriteConsoleW 直写 UTF-16。
///
/// 为什么不用 UTF-8 直写：OpenStandardOutput 绕过 Console 的转码层，UTF-8 字节会被
/// GBK 代码页（中文 Windows cmd 默认 cp936）的解码器显示成"鏈壘鍒?"式乱码。
/// 为什么不用 Console.OutputEncoding 转码：项目启用 InvariantGlobalization，代码页编码
/// 不可依赖；且转码会丢失 GBK 外字符。WriteConsoleW 与控制台代码页无关、无损、
/// 也不改动用户控制台设置（无 chcp 的会话级副作用）。
///
/// 仅当句柄确为控制台（GetFileType == FILE_TYPE_CHAR）时启用；重定向/管道/非 Windows
/// 一律返回 false，由调用方回退 UTF-8 StreamWriter（重定向场景无代码页语义）。
/// </summary>
public sealed class WindowsConsoleWriter : TextWriter
{
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;
    private const uint FILE_TYPE_CHAR = 0x0002;
    private const nint INVALID_HANDLE = -1;
    private const int ChunkChars = 4096;   // WriteConsoleW 单次缓冲建议 < 64K，取 4K

    private readonly nint _handle;
    private readonly Stream _fallback;
    private bool _consoleUsable = true;

    public override Encoding Encoding => Encoding.Unicode;

    private WindowsConsoleWriter(nint handle, Stream fallback) =>
        (_handle, _fallback) = (handle, fallback);

    /// <summary>句柄是真实 Windows 控制台时创建 WriteConsoleW 写入器；否则返回 false（调用方回退 UTF-8）。</summary>
    public static bool TryCreate(Stream fallback, bool isConsoleHint, bool stderr, out TextWriter writer)
    {
        writer = TextWriter.Null;
        if (!OperatingSystem.IsWindows() || !isConsoleHint) return false;

        var handle = GetStdHandle(stderr ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
        if (handle == 0 || handle == INVALID_HANDLE) return false;
        if (GetFileType(handle) != FILE_TYPE_CHAR) return false;   // 重定向到文件/管道（IsOutputRedirected 判定失效时的兜底）

        writer = new WindowsConsoleWriter(handle, fallback);
        return true;
    }

    // TextWriter 的最小覆写集：其余 Write/WriteLine 重载最终都落到这三个方法
    public override void Write(char value) => Write(new ReadOnlySpan<char>(in value));

    public override void Write(string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        Write(value.AsSpan());
    }

    public override void Write(char[] buffer, int index, int count)
    {
        if (buffer is null || count <= 0) return;
        Write(buffer.AsSpan(index, count));
    }

    private void Write(ReadOnlySpan<char> text)
    {
        while (!text.IsEmpty)
        {
            var chunk = text[..Math.Min(text.Length, ChunkChars)];
            if (!WriteConsoleChunk(chunk)) FallbackUtf8(chunk);
            text = text[chunk.Length..];
        }
    }

    private bool WriteConsoleChunk(ReadOnlySpan<char> text)
    {
        if (!_consoleUsable) return false;
        var buf = text.ToArray();
        if (WriteConsoleW(_handle, buf, (uint)buf.Length, out var written) && written == buf.Length)
            return true;
        _consoleUsable = false;   // 句柄失效（控制台被关闭/分离等）：本次起整体回退 UTF-8 字节流
        return false;
    }

    private void FallbackUtf8(ReadOnlySpan<char> text)
    {
        var bytes = new byte[Encoding.UTF8.GetByteCount(text)];
        Encoding.UTF8.GetBytes(text, bytes);
        _fallback.Write(bytes, 0, bytes.Length);
        _fallback.Flush();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(nint hFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteConsoleW(nint hConsoleOutput, char[] lpBuffer, uint nNumberOfCharsToWrite, out uint lpNumberOfCharsWritten, nint lpReserved = default);
}
