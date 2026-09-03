using System.Runtime.InteropServices;
using System.Text;
using PwHide.Core;

namespace PwHide.Cli;

/// <summary>
/// 隐藏输入（密码/口令）。Unix 路径的关键事实（0.8.0 修复的三层坑）：
///   1. .NET 10 的 Console.ReadLine 自带行编辑回显，stty -echo 压不住 → 不能用 Console.ReadLine；
///   2. .NET 10 会把 fd 0 代理成自己的终端层：对 fd 0 跑 `stty raw -echo` 报成功但改的是代理、
///      真终端纹丝不动（实测 ECHO 位在打字时刻仍为 ON）→ 不能依赖 fd 0 / stty 子进程；
///   3. 正解：打开真实控制终端 /dev/tty，用 termios P/Invoke（tcgetattr/tcsetattr）原位清
///      ECHO|ICANON（无子进程、无 spawn 竞态窗口），设置后回读标志位验证（fail-closed），
///      再从该 fd 逐字节 read。lflag 位偏移按平台：Linux lflag@12(u32)，macOS lflag@24(u64)。
/// 非交互/管道（stdin 重定向）时 Begin 返回非激活作用域，Read 直接走提供的 TextReader。
/// </summary>
public static class HiddenInput
{
    public sealed class HiddenScope : IDisposable
    {
        private readonly Action? _restore;
        public bool Active => _restore != null;
        internal HiddenScope(Action? restore) => _restore = restore;
        public void Dispose() => _restore?.Invoke();
    }

    private const int O_RDWR = 0x2;
    private const uint ECHO_BIT = 0x8;    // POSIX：ECHO=0x8，ICANON=0x2（Linux/macOS 位值一致）
    private const uint ICANON_BIT = 0x2;

    /// <summary>进入隐藏输入模式。必须在打印提示符之前调用（提示符期间回显已关闭）。</summary>
    public static HiddenScope Begin(TextReader stdin, bool interactive)
    {
        if (!interactive || Console.IsInputRedirected) return new HiddenScope(null);
        if (OperatingSystem.IsWindows())
        {
            var h = GetStdHandle(StdInputHandle);
            _ = GetConsoleMode(h, out var mode);
            _ = SetConsoleMode(h, mode & ~EnableEchoInput);
            return new HiddenScope(() => _ = SetConsoleMode(h, mode));
        }

        var tty = open("/dev/tty", O_RDWR);
        if (tty < 0)
            throw new VaultException("无法打开控制终端（/dev/tty）。为防口令明文回显，拒绝在无终端环境读取口令：请改用 PWHIDE_PASSPHRASE_FILE（chmod 600）");

        try
        {
            var original = new byte[128];
            if (tcgetattr(tty, original) != 0)
                throw new VaultException("无法读取终端属性（tcgetattr 失败）。为防口令明文回显，拒绝在此终端读取口令：请改用 PWHIDE_PASSPHRASE_FILE（chmod 600）");

            var hidden = new byte[original.Length];
            Array.Copy(original, hidden, original.Length);
            ClearEchoCanonical(hidden);
            if (tcsetattr(tty, 0 /* TCSANOW */, hidden) != 0)
                throw new VaultException("无法设置终端属性（tcsetattr 失败）。为防口令明文回显，拒绝在此终端读取口令：请改用 PWHIDE_PASSPHRASE_FILE（chmod 600）");

            // 回读验证（fail-closed）：设置未生效（被其他层覆盖等）就拒绝读取
            var verify = new byte[128];
            if (tcgetattr(tty, verify) != 0 || EchoOrCanonicalOn(verify))
                throw new VaultException("终端回显无法关闭（设置被覆盖）。为防口令明文回显，拒绝在此终端读取口令：请改用 PWHIDE_PASSPHRASE_FILE（chmod 600）");

            _ttyFd = tty;
            return new HiddenScope(() =>
            {
                var fd = open("/dev/tty", O_RDWR);
                if (fd >= 0)
                {
                    var restore = new byte[original.Length];
                    Array.Copy(original, restore, original.Length);
                    tcsetattr(fd, 0, restore);
                    close(fd);
                }
                _ttyFd = 0;
            });
        }
        catch
        {
            close(tty);
            _ttyFd = 0;
            throw;
        }
    }

    private static int _ttyFd;

    public static string ReadLine(HiddenScope scope, TextReader stdin)
    {
        if (!scope.Active) return stdin.ReadLine() ?? "";
        if (OperatingSystem.IsWindows()) return Console.ReadLine() ?? "";
        return ReadRawFromTty(scope);
    }

    private static string ReadRawFromTty(HiddenScope scope)
    {
        var fd = _ttyFd;
        var bytes = new List<byte>();
        var buf = new byte[1];
        while (true)
        {
            var n = read(fd, buf, 1);
            if (n <= 0) break;
            var b = buf[0];
            if (b == (byte)'\n' || b == (byte)'\r') break;
            if (b == 0x7f || b == 0x08)
            {
                var k = 1;
                while (bytes.Count >= k && (bytes[bytes.Count - k] & 0xC0) == 0x80) k++;
                if (bytes.Count >= k)
                {
                    bytes.RemoveRange(bytes.Count - k, k);
                    Console.Error.Write("\b \b");
                }
                continue;
            }
            if (b < 0x20) continue;
            bytes.Add(b);
            if (b < 0x80 || (b & 0xC0) == 0xC0) Console.Error.Write('*');
        }
        Console.Error.WriteLine();
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    private static void ClearEchoCanonical(Span<byte> buf)
    {
        var off = OperatingSystem.IsMacOS() ? 24 : 12;   // c_lflag 偏移：macOS u64@24 / Linux u32@12
        if (OperatingSystem.IsMacOS())
        {
            var v = (uint)(buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16) | (buf[off+3] << 24));
            v &= ~(ECHO_BIT | ICANON_BIT);
            for (var i = 0; i < 4; i++) buf[off + i] = (byte)(v >> (8 * i));
        }
        else
        {
            var v = BitConverter.ToUInt32(buf.ToArray(), off);
            v &= ~(ECHO_BIT | ICANON_BIT);
            for (var i = 0; i < 4; i++) buf[off + i] = (byte)(v >> (8 * i));
        }
    }

    private static bool EchoOrCanonicalOn(ReadOnlySpan<byte> buf)
    {
        var off = OperatingSystem.IsMacOS() ? 24 : 12;
        uint v = OperatingSystem.IsMacOS()
            ? (uint)(buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16) | (buf[off+3] << 24))
            : BitConverter.ToUInt32(buf.ToArray(), off);
        return (v & (ECHO_BIT | ICANON_BIT)) != 0;
    }

    private const int StdInputHandle = -10;
    private const uint EnableEchoInput = 0x0004;

    [DllImport("libc", SetLastError = true)]
    private static extern int open(string path, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int read(int fd, byte[] buf, int count);

    [DllImport("libc", SetLastError = true)]
    private static extern int tcgetattr(int fd, byte[] termios);

    [DllImport("libc", SetLastError = true)]
    private static extern int tcsetattr(int fd, int actions, byte[] termios);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string ReadHiddenWindows()
    {
        var h = GetStdHandle(StdInputHandle);
        _ = GetConsoleMode(h, out var mode);
        _ = SetConsoleMode(h, mode & ~EnableEchoInput);
        try
        {
            var line = Console.ReadLine() ?? "";
            Console.Out.WriteLine();
            return line;
        }
        finally
        {
            _ = SetConsoleMode(h, mode);
        }
    }
}
