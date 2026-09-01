using System.Runtime.InteropServices;
using PwHide.Core;

namespace PwHide.Cli;

/// <summary>
/// 隐藏输入（密码/口令）。Unix 经 stty 关闭回显（避免跨平台 termios 结构差异），Windows 经控制台 API。
/// 仅在交互终端使用；管道/测试环境直接从提供的 TextReader 读取。
/// </summary>
public static class HiddenInput
{
    public static string ReadLineHidden(TextReader stdin, bool interactive)
    {
        if (!interactive || Console.IsInputRedirected)
            return stdin.ReadLine() ?? "";
        return OperatingSystem.IsWindows() ? ReadHiddenWindows() : ReadHiddenUnix();
    }

    private static string ReadHiddenUnix()
    {
        if (!RunStty("-echo"))
            // fail-closed：关闭回显失败时继续读取会把口令明文回显进终端/会话录像——宁可拒绝
            throw new VaultException("无法关闭终端回显（/bin/stty 失败）。为防口令明文回显，拒绝在此终端读取口令：请改用 PWHIDE_PASSPHRASE_FILE（chmod 600）或在常规终端运行");
        try
        {
            var line = Console.ReadLine() ?? "";
            Console.Out.WriteLine();
            return line;
        }
        finally
        {
            _ = RunStty("echo");
        }
    }

    private static bool RunStty(string args)
    {
        // 直接执行绝对路径 /bin/stty：经 sh 按 PATH 解析会被种植假 stty 收割口令；同时清洗环境
        var psi = new System.Diagnostics.ProcessStartInfo("/bin/stty", [args])
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.Environment.Remove("PWHIDE_PASSPHRASE");
        psi.Environment.Remove("PWHIDE_PASSPHRASE_FILE");
        try
        {
            using var p = System.Diagnostics.Process.Start(psi)!;
            if (!p.WaitForExit(2000)) return false;
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private const int StdInputHandle = -10;
    private const uint EnableEchoInput = 0x0004;

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
