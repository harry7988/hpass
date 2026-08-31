using System.Runtime.InteropServices;

namespace HPass.Cli;

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
        _ = RunSh("stty -echo");
        try
        {
            var line = Console.ReadLine() ?? "";
            Console.Out.WriteLine();
            return line;
        }
        finally
        {
            _ = RunSh("stty echo");
        }
    }

    private static string RunSh(string args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("/bin/sh", ["-c", args])
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.WaitForExit(2000);
        return p.StandardOutput.ReadToEnd();
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
