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
        _ = RunStty("-echo");
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

    private static string RunStty(string args)
    {
        // 直接执行绝对路径 /bin/stty：经 sh 按 PATH 解析会被种植假 stty 收割口令；同时清洗环境
        var psi = new System.Diagnostics.ProcessStartInfo("/bin/stty", [args])
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.Environment.Remove("HPASS_PASSPHRASE");
        psi.Environment.Remove("HPASS_PASSPHRASE_FILE");
        try
        {
            using var p = System.Diagnostics.Process.Start(psi)!;
            p.WaitForExit(2000);
            return p.StandardOutput.ReadToEnd();
        }
        catch
        {
            return "";
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
