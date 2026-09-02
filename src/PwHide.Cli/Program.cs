using System.Text;
using PwHide.Core;

namespace PwHide.Cli;

public sealed class CliContext
{
    public required Stream Out { get; init; }
    public required Stream Err { get; init; }
    public required TextReader In { get; init; }
    public bool Interactive { get; init; } = true;
    public string Home { get; set; } = Vault.DefaultHome();
    /// <summary>Out/Err 是否为真实控制台句柄（Windows 下走 WriteConsoleW，中文 cmd 不乱码；重定向/管道/测试内存流恒为 UTF-8）。</summary>
    internal bool OutIsConsole { get; init; }
    internal bool ErrIsConsole { get; init; }

    private TextWriter? _outText;
    private TextWriter? _errText;
    public TextWriter OutText => _outText ??= NewWriter(Out, OutIsConsole, stderr: false);
    public TextWriter ErrText => _errText ??= NewWriter(Err, ErrIsConsole, stderr: true);

    private static readonly UTF8Encoding Utf8NoBom = new(false);

    /// <summary>
    /// 输出编码/通道选择：真实 Windows 控制台 → WriteConsoleW（UTF-16 直写，与控制台代码页无关，
    /// 亦不依赖 InvariantGlobalization 下不可用的代码页转码；OpenStandardOutput 直写 UTF-8 到
    /// GBK 控制台会产生"鏈壘鍒?"式乱码）；重定向到文件/管道时无代码页语义，一律 UTF-8
    /// （与 exec 子进程链路的约定一致）。
    /// </summary>
    private static TextWriter NewWriter(Stream s, bool isConsole, bool stderr) =>
        WindowsConsoleWriter.TryCreate(s, isConsole, stderr, out var consoleWriter)
            ? consoleWriter
            : new StreamWriter(s, Utf8NoBom, 1024, leaveOpen: true) { AutoFlush = true };
}

public static class CliRunner
{
    public static int Run(string[] args, Stream? stdout = null, Stream? stderr = null,
                          TextReader? stdin = null, bool interactive = true)
    {
        var ctx = new CliContext
        {
            Out = stdout ?? Console.OpenStandardOutput(),
            Err = stderr ?? Console.OpenStandardError(),
            In = stdin ?? Console.In,
            Interactive = interactive,
            // 真实 CLI 运行（未显式传流）且句柄是控制台时，才按控制台代码页输出；测试传入内存流恒为 UTF-8
            OutIsConsole = stdout is null && !Console.IsOutputRedirected,
            ErrIsConsole = stderr is null && !Console.IsErrorRedirected,
        };

        // 全局选项 --home <dir>：只认命令名之前的位置（第 0/1 个 token），
        // 避免劫持子命令自己的 --home 参数（如 pwhide exec -- gpg --home ~/.gnupg …）
        var rest = new List<string>(args);
        for (var i = 0; i < Math.Min(2, rest.Count - 1); i++)
        {
            if (rest[i] == "--home")
            {
                ctx.Home = rest[i + 1]!;
                rest.RemoveRange(i, 2);
                break;
            }
        }

        try
        {
            if (rest.Count == 0) return Usage(ctx, "用法：pwhide <init|set|list|inspect|delete|rename|exec|rotate|harden|doctor|version> [选项]");
            var cmd = rest[0];
            var cmdArgs = rest.Skip(1).ToArray();
            return cmd switch
            {
                "init" => Commands.Init(ctx, cmdArgs),
                "set" => Commands.Set(ctx, cmdArgs),
                "list" => Commands.List(ctx, cmdArgs),
                "inspect" => Commands.Inspect(ctx, cmdArgs),
                "delete" => Commands.Delete(ctx, cmdArgs),
                "rename" => Commands.Rename(ctx, cmdArgs),
                "exec" => ExecCommand.Run(ctx, cmdArgs),
                "rotate" => Commands.Rotate(ctx, cmdArgs),
                "harden" => Commands.Harden(ctx, cmdArgs),
                "_install-staged" => Commands.InstallStaged(ctx, cmdArgs),
                "doctor" => Commands.Doctor(ctx, cmdArgs),
                "version" or "--version" or "-v" => VersionCmd(ctx),
                "help" or "--help" or "-h" => Usage(ctx, ""),
                _ => Usage(ctx, $"未知命令：{cmd}"),
            };
        }
        catch (UsageException e)
        {
            ctx.ErrText.WriteLine($"pwhide: {e.Message}");
            return ExitCodes.Usage;
        }
        catch (VaultException e)
        {
            ctx.ErrText.WriteLine($"pwhide: {e.Message}");
            return ExitCodes.Vault;
        }
        catch (PlaceholderException e)
        {
            // 不变式 I5：错误信息只含条目名/占位符，绝不含解析后的值
            ctx.ErrText.WriteLine($"pwhide: 未知占位符 {e.Token}（{e.Message}）。可用 pwhide list 查询已有条目");
            return ExitCodes.UnknownPlaceholder;
        }
        catch (Exception e)
        {
            // CLI 兜底：任何未预期错误（权限、IO 等）都以明确消息退出，不向用户抛栈、不泄露密文
            ctx.ErrText.WriteLine($"pwhide: {e.Message.Split('\n')[0]}");
            return ExitCodes.Vault;
        }
    }

    private static int Usage(CliContext ctx, string msg)
    {
        if (msg.Length > 0) ctx.ErrText.WriteLine(msg);
        ctx.ErrText.WriteLine("""
            pwhide — 本地密码代填执行器（密码只进进程，不出终端）

            pwhide init [--no-harden]                 初始化 vault（设置主口令）
            pwhide set <名> [-t 类型] [-u 账号] [-T 租户] [-f 字段=值]… [--password-stdin]
                                                    录入/更新条目（密码隐藏输入）
            pwhide list [--json]                      列出条目元数据（不含密文值）
            pwhide inspect <名> [--json]              单条目元数据与可用占位符
            pwhide delete <名> / rename <旧> <新>     管理条目
            pwhide exec [选项] -- <命令…>             填充+执行+脱敏
            pwhide exec [选项] -f <脚本>              脚本 stdin 模式（不落盘）
            pwhide rotate                             更换身份密钥对
            pwhide harden / doctor / version

            exec 选项：--shell auto|bash|sh|pwsh|cmd|none  --env 条目:环境变量(可重复)
                       --timeout 秒(默认120)  --allow-echo(放行回显探测拦截)  --home <目录>
                       --ph #|@（占位符定界符，默认 {{name}}；脚本中 # 与注释冲突时用 @）
            环境变量：PWHIDE_HOME / PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE
            """);
        return ExitCodes.Usage;
    }

    private static int VersionCmd(CliContext ctx)
    {
        var v = typeof(CliRunner).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        ctx.OutText.WriteLine($"pwhide {v} ({System.Runtime.InteropServices.RuntimeInformation.OSDescription} {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})");
        return ExitCodes.Ok;
    }
}

public static class Program
{
    public static int Main(string[] args) => CliRunner.Run(args);
}
