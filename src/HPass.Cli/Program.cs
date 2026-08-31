using System.Text;
using HPass.Core;

namespace HPass.Cli;

public sealed class CliContext
{
    public required Stream Out { get; init; }
    public required Stream Err { get; init; }
    public required TextReader In { get; init; }
    public bool Interactive { get; init; } = true;
    public string Home { get; set; } = Vault.DefaultHome();

    private TextWriter? _outText;
    private TextWriter? _errText;
    public TextWriter OutText => _outText ??= NewWriter(Out);
    public TextWriter ErrText => _errText ??= NewWriter(Err);

    private static TextWriter NewWriter(Stream s) =>
        new StreamWriter(s, new UTF8Encoding(false), 1024, leaveOpen: true) { AutoFlush = true };
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
        };

        // 全局选项 --home <dir> 可出现在任意位置
        var rest = new List<string>(args);
        for (var i = 0; i < rest.Count - 1; i++)
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
            if (rest.Count == 0) return Usage(ctx, "用法：hpass <init|set|list|inspect|delete|rename|exec|rotate|harden|doctor|version> [选项]");
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
                "doctor" => Commands.Doctor(ctx, cmdArgs),
                "version" or "--version" or "-v" => VersionCmd(ctx),
                "help" or "--help" or "-h" => Usage(ctx, ""),
                _ => Usage(ctx, $"未知命令：{cmd}"),
            };
        }
        catch (UsageException e)
        {
            ctx.ErrText.WriteLine($"hpass: {e.Message}");
            return ExitCodes.Usage;
        }
        catch (VaultException e)
        {
            ctx.ErrText.WriteLine($"hpass: {e.Message}");
            return ExitCodes.Vault;
        }
        catch (PlaceholderException e)
        {
            // 不变式 I5：错误信息只含条目名/占位符，绝不含解析后的值
            ctx.ErrText.WriteLine($"hpass: 未知占位符 {e.Token}（{e.Message}）。可用 hpass list 查询已有条目");
            return ExitCodes.UnknownPlaceholder;
        }
    }

    private static int Usage(CliContext ctx, string msg)
    {
        if (msg.Length > 0) ctx.ErrText.WriteLine(msg);
        ctx.ErrText.WriteLine("""
            hpass — 本地密码代填执行器（密码只进进程，不出终端）

            hpass init [--no-harden]                 初始化 vault（设置主口令）
            hpass set <名> [-t 类型] [-u 账号] [-T 租户] [-f 字段=值]… [--password-stdin]
                                                    录入/更新条目（密码隐藏输入）
            hpass list [--json]                      列出条目元数据（不含密文值）
            hpass inspect <名> [--json]              单条目元数据与可用占位符
            hpass delete <名> / rename <旧> <新>     管理条目
            hpass exec [选项] -- <命令…>             填充+执行+脱敏
            hpass exec [选项] -f <脚本>              脚本 stdin 模式（不落盘）
            hpass rotate                             更换身份密钥对
            hpass harden / doctor / version

            exec 选项：--shell auto|bash|sh|pwsh|cmd|none  --env 条目:环境变量(可重复)
                       --timeout 秒(默认120)  --home <目录>
            环境变量：HPASS_HOME / HPASS_PASSPHRASE / HPASS_PASSPHRASE_FILE
            """);
        return ExitCodes.Usage;
    }

    private static int VersionCmd(CliContext ctx)
    {
        var v = typeof(CliRunner).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        ctx.OutText.WriteLine($"hpass {v} ({System.Runtime.InteropServices.RuntimeInformation.OSDescription} {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})");
        return ExitCodes.Ok;
    }
}

public static class Program
{
    public static int Main(string[] args) => CliRunner.Run(args);
}
