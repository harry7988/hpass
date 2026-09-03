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
    /// <summary>Out/Err 是否为进程标准句柄（真实 CLI 运行）。Windows 下按句柄类型选通道：控制台→WriteConsoleW、
    /// 管道→按会话控制台代码页转码、文件→UTF-8；测试传入内存流恒 false → 恒 UTF-8（除非显式配置覆盖）。</summary>
    internal bool OutIsStd { get; init; }
    internal bool ErrIsStd { get; init; }

    private TextWriter? _outText;
    private TextWriter? _errText;
    public TextWriter OutText => _outText ??= new LocalizingWriter(OutputChannel.Create(Out, stderr: false, OutIsStd, Home));
    public TextWriter ErrText => _errText ??= new LocalizingWriter(OutputChannel.Create(Err, stderr: true, ErrIsStd, Home));
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
            // 真实 CLI 运行（未显式传流）时标准句柄标记为 true，Windows 下据此选通道；
            // 测试传入内存流恒 false → UTF-8。通道判定以句柄真实类型为准（见 OutputChannel）
            OutIsStd = stdout is null,
            ErrIsStd = stderr is null,
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

        Loc.Load(ctx.Home);   // 语言解析：PWHIDE_LANG > home/language > 默认 en（输出边界按此翻译）

        try
        {
            if (rest.Count == 0) return Usage(ctx, "用法：pwhide <init|set|list|inspect|delete|rename|exec|verify|rotate|harden|doctor|language|version> [选项]");
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
                "verify" => Commands.Verify(ctx, cmdArgs),
                "rotate" => Commands.Rotate(ctx, cmdArgs),
                "harden" => Commands.Harden(ctx, cmdArgs),
                "_install-staged" => Commands.InstallStaged(ctx, cmdArgs),
                "doctor" => Commands.Doctor(ctx, cmdArgs),
                "keychain" => Commands.KeychainCmd(ctx, cmdArgs),
                "language" => Commands.LanguageCmd(ctx, cmdArgs),
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
            ctx.ErrText.WriteLine(Loc.T($"pwhide: unknown placeholder {e.Token} ({Loc.Tr(e.Message)}). run pwhide list to see existing entries",
                $"pwhide: 未知占位符 {e.Token}（{Loc.Tr(e.Message)}）。可用 pwhide list 查询已有条目"));
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
            pwhide set <名> [-t 类型] [-u 账号] [-T 租户] [-f 字段=值]… [-pf 明文字段=值]… [--password-stdin]
                                                    录入/更新条目（密码隐藏输入）
            pwhide list [--json]                      列出条目元数据（不含密文值）
            pwhide inspect <名> [--json] [--verify]    元数据与占位符；--verify 人工核验（解密显示）
            pwhide delete <名> / rename <旧> <新>     管理条目
            pwhide exec [选项] -- <命令…>             填充+执行+脱敏
            pwhide exec [选项] -f <脚本>              脚本 stdin 模式（不落盘）
            pwhide rotate                             更换身份密钥对
            pwhide verify <名>                        人工核验：解密显示密码/字段（需终端手输主口令）
            pwhide keychain set|clear|status          主口令存入系统钥匙串（配置后 exec 零交互）
            pwhide language en|zh                      界面语言（默认英文；PWHIDE_LANG 可覆盖）
            pwhide harden / doctor / version
            pwhide doctor --output-encoding <auto|utf8|utf16|gbk|json>
                                                    全局手工指定输出编码（乱码兜底）

            exec 选项：--shell auto|bash|sh|pwsh|cmd|none  --env 条目:环境变量(可重复)
                       --timeout 秒(默认120)  --allow-echo(放行回显探测拦截)  --home <目录>
                       --ph #|@（占位符定界符，默认 {{name}}；脚本中 # 与注释冲突时用 @）
                       --verify（执行前人工核对：需交互终端手输主口令，展示解密值并确认）
            环境变量：PWHIDE_HOME / PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE / PWHIDE_OUTPUT_ENCODING / PWHIDE_NO_KEYCHAIN
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
