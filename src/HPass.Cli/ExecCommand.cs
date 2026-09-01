using System.Text.RegularExpressions;
using HPass.Core;

namespace HPass.Cli;

/// <summary>
/// hpass exec：解析全部占位符（I2：任一未知则拒跑）→ 解密 → 三种模式执行 → 流式脱敏（I3）→ 透传退出码。
/// 读路径永不提权（I6），且绝不回显解析后的命令（I5）。
/// </summary>
public static partial class ExecCommand
{
    // 环境变量名必须是合法标识符（psi.Environment 赋值非法名会在启动期以错误码 3 失败，应提前以用法错误拒绝）
    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex EnvVarNameRegex();

    public static int Run(CliContext ctx, string[] args)
    {
        string? shell = null, scriptPath = null, scriptText = null;
        int? timeout = null;
        var envSpecs = new List<(string Entry, string Var)>();
        var cmd = new List<string>();
        var restAreCmd = false;   // 首个 -- 或首个位置参数之后，一律视为命令内容（防劫持子命令的 -f/--timeout 等选项）
        var allowEcho = false;

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (restAreCmd) { cmd.Add(a); continue; }
            if (a is "--") { restAreCmd = true; continue; }  // 仅首个 -- 是分隔符，后续 -- 属于命令本身（git log -- path 等）
            switch (a)
            {
                case "--shell":
                    if (++i >= args.Length) throw new UsageException("--shell 需要 shell 名");
                    shell = args[i];
                    break;
                case "--allow-echo":
                    allowEcho = true;
                    break;
                case "--timeout":
                    if (++i >= args.Length || !int.TryParse(args[i], out var t) || t <= 0)
                        throw new UsageException("--timeout 需要正整数秒数");
                    timeout = t;
                    break;
                case "--env":
                    if (++i >= args.Length) throw new UsageException("--env 需要 <条目名>:<环境变量名>");
                    var spec = args[i];
                    var colon = spec.IndexOf(':');
                    if (colon <= 0 || colon == spec.Length - 1)
                        throw new UsageException($"--env 格式应为 条目名:环境变量名（收到 {spec}）");
                    var envVar = spec[(colon + 1)..];
                    if (!EnvVarNameRegex().IsMatch(envVar))
                        throw new UsageException($"--env 环境变量名非法：{envVar}");
                    // 保留变量：注入的值随后会被环境清洗移除，静默违背用户意图
                    if (envVar is "HPASS_PASSPHRASE" or "HPASS_PASSPHRASE_FILE")
                        throw new UsageException($"--env 不能注入保留变量：{envVar}");
                    if (envSpecs.Any(e => e.Var == envVar))
                        throw new UsageException($"--env 重复的环境变量：{envVar}");
                    envSpecs.Add((spec[..colon], envVar));
                    break;
                case "-f" or "--file":
                    if (++i >= args.Length) throw new UsageException("-f 需要 <脚本路径>");
                    scriptPath = args[i];
                    if (!File.Exists(scriptPath)) throw new UsageException($"脚本不存在：{scriptPath}");
                    break;
                default:
                    if (a.StartsWith("--") || (a.StartsWith('-') && a.Length > 1 && char.IsLetter(a[1])))
                        throw new UsageException($"未知的 hpass 选项：{a}（命令自身的选项请放在 -- 之后）");
                    // 首个位置参数：从此停止解析 hpass 选项（exec curl -f url 中的 -f 属于 curl）
                    restAreCmd = true;
                    cmd.Add(a);
                    break;
            }
        }

        if (scriptPath is null && cmd.Count == 0)
            throw new UsageException("缺少要执行的命令（hpass exec [--] <命令…> 或 -f <脚本>）");
        if (scriptPath is not null && cmd.Count > 0)
            throw new UsageException("不能同时指定 -f 脚本与命令参数（多余部分会被忽略，已拒绝）");

        using var vault = Vault.Open(ctx.Home);

        // 脚本只读一次：校验/探测与执行使用同一份内容，消除"检查后文件被改写"的 TOCTOU
        if (scriptPath is not null)
            scriptText = File.ReadAllText(scriptPath);

        // 1) 先收集全部占位符（含 env 注入隐式引用的密码），I2：未知即拒跑，子进程不会启动
        var texts = new List<string>();
        if (scriptText is not null) texts.Add(scriptText);
        else texts.Add(string.Join('\n', cmd));
        var refs = texts.SelectMany(Placeholder.Extract).GroupBy(r => r.Token).Select(g => g.First()).ToList();

        // I2 预校验：条目与字段必须存在。仅查元数据、无需口令，先于解锁给出精确的退出码 4
        foreach (var (entry, field) in refs)
        {
            var token = Vault.Token(entry, field);
            var e = vault.Find(entry)
                ?? throw new PlaceholderException(token, entry, $"条目不存在：{entry}");
            if (field is null && e.Ct.Length == 0)
                throw new PlaceholderException(token, entry, $"{entry} 尚未设置密码");
            if (field is "user" && e.Username is null)
                throw new PlaceholderException(token, entry, $"{entry} 未设置账号（user）");
            if (field is "tenant" && e.Tenant is null)
                throw new PlaceholderException(token, entry, $"{entry} 未设置租户（tenant）");
            if (field is not null and not "user" and not "tenant" && e.Fields.All(f => f.Name != field))
                throw new PlaceholderException(token, entry, $"条目 {entry} 不存在字段 {field}");
        }
        foreach (var (envEntry, _) in envSpecs)
        {
            var e = vault.Find(envEntry);
            if (e is null)
                throw new PlaceholderException(Vault.Token(envEntry, null), envEntry, $"条目不存在：{envEntry}");
            if (e.Ct.Length == 0)
                throw new PlaceholderException(Vault.Token(envEntry, null), envEntry, $"{envEntry} 尚未设置密码");
        }

        // 回显探测防护（全文共现语义）：回显原语 + 密文引用共现即拒绝——组合即可做逐候选字典探测。
        // 密文引用 = 文本中的密文占位符，或 --env 注入（同样激活脱敏规则：echo 候选被替换 ⟺ 候选==密码）
        if (!allowEcho && (refs.Any(NeedsSecret) || envSpecs.Count > 0))
        {
            var rawText = string.Join('\n', texts);
            if (EchoProbe.HasEchoPrimitive(rawText))
            {
                var secretToken = refs.Where(r => NeedsSecret(r)).Select(r => r.Token).FirstOrDefault() ?? "{{条目}}";
                throw new UsageException(EchoProbe.DenyMessage(secretToken));
            }
        }

        var needsSecret = refs.Any(NeedsSecret) || envSpecs.Count > 0;

        if (needsSecret)
            vault.Unlock(Commands.GetPassphrase(ctx, confirm: false));

        var tokenValues = new Dictionary<string, string>();
        var redaction = new Dictionary<string, string>();
        foreach (var (entry, field) in refs)
        {
            var token = Vault.Token(entry, field);
            if (tokenValues.ContainsKey(token)) continue;
            var e = vault.Find(entry)!;
            var value = field switch
            {
                null => vault.DecryptPassword(e),
                "user" => e.Username!,
                "tenant" => e.Tenant!,
                _ => vault.DecryptField(e, field),
            };
            tokenValues[token] = value;
            if (NeedsSecret(new PlaceholderRef(entry, field))) redaction[value] = token;
        }

        // 2) env 注入：条目密码 → 子进程环境变量（argv 干净；注意 /proc/<pid>/environ 对祖先进程可读，见 threat-model）
        var envInject = new Dictionary<string, string>();
        foreach (var (entryName, var) in envSpecs)
        {
            var e = vault.Find(entryName)!;
            var secret = vault.DecryptPassword(e);
            envInject[var] = secret;
            redaction[secret] = Vault.Token(entryName, null);
        }

        // 3) 执行（脚本内容经 stdin 喂给 shell；替换只发生在内存）
        var request = new ExecRequest
        {
            Args = cmd,
            ScriptPath = scriptPath,
            ScriptText = scriptText,
            Shell = shell ?? vault.Config.DefaultShell,
            EnvInject = envInject,
            TimeoutSeconds = timeout ?? Math.Clamp(vault.Config.TimeoutSeconds, 1, 86_400),
            Resolve = token => tokenValues.TryGetValue(token, out var v)
                ? v
                : throw new PlaceholderException(token, token.Trim('{', '}'), "占位符未被预解析（内部错误）"),
            RedactionRules = redaction,
        };

        var result = ShellLauncher.Run(request, ctx.Out, ctx.Err);
        if (result.TimedOut)
            ctx.ErrText.WriteLine($"hpass: 执行超时（{request.TimeoutSeconds}s），已终止进程树");
        // 高频碰撞警告：某密文在输出中出现过多 → 密码疑似为常见语句，替换位置会暴露其内容，建议更换
        foreach (var (token, count) in result.ReplacementCounts)
        {
            if (count > 32)
                ctx.ErrText.WriteLine($"hpass: 警告：{token} 在输出中出现 {count} 次已被脱敏——该密码疑似与常见文本碰撞（既破坏输出，也可能被据此推测），建议更换强密码：hpass set {token.Trim('{', '}').Split('.')[0]}");
        }
        return result.ExitCode;
    }

    /// <summary>密码与自定义字段值为密文；user/tenant 为明文，不参与脱敏。</summary>
    private static bool NeedsSecret(PlaceholderRef r) =>
        r.Field is null || r.Field is not ("user" or "tenant");
}
