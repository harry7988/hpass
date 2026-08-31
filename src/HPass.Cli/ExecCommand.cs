using HPass.Core;

namespace HPass.Cli;

/// <summary>
/// hpass exec：解析全部占位符（I2：任一未知则拒跑）→ 解密 → 三种模式执行 → 流式脱敏（I3）→ 透传退出码。
/// 读路径永不提权（I6），且绝不回显解析后的命令（I5）。
/// </summary>
public static class ExecCommand
{
    public static int Run(CliContext ctx, string[] args)
    {
        string? shell = null, scriptPath = null;
        int? timeout = null;
        var envSpecs = new List<(string Entry, string Var)>();
        var cmd = new List<string>();
        var inCmd = false;

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (inCmd || a is "--") { if (a is not "--") cmd.Add(a); else inCmd = true; continue; }
            switch (a)
            {
                case "--shell":
                    if (++i >= args.Length) throw new UsageException("--shell 需要 shell 名");
                    shell = args[i];
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
                    envSpecs.Add((spec[..colon], spec[(colon + 1)..]));
                    break;
                case "-f" or "--file":
                    if (++i >= args.Length) throw new UsageException("-f 需要 <脚本路径>");
                    scriptPath = args[i];
                    if (!File.Exists(scriptPath)) throw new UsageException($"脚本不存在：{scriptPath}");
                    break;
                default:
                    cmd.Add(a);
                    break;
            }
        }

        using var vault = Vault.Open(ctx.Home);

        // 1) 先收集全部占位符（含 env 注入隐式引用的密码），I2：未知即拒跑，子进程不会启动
        var texts = new List<string>();
        if (scriptPath is not null) texts.Add(File.ReadAllText(scriptPath));
        else if (cmd.Count > 0) texts.Add(string.Join('\n', cmd));
        var refs = texts.SelectMany(Placeholder.Extract).GroupBy(r => r.Token).Select(g => g.First()).ToList();

        // I2 预校验：条目与字段必须存在。仅查元数据、无需口令，先于解锁给出精确的退出码 4
        foreach (var (entry, field) in refs)
        {
            var token = Vault.Token(entry, field);
            var e = vault.Find(entry)
                ?? throw new PlaceholderException(token, entry, $"条目不存在：{entry}");
            if (field is "user" && e.Username is null)
                throw new PlaceholderException(token, entry, $"{entry} 未设置账号（user）");
            if (field is "tenant" && e.Tenant is null)
                throw new PlaceholderException(token, entry, $"{entry} 未设置租户（tenant）");
            if (field is not null and not "user" and not "tenant" && e.Fields.All(f => f.Name != field))
                throw new PlaceholderException(token, entry, $"条目 {entry} 不存在字段 {field}");
        }
        foreach (var (envEntry, _) in envSpecs)
        {
            if (vault.Find(envEntry) is null)
                throw new PlaceholderException(Vault.Token(envEntry, null), envEntry, $"条目不存在：{envEntry}");
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
            var e = vault.Find(entry)
                ?? throw new PlaceholderException(token, entry, $"条目不存在：{entry}");
            var value = field switch
            {
                null => vault.DecryptPassword(e),
                "user" => e.Username ?? throw new PlaceholderException(token, entry, $"{entry} 未设置账号（user）"),
                "tenant" => e.Tenant ?? throw new PlaceholderException(token, entry, $"{entry} 未设置租户（tenant）"),
                _ => vault.DecryptField(e, field),
            };
            tokenValues[token] = value;
            if (NeedsSecret(new PlaceholderRef(entry, field))) redaction[value] = token;
        }

        // 2) env 注入：条目密码 → 子进程环境变量（argv 干净，ps 不可见）
        var envInject = new Dictionary<string, string>();
        foreach (var (entryName, var) in envSpecs)
        {
            var e = vault.Find(entryName)
                ?? throw new PlaceholderException(Vault.Token(entryName, null), entryName, $"条目不存在：{entryName}");
            var secret = vault.DecryptPassword(e);
            envInject[var] = secret;
            redaction[secret] = Vault.Token(entryName, null);
        }

        // 3) 执行（脚本模式从文件重读原文，经 stdin 喂给 shell；替换只发生在内存）
        var request = new ExecRequest
        {
            Args = cmd,
            ScriptPath = scriptPath,
            Shell = shell ?? vault.Config.DefaultShell,
            EnvInject = envInject,
            TimeoutSeconds = timeout ?? vault.Config.TimeoutSeconds,
            Resolve = token => tokenValues.TryGetValue(token, out var v)
                ? v
                : throw new PlaceholderException(token, token.Trim('{', '}'), "占位符未被预解析（内部错误）"),
            RedactionRules = redaction,
        };

        var result = ShellLauncher.Run(request, ctx.Out, ctx.Err);
        if (result.TimedOut)
            ctx.ErrText.WriteLine($"hpass: 执行超时（{request.TimeoutSeconds}s），已终止进程树");
        return result.ExitCode;
    }

    /// <summary>密码与自定义字段值为密文；user/tenant 为明文，不参与脱敏。</summary>
    private static bool NeedsSecret(PlaceholderRef r) =>
        r.Field is null || r.Field is not ("user" or "tenant");
}
