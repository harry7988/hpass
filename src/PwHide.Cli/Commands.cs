using System.Text.Json;
using PwHide.Core;

namespace PwHide.Cli;

public static class Commands
{
    internal static string GetPassphrase(CliContext ctx, bool confirm)
    {
        var env = Environment.GetEnvironmentVariable("PWHIDE_PASSPHRASE");
        if (!string.IsNullOrEmpty(env)) return CheckLength(env);

        var file = Environment.GetEnvironmentVariable("PWHIDE_PASSPHRASE_FILE");
        if (!string.IsNullOrEmpty(file) && File.Exists(file))
        {
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                var mode = File.GetUnixFileMode(file);
                if (mode.HasFlag(UnixFileMode.GroupRead) || mode.HasFlag(UnixFileMode.OtherRead))
                    ctx.ErrText.WriteLine($"pwhide: 警告：口令文件 {file} 对组/其他用户可读（主口令泄露=库可离线穷举），建议 chmod 600");
            }
            return CheckLength(File.ReadAllText(file).TrimEnd('\r', '\n'));
        }

        // 系统钥匙串：配置一次（pwhide keychain set）后 exec/set 全自动，非交互（AI 调用）也可用。
        // 口令只在本进程内解密使用，永不回显/记录；PWHIDE_NO_KEYCHAIN=1 可跳过
        if (Environment.GetEnvironmentVariable("PWHIDE_NO_KEYCHAIN") != "1"
            && Keychain.IsSupported && Keychain.TryGet(ctx.Home, out var fromKeychain))
        {
            return CheckLength(fromKeychain);
        }

        if (!ctx.Interactive)
            throw new VaultException("非交互环境需要解锁：请设置 PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE，或先运行 pwhide keychain set 存入系统钥匙串");

        if (Console.IsInputRedirected)
            throw new UsageException("stdin 被重定向时无法进行交互口令输入：请设置 PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE，或先运行 pwhide keychain set");
        using var hidden = HiddenInput.Begin(ctx.In, ctx.Interactive);   // 先隐藏后提示：消除提示符与 stty 生效间的回显竞态
        ctx.ErrText.Write("主口令: ");
        var first = HiddenInput.ReadLine(hidden, ctx.In);
        first = CheckLength(first);
        if (first.Length < 8) throw new VaultException("口令至少需要 8 个字符");
        if (confirm)
        {
            ctx.ErrText.Write("再次确认: ");
            var second = HiddenInput.ReadLine(hidden, ctx.In);
            if (first != second) throw new VaultException("两次输入不一致");
        }
        return first;
    }

    private static string CheckLength(string passphrase)
    {
        if (passphrase.Length > 1024)
            throw new VaultException("口令过长（>1024 字符），拒绝使用");
        if (passphrase.Length < 8)
            throw new VaultException("口令至少需要 8 个字符（env/文件方式与交互输入执行同一标准）");
        return passphrase;
    }

    public static int Init(CliContext ctx, string[] args)
    {
        var noHarden = args.Contains("--no-harden");
        // 持锁创建 + 二次确认：两个并发 init 都过 Exists 检查会交错写出失配的 master.key/vault.json（不可恢复）
        using var _initLock = Vault.FileLock.Acquire(ctx.Home);
        if (Vault.Exists(ctx.Home))
            throw new VaultException($"vault 已存在（{ctx.Home}）。如需重置请先手动删除该目录");

        var passphrase = GetPassphrase(ctx, confirm: true);
        using var vault = Vault.Create(ctx.Home, passphrase);
        ctx.OutText.WriteLine($"已初始化：{ctx.Home}");
        ctx.OutText.WriteLine(Loc.T("next: pwhide keychain set (zero interaction) | pwhide set <name> (first credential)",
            "下一步：pwhide keychain set（免交互）| pwhide set <名>（录入第一条凭据）"));
        ctx.OutText.WriteLine(noHarden || !OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS() && !OperatingSystem.IsWindows()
            ? "文件保护：基础模式（目录 700 / 文件 600）。可随时运行 pwhide harden 升级为管理员写保护"
            : "文件保护：基础模式（目录 700 / 文件 600）。可运行 pwhide harden 启用管理员写保护（仅整体覆盖）");
        return ExitCodes.Ok;
    }

    public static int Set(CliContext ctx, string[] args)
    {
        string? name = null, type = null, username = null, tenant = null, password = null;
        var fields = new List<(string Name, string? Value, bool Plain)>();
        var passwordStdin = false;
        var forceWeak = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-t": type = Value(args, ref i, "-t 需要 <类型>"); break;
                case "-u": username = Value(args, ref i, "-u 需要 <账号>"); break;
                case "-T": tenant = Value(args, ref i, "-T 需要 <租户>"); break;
                case "-f":
                    var spec = Value(args, ref i, "-f 需要 <字段名=值> 或 <字段名>（隐藏输入）");
                    var eq = spec.IndexOf('=');
                    fields.Add(eq < 0 ? (spec, null, false) : (spec[..eq], spec[(eq + 1)..], false));
                    break;
                case "-pf" or "--plain-field":
                    // 明文字段（非敏感配置：IP/协议/端口等）：值进 list --json 元数据，AI 可见，填充无需解锁
                    var pspec = Value(args, ref i, "-pf 需要 <字段名=值>（明文字段必须显式给值）");
                    var peq = pspec.IndexOf('=');
                    if (peq <= 0 || peq == pspec.Length - 1)
                        throw new UsageException($"-pf 需要 <字段名=值>（收到 {pspec}）");
                    fields.Add((pspec[..peq], pspec[(peq + 1)..], true));
                    break;
                case "--password-stdin": passwordStdin = true; break;
                case "--force-weak": forceWeak = true; break;
                default:
                    if (name is null && !args[i].StartsWith('-')) name = args[i];
                    else throw new UsageException($"set：无法识别的参数 {args[i]}");
                    break;
            }
        }
        if (fields.Select(f => f.Name).GroupBy(n => n).Any(g => g.Count() > 1))
            throw new UsageException("同一字段名不能重复指定（-f 与 -pf 同名也不行：加密/明文二选一）");
        if (name is null) throw new UsageException("用法：pwhide set <名> [-t 类型] [-u 账号] [-T 租户] [-f 字段=值]… [-pf 明文字段=值]… [--password-stdin] [--force-weak]");

        if (passwordStdin)
        {
            password = ctx.In.ReadLine() ?? "";
            // 清除首尾空白：粘贴/管道极易带入换行与空格，注入后与预期不符且脱敏按原值匹配
            password = password.Trim();
            if (password.Length == 0) throw new UsageException("--password-stdin：未从 stdin 读到密码（或内容全是空白）");
        }
        else if (ctx.Interactive)
        {
            using var hidden = HiddenInput.Begin(ctx.In, ctx.Interactive);   // 先隐藏后提示
            ctx.ErrText.Write($"密码（{name}）: ");
            password = HiddenInput.ReadLine(hidden, ctx.In);
            password = password.Trim();
            ctx.ErrText.Write("再次确认: ");
            if (HiddenInput.ReadLine(hidden, ctx.In).Trim() != password)
                throw new VaultException("两次输入不一致");
        }
        else if (Console.IsInputRedirected)
            throw new UsageException("检测到 stdin 被重定向但未指定 --password-stdin：请改用 pwhide set <名> --password-stdin < 密码文件（交互隐藏输入需要真实终端）");
        else throw new UsageException("非交互环境请使用 --password-stdin 从 stdin 提供密码（禁止命令行明文传密码）");

        if (password.Length == 0)
            throw new UsageException("密码不能为空");

        // 弱密文拦截：密码=常见语句时会与正常输出碰撞，且"被替换的位置"会直接暴露密码内容
        if (!forceWeak && WeakSecret.Check(password) is { } reason)
            throw new UsageException(Loc.T($"refusing weak password: {Loc.Tr(reason)}. append --force-weak to override at your own risk (common texts in output would be massively mis-redacted and could be inferred)", $"拒绝保存弱密码：{reason}。如确要使用请追加 --force-weak（风险自担：输出中的常见文本会被大面积误替换为占位符，并可被据此推测）"));

        // 先取锁再读：Open 在锁前会读到陈旧快照，并发写覆盖会丢更新（last-writer-wins）
        using var _lock = Vault.FileLock.Acquire(ctx.Home);
        using var vault = Vault.Open(ctx.Home);
        vault.Unlock(GetPassphrase(ctx, confirm: false));
        var entry = vault.GetOrAdd(name, type, username, tenant);
        vault.SetPassword(entry, password);
        foreach (var (fname, fvalue, plainFlag) in fields)
        {
            string value;
            if (fvalue is not null) value = fvalue;
            else if (ctx.Interactive)
            {
                using var hidden = HiddenInput.Begin(ctx.In, ctx.Interactive);
                ctx.ErrText.Write($"字段 {fname} 的值: ");
                value = HiddenInput.ReadLine(hidden, ctx.In);
            }
            else throw new UsageException($"非交互环境请用 -f {fname}=<值> 提供字段值");

            // 交互式逐字段询问是否加密（-pf 已显式选明文，不再问）。
            // 回车取默认：形似敏感（key/token/secret…）默认加密，其余（IP/协议/端口等）默认明文。
            // stdin 被重定向（AI/脚本场景，无人应答）时跳过询问：-f 一律加密（安全默认，
            //  防止 EOF 空回答静默把字段降级为明文；要明文请显式 -pf）
            var encrypt = plainFlag ? false : true;
            if (!plainFlag && ctx.Interactive)
            {
                var sensitive = LooksSensitive(fname);
                ctx.ErrText.Write($"字段 {fname} 是否敏感、需要加密存储？[{(sensitive ? "Y/n" : "y/N")}] ");
                var ans = (ctx.In.ReadLine() ?? "").Trim().ToLowerInvariant();
                // 空 answers 的安全默认：真终端回车 → 按字段名启发式；
                // 管道 EOF（AI/脚本无人应答）→ 一律加密（防止 -f 静默降级为明文）
                encrypt = ans.Length == 0 ? (sensitive || Console.IsInputRedirected) : ans is "y" or "yes";
            }

            value = value.Trim();
            if (value.Length == 0)
                throw new UsageException($"字段 {fname} 的值不能为空（首尾空白已清除后仍为空）");

            if (!encrypt)
            {
                vault.SetPlainField(entry, fname, value);
                continue;
            }
            // 敏感字段名经 argv 传值会进 shell history/ps：提醒改用交互隐藏输入
            if (fvalue is not null && LooksSensitive(fname))
                ctx.ErrText.WriteLine($"pwhide: 警告：字段 {fname} 形似敏感字段，命令行传值会进入 shell history——建议改用交互隐藏输入（pwhide set … -f {fname}）");
            // 加密字段值（如 host=127.0.0.1 这类常见值）不阻断，仅警告：密文注入可能与正常输出碰撞（明文字段无此问题）
            if (WeakSecret.Check(value) is { } fieldReason)
                ctx.ErrText.WriteLine(Loc.T($"pwhide: warning: value of field {fname}{Loc.Tr(fieldReason)}; when injected as a secret it may collide with normal output, please double-check", $"pwhide: 警告：字段 {fname} 的值{fieldReason}；作为密文注入时可能与正常输出碰撞，请确认"));
            vault.SetField(entry, fname, value);
        }
        vault.Save();
        ctx.OutText.WriteLine($"已保存条目 {name}（{vault.Data.Entries.Count} 个条目）");
        ctx.OutText.WriteLine(Loc.T($"next: pwhide inspect {name} (placeholders) | use {{{{{name}}}}} in pwhide exec",
            $"下一步：pwhide inspect {name}（查看占位符）| 在 pwhide exec 中使用 {{{{{name}}}}}"));
        return ExitCodes.Ok;
    }

    // ---------- --verify 人类验证通道 ----------
    // 测试钩子：模拟"真实交互终端"（CI 无法提供 TTY；用完必须置回 null）
    internal static Func<bool>? HookIsHumanTerminal;

    /// <summary>--verify 的硬性前提：真实交互终端。stdin 非终端或 stdout 被重定向（管道/文件/日志采集）一律拒绝——密文绝不进入管道与 AI 上下文。</summary>
    internal static bool IsHumanTerminal(CliContext ctx) =>
        HookIsHumanTerminal is not null ? HookIsHumanTerminal()
        : ctx.Interactive && !Console.IsInputRedirected && !Console.IsOutputRedirected;

    /// <summary>--verify 强制手输主口令：忽略 env/文件/钥匙串（在场人类证明）。口令错误由随后 Unlock 以退出码 3 暴露。</summary>
    internal static string PassphraseForcedInteractive(CliContext ctx)
    {
        if (!IsHumanTerminal(ctx))
            throw new UsageException("--verify 需要在真实交互终端运行并手动输入主口令（当前为非交互或 stdin/stdout 被重定向——这是防止密文进入 AI 上下文/日志/管道的硬性限制）");
        using var hidden = HiddenInput.Begin(ctx.In, ctx.Interactive);
        ctx.ErrText.Write("主口令（--verify 手输）: ");
        return CheckLength(HiddenInput.ReadLine(hidden, ctx.In));
    }

    /// <summary>终端确认提问（仅 --verify 流程使用），默认否。</summary>
    internal static bool Confirm(CliContext ctx, string question)
    {
        ctx.ErrText.Write(question + " [y/N] ");
        var ans = (ctx.In.ReadLine() ?? "").Trim().ToLowerInvariant();
        return ans is "y" or "yes";
    }

    private static bool LooksSensitive(string fieldName)
    {
        foreach (var marker in new[] { "key", "token", "secret", "pin", "password", "passwd", "pwd" })
            if (fieldName.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string HiddenInputWithPrompt(CliContext ctx, string prompt)
    {
        using var hidden = HiddenInput.Begin(ctx.In, ctx.Interactive);
        ctx.ErrText.Write(prompt);
        return HiddenInput.ReadLine(hidden, ctx.In);
    }

    public static int List(CliContext ctx, string[] args)
    {
        var json = args.Contains("--json");
        using var vault = Vault.Open(ctx.Home);
        var metas = vault.Data.Entries.Select(e => ToMeta(e)).ToList();
        if (json)
        {
            ctx.OutText.WriteLine(JsonSerializer.Serialize(metas, PwHideJsonContext.Default.ListEntryMeta));
            return ExitCodes.Ok;
        }
        if (metas.Count == 0) { ctx.OutText.WriteLine("（vault 为空，用 pwhide set <名> 录入）"); return ExitCodes.Ok; }
        ctx.OutText.WriteLine(Loc.T($"{"name",-16}{"type",-10}{"user",-14}{"tenant",-10}{"pw",-4}plain fields / encrypted fields", $"{"名称",-16}{"类型",-10}{"账号",-14}{"租户",-10}{"密码",-6}字段（明文/加密）"));
        foreach (var m in metas)
        {
            var entry = vault.Data.Entries.First(e => e.Name == m.Name);
            var plain = string.Join(",", entry.PlainFields.Select(kv => $"{kv.Key}={kv.Value}"));
            var enc = string.Join(",", m.Fields);
            var fieldsPart = plain.Length > 0 && enc.Length > 0 ? plain + " / " + enc : plain + enc;
            ctx.OutText.WriteLine($"{m.Name,-16}{m.Type ?? "-",-10}{m.Username ?? "-",-14}{m.Tenant ?? "-",-10}{(m.HasPassword ? "✓" : "-"),-4}{fieldsPart}");
        }
        return ExitCodes.Ok;
    }

    public static int Inspect(CliContext ctx, string[] args)
    {
        var verify = args.Contains("--verify");
        var json = args.Contains("--json");
        if (verify && json)
            throw new UsageException("--verify 与 --json 不能同时使用（--verify 为人类交互验证通道，输出为终端文本）");
        var name = args.FirstOrDefault(a => !a.StartsWith('-'))
            ?? throw new UsageException("用法：pwhide inspect <名> [--json] [--verify（人工核验：需交互终端手输主口令，解密显示密码与字段）]");
        using var vault = Vault.Open(ctx.Home);
        var entry = vault.Find(name) ?? throw new VaultException($"条目不存在：{name}");
        var meta = ToMeta(entry);
        if (verify)
            return VerifyDisplay(ctx, vault, entry);
        if (json)
            ctx.OutText.WriteLine(JsonSerializer.Serialize(meta, PwHideJsonContext.Default.EntryMeta));
        else
        {
            ctx.OutText.WriteLine(Loc.T($"name: {meta.Name}", $"名称: {meta.Name}"));
            ctx.OutText.WriteLine(Loc.T($"type: {meta.Type ?? "-"}    user: {meta.Username ?? "-"}    tenant: {meta.Tenant ?? "-"}", $"类型: {meta.Type ?? "-"}    账号: {meta.Username ?? "-"}    租户: {meta.Tenant ?? "-"}"));
            ctx.OutText.WriteLine(Loc.T($"password: {(meta.HasPassword ? $"set (injected only via {{{{{meta.Name}}}}})" : "(not set)")}", $"密码: {(meta.HasPassword ? "已设置（只能经 {{" + meta.Name + "}} 注入）" : "未设置")}"));
            if (meta.PlainFields.Count > 0)
                ctx.OutText.WriteLine(Loc.T("plain fields (non-sensitive, visible in metadata): ", "明文字段（非敏感，元数据可见）: ") + string.Join("  ", meta.PlainFields.Select(kv => $"{kv.Key}={kv.Value}")));
            ctx.OutText.WriteLine("可用占位符:");
            foreach (var p in meta.Placeholders) ctx.OutText.WriteLine($"  {p}");
        }
        return ExitCodes.Ok;
    }

    internal static EntryMeta ToMeta(VaultEntry e)
    {
        var meta = new EntryMeta
        {
            Name = e.Name,
            Type = e.Type,
            Username = e.Username,
            Tenant = e.Tenant,
            HasPassword = e.Ct.Length > 0,
            Fields = e.Fields.Select(f => f.Name).ToList(),
            UpdatedAt = e.UpdatedAt,
        };
        meta.Placeholders.Add(Vault.Token(e.Name, null));
        if (e.Username is not null) meta.Placeholders.Add(Vault.Token(e.Name, "user"));
        if (e.Tenant is not null) meta.Placeholders.Add(Vault.Token(e.Name, "tenant"));
        foreach (var f in e.Fields) meta.Placeholders.Add(Vault.Token(e.Name, f.Name));
        foreach (var n in e.PlainFields.Keys) meta.Placeholders.Add(Vault.Token(e.Name, n));
        meta.PlainFields = e.PlainFields;
        return meta;
    }

    public static int Delete(CliContext ctx, string[] args)
    {
        var name = args.FirstOrDefault(a => !a.StartsWith('-')) ?? throw new UsageException("用法：pwhide delete <名>");
        // 先取锁再读：Open 在锁前会读到陈旧快照，并发写覆盖会丢更新（last-writer-wins）
        using var _lock = Vault.FileLock.Acquire(ctx.Home);
        using var vault = Vault.Open(ctx.Home);
        if (!vault.Delete(name)) throw new VaultException($"条目不存在：{name}");
        vault.Save();
        ctx.OutText.WriteLine($"已删除 {name}");
        return ExitCodes.Ok;
    }

    public static int Rename(CliContext ctx, string[] args)
    {
        var positional = args.Where(a => !a.StartsWith('-')).ToList();
        if (positional.Count != 2) throw new UsageException("用法：pwhide rename <旧名> <新名>");
        // 先取锁再读：Open 在锁前会读到陈旧快照，并发写覆盖会丢更新（last-writer-wins）
        using var _lock = Vault.FileLock.Acquire(ctx.Home);
        using var vault = Vault.Open(ctx.Home);
        vault.Unlock(GetPassphrase(ctx, confirm: false));
        vault.Rename(positional[0], positional[1]);
        vault.Save();
        ctx.OutText.WriteLine($"已重命名 {positional[0]} → {positional[1]}");
        ctx.OutText.WriteLine(Loc.T($"placeholders are now {{{{{positional[1]}}}}} / {{{{{positional[1]}}}}}.field",
            $"占位符现为 {{{{{positional[1]}}}}} / {{{{{positional[1]}}}}}.字段"));
        ctx.OutText.WriteLine(Loc.T($"placeholders are now {{{{{positional[1]}}}}} / {{{{{positional[1]}}}}}.field", $"占位符现为 {{{{{positional[1]}}}}} / {{{{{positional[1]}}}}}.字段"));
        return ExitCodes.Ok;
    }

    public static int Rotate(CliContext ctx, string[] args)
    {
        // 先取锁再读：Open 在锁前会读到陈旧快照，并发写覆盖会丢更新（last-writer-wins）
        using var _lock = Vault.FileLock.Acquire(ctx.Home);
        using var vault = Vault.Open(ctx.Home);
        var passphrase = GetPassphrase(ctx, confirm: false);
        vault.Unlock(passphrase);
        vault.Rotate(passphrase);
        ctx.OutText.WriteLine("已更换身份密钥对（DEK 未变，条目无需重加密）");
        return ExitCodes.Ok;
    }

    /// <summary>
    /// 特权加固（M3 / PLAN §5.1）：密码文件只可整体覆盖。
    /// - root（sudo 重拉）→ 管理员级：root 属主 440 + schg/chattr +i；
    /// - macOS 普通用户 → 用户级 uchg 不可变（属主可清，set 等命令会自动清/复加）；
    /// - Linux 普通用户 → 无法 chattr：交互模式经 sudo 重拉自身，非交互打印指引。
    /// </summary>
    public static int Harden(CliContext ctx, string[] args)
    {
        if (!Vault.Exists(ctx.Home))
            throw new VaultException($"未找到 vault（{ctx.Home}），请先 pwhide init");

        if (!Hardening.Unix)
        {
            ctx.OutText.WriteLine("Windows 平台：请以管理员运行以下命令设置 ACL（用户只读，Administrators/SYSTEM 完全控制）：");
            ctx.OutText.WriteLine($"  icacls \"{ctx.Home}\" /inheritance:r /grant:r Administrators:F /grant:r SYSTEM:F /grant:r {Environment.UserName}:RX");
            return ExitCodes.Ok;
        }

        if (Hardening.IsRoot())
        {
            Hardening.ApplyRootOwnership(ctx.Home);
            ctx.OutText.WriteLine("已加固（管理员级）：root 属主 + 不可变标志（schg / chattr +i），密码文件只可整体覆盖。");
            ctx.OutText.WriteLine($"exec 读路径无需提权；后续 set/delete/rename/rotate 会自动经 sudo 搬运安装（也可手动：sudo pwhide --home {Hardening.Q(ctx.Home)} …）");
            return ExitCodes.Ok;
        }

        if (OperatingSystem.IsMacOS())
        {
            foreach (var f in Hardening.CoreFiles)
                Hardening.SetImmutable(Path.Combine(ctx.Home, f));
            ctx.OutText.WriteLine("已加固（用户级 uchg 不可变）：文件只能整体覆盖（pwhide 内部自动清/复加）。");
            ctx.OutText.WriteLine($"升级为管理员级（root 属主 + schg）：sudo pwhide --home {Hardening.Q(ctx.Home)} harden");
            return ExitCodes.Ok;
        }

        // Linux 普通用户：chattr 需提权
        if (ctx.Interactive && !Console.IsInputRedirected)
        {
            var exe = Environment.ProcessPath
                ?? throw new VaultException("无法定位 pwhide 可执行文件");
            // 交互输密码的 sudo 一律用严格信任档（二进制+目录链全 root 属主）：
            // 用户属主路径（~/.local/bin 等）下同 UID 替换木马会借"例行加固提示"获得密码认证过的 root 执行
            if (!Hardening.IsTrustedBinaryPath(exe, requireRootOwner: true))
            {
                ctx.ErrText.WriteLine($"pwhide: 二进制位于不受信任路径（{exe}，用户可写位置），不自动提权。请手动执行：sudo pwhide --home {Hardening.Q(ctx.Home)} harden（请亲眼核对 sudo 目标）");
                return ExitCodes.Vault;
            }
            var sudo = Hardening.SudoPath();
            if (sudo is null)
            {
                ctx.ErrText.WriteLine($"pwhide: 未找到 sudo（/usr/bin/sudo）。请手动执行：sudo pwhide --home {Hardening.Q(ctx.Home)} harden");
                return ExitCodes.Vault;
            }
            ctx.OutText.WriteLine("将以 sudo 重新执行加固（root 属主 + chattr +i）…");
            Console.Error.WriteLine(Loc.Tr("pwhide: 即将请求 sudo 密码执行加固（目标为上述 vault 目录）"));
            var (code, _, _) = Hardening.RunCaptureEx(sudo, ["--", exe, "--home", ctx.Home, "harden"], timeoutMs: 300_000);
            return code == 0 ? ExitCodes.Ok : ExitCodes.Vault;
        }
        // 非交互（AI/CI 常态）：先尝试免密 sudo（与安装路径对齐），失败必须返回非 0——
        // 退出码 0 会让 `pwhide harden && …` 得到"加固已启用"的假信号
        if (Environment.GetEnvironmentVariable("PWHIDE_NO_SUDO") != "1")
        {
            var sudoN = Hardening.SudoPath();
            if (sudoN is not null)
            {
                var exeN = Environment.ProcessPath;
                if (exeN is not null && Hardening.IsTrustedBinaryPath(exeN))
                {
                    var (codeN, _, _) = Hardening.RunCaptureEx(sudoN, ["-n", "--", exeN, "--home", ctx.Home, "harden"], timeoutMs: 120_000);
                    if (codeN == 0)
                    {
                        ctx.OutText.WriteLine("已加固（管理员级，经 sudo -n）：root 属主 + 不可变标志，密码文件只可整体覆盖。");
                        return ExitCodes.Ok;
                    }
                }
            }
        }
        ctx.ErrText.WriteLine($"pwhide: 非交互环境未能完成加固（Linux 普通用户无法 chattr 且 sudo -n 不可用）。请手动运行：sudo pwhide --home {Hardening.Q(ctx.Home)} harden");
        return ExitCodes.Vault;
    }

    /// <summary>内部命令：提权子进程的"密文搬运"（清保护 → 原子覆盖 → 恢复 root 属主与保护）。仅在提权中使用。</summary>
    public static int InstallStaged(CliContext ctx, string[] args)
    {
        // --child-install：由自动提权父进程传入（经 argv——sudo env_reset 不剥离参数）；
        // 写锁由父进程持有（临界区保护不变），子进程跳过重复获取以免 flock 自锁
        var childInstall = args.Contains("--child-install");
        args = args.Where(a => a != "--child-install").ToArray();
        if (args.Length != 2) throw new UsageException("用法（内部）：pwhide _install-staged [--child-install] <暂存文件> <最终路径>");
        var staging = Path.GetFullPath(args[0]);
        var final = Path.GetFullPath(args[1]);
        var stagingRoot = Path.GetFullPath(Path.Combine(ctx.Home, "run", "staging"));
        if (!staging.StartsWith(stagingRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new UsageException($"安全限制：暂存文件必须位于 {stagingRoot} 之下");
        var allowed = new[] { "vault.json", "master.key", "config.json" }
            .Select(n => Path.GetFullPath(Path.Combine(ctx.Home, n)));
        if (!allowed.Contains(final))
            throw new UsageException("安全限制：最终路径只能是 vault.json / master.key / config.json");

        // 手动恢复路径持锁（与并发 set 竞争同一 final 会丢更新）；自动提权子进程（--child-install）跳过
        using var _lock = childInstall ? null : Vault.FileLock.Acquire(ctx.Home);

        var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
        if (Hardening.IsRoot())
        {
            // root 侧不信任 argv 的 --home：必须已是真实 pwhide 库（两文件俱在）、
            // 属主==调用用户、非符号链接、目录非 group/other 可写（挡住 /tmp 等粘滞目录伪造）
            if (!Vault.Exists(ctx.Home))
                throw new UsageException($"安全限制：{ctx.Home} 不是已初始化的 pwhide 库，拒绝在此执行特权安装");
            // 注：不校验 home 属主——加固态 home 本就是 root 属主（ApplyRootOwnership），属主检查会误杀正常流程；
            // 防伪造由 Exists + 非链接 + 非 group/other 可写 + staging 属主校验共同承担
            if (Hardening.IsSymbolicLink(ctx.Home))
                throw new UsageException($"安全限制：home 是符号链接，拒绝特权安装：{ctx.Home}");
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                var homeMode = File.GetUnixFileMode(ctx.Home);
                if (homeMode.HasFlag(UnixFileMode.GroupWrite) || homeMode.HasFlag(UnixFileMode.OtherWrite))
                    throw new UsageException($"安全限制：home 目录对组/其他用户可写（{ctx.Home}），拒绝特权安装");
            }
            // root 搬运时校验暂存属主 = 调用用户（SUDO_USER），收窄跨用户伪造 staging 的面
            if (!string.IsNullOrEmpty(sudoUser))
            {
                var owner = Hardening.FileOwnerUid(staging);
                var caller = Hardening.UserIdOf(sudoUser);
                if (owner >= 0 && caller >= 0 && owner != caller)
                    throw new UsageException($"安全限制：暂存文件属主（uid {owner}）与调用用户（uid {caller}）不一致，拒绝安装");
            }
            // root 首次创建的 lock 若留在 root 名下，用户侧从此 EACCES——归还给调用用户。
            // -h（lchown）+ 链接拒绝：锁路径被换成符号链接时绝不把特权 chown 作用到任意文件（提权原语）
            var lockPath = Path.Combine(ctx.Home, "run", "lock");
            if (File.Exists(lockPath) && !string.IsNullOrEmpty(sudoUser))
            {
                if (Hardening.IsSymbolicLink(lockPath))
                    throw new VaultException($"run/lock 是符号链接（可能的攻击），拒绝执行：{lockPath}");
                _ = Hardening.Sh($"chown -h {Hardening.Q(sudoUser)} {Hardening.Q(lockPath)} 2>/dev/null || true");
            }
        }
        SecureFile.InstallStagedDirect(staging, final);
        return ExitCodes.Ok;
    }

    public static int Doctor(CliContext ctx, string[] args)
    {
        // --output-encoding <auto|utf8|utf16|gbk|json>：全局手工指定输出编码（兜底方案，防终端/管道解码不匹配）
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--output-encoding")
            {
                if (++i >= args.Length) throw new UsageException("--output-encoding 需要 <auto|utf8|utf16|gbk|json>");
                var mode = OutputChannel.NormalizeOverride(args[i])
                    ?? throw new UsageException($"无效的输出编码：{args[i]}（可用 auto|utf8|utf16|gbk|json；json = 非 ASCII 转义为 \\uXXXX，任何终端可读）");
                Directory.CreateDirectory(ctx.Home);
                var file = Path.Combine(ctx.Home, OutputChannel.FileName);
                File.WriteAllText(file, mode);
                ctx.OutText.WriteLine($"输出编码 : 已全局指定为 {mode}（{file}，对所有 pwhide 命令生效；删除该文件或改回 auto 恢复自动检测）");
            }
            else throw new UsageException($"未知的 doctor 选项：{args[i]}");
        }

        ctx.OutText.WriteLine($"home     : {ctx.Home}");
        ctx.OutText.WriteLine($"platform : {System.Runtime.InteropServices.RuntimeInformation.OSDescription} {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}");
        foreach (var line in OutputChannel.Describe(ctx.Home))
            ctx.OutText.WriteLine(line);
        ctx.OutText.WriteLine(Loc.T($"language : {Loc.Lang} ({Loc.Source(ctx.Home)}; pwhide language en|zh)",
            $"语言     : {Loc.Lang}（{Loc.Source(ctx.Home)}；pwhide language en|zh）"));
        if (Environment.GetEnvironmentVariable("PWHIDE_NO_KEYCHAIN") != "1" && Keychain.IsSupported)
        {
            var stored = Keychain.TryGet(ctx.Home, out _);
            ctx.OutText.WriteLine(Loc.T(stored
                ? "keychain : stored (zero-interaction)"
                : "keychain : not stored (pwhide keychain set enables zero-interaction)",
                stored ? "钥匙串   : 已存主口令（零交互）" : "钥匙串   : 未存储（pwhide keychain set 可免交互）"));
        }
        var ok = true;

        // 安装残留报告：必须在 Vault.Exists 判断之外——"final 缺失、orig 是旧库唯一副本"的恢复场景恰在此
        if (Directory.Exists(ctx.Home))
            foreach (var pattern in new[] { "*.pwhide-orig-*", "*.pwhide-new-*" })
                foreach (var f in Directory.EnumerateFiles(ctx.Home, pattern))
                ctx.OutText.WriteLine($"安装残留 : {Path.GetFileName(f)}（特权安装被中断的产物；orig 为旧库唯一副本，可用 sudo 手动改名恢复，切勿先 init 覆盖）");

        // 中断检测与恢复（I6 / §5.1）：清理残留暂存（仅密文，可安全删除）。
        // 持有写锁 + 跳过 60s 内的新鲜暂存，避免误删并发 set 正在等待提权搬运的内容
        if (Vault.Exists(ctx.Home))
        {
            using var _stagingLock = Vault.FileLock.Acquire(ctx.Home);
            var cleaned = Hardening.CleanStaging(ctx.Home);
            if (cleaned > 0)
                ctx.OutText.WriteLine($"中断残留 : 已清理 {cleaned} 个未安装的暂存文件（run/staging，仅密文）");
            using var vault = Vault.Open(ctx.Home);
            ctx.OutText.WriteLine($"vault    : 正常（{vault.Data.Entries.Count} 个条目，元数据可查）");
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                var mode = File.GetUnixFileMode(ctx.Home);
                var tight = mode.HasFlag(UnixFileMode.UserRead) && mode.HasFlag(UnixFileMode.UserWrite) && !mode.HasFlag(UnixFileMode.GroupRead) && !mode.HasFlag(UnixFileMode.OtherRead);
                ctx.OutText.WriteLine($"目录权限 : {(tight ? "700（符合预期）" : $"{Convert.ToString((int)mode, 8)}（建议 700）")}");
                ReportProtection(ctx);
            }
            else ctx.OutText.WriteLine("目录权限 : Windows ACL（建议 Administrators/SYSTEM 完全控制、当前用户读写）");
            try
            {
                var shell = ShellLauncher.ResolveShell("auto");
                ctx.OutText.WriteLine($"shell    : auto → {shell}");
            }
            catch (UsageException e) { ctx.OutText.WriteLine($"shell    : {e.Message}"); }
        }
        else
        {
            ok = false;
            ctx.OutText.WriteLine(Directory.Exists(ctx.Home) && Directory.EnumerateFiles(ctx.Home, "*.pwhide-orig-*").Any()
                ? "vault    : 文件缺失，但存在 *.pwhide-orig-* 残留（旧库唯一副本）——请先恢复再考虑 init"
                : "vault    : 未初始化（pwhide init）");
        }
        return ok ? ExitCodes.Ok : ExitCodes.Vault;
    }

    /// <summary>保护状态报告 + 中断的加固自动恢复（补齐缺失保护）。</summary>
    private static void ReportProtection(CliContext ctx)
    {
        var level = Hardening.GetLevel(ctx.Home);
        switch (level)
        {
            case Hardening.Level.Hardened:
                ctx.OutText.WriteLine($"保护状态 : 已加固（{Hardening.Describe(ctx.Home)}）：密码文件只可整体覆盖");
                return;
            case Hardening.Level.Interrupted:
                ctx.OutText.Write("保护状态 : 中断的加固（部分文件受保护）→ ");
                if (Hardening.IsRoot())
                {
                    Hardening.ApplyRootOwnership(ctx.Home);
                    ctx.OutText.WriteLine("已自动修复（管理员级）");
                }
                else if (OperatingSystem.IsMacOS())
                {
                    foreach (var f in Hardening.CoreFiles)
                    {
                        var p = Path.Combine(ctx.Home, f);
                        if (File.Exists(p) && !Hardening.IsProtected(p)) Hardening.SetImmutable(p);
                    }
                    ctx.OutText.WriteLine("已自动补齐用户级不可变（uchg）；管理员级请 sudo pwhide harden");
                }
                else
                {
                    ctx.OutText.WriteLine($"Linux 普通用户无法补齐 chattr，请运行 sudo pwhide --home \"{ctx.Home}\" harden");
                }
                return;
            default:
                ctx.OutText.WriteLine("保护状态 : 基础模式（700/600）。可运行 pwhide harden 启用不可变写保护");
                return;
        }
    }

    private static string Value(string[] args, ref int i, string err)
    {
        if (i + 1 >= args.Length) throw new UsageException(err);
        i++;
        return args[i];
    }

    /// <summary>人类核验通道共享显示：强制真实终端 + 手输主口令（忽略 env/文件/钥匙串），解密显示供本人核对。</summary>
    private static int VerifyDisplay(CliContext ctx, Vault vault, VaultEntry entry)
    {
        // 唯一允许密文可见的场景；绝无管道/日志路径（IsHumanTerminal 已拒绝重定向）
        vault.Unlock(PassphraseForcedInteractive(ctx));
        var meta = ToMeta(entry);
        ctx.OutText.WriteLine($"条目 {meta.Name}（类型 {meta.Type ?? "-"}）  [verify 解密显示，仅限本人终端，请勿截图/粘贴给 AI]");
        ctx.OutText.WriteLine($"账号: {meta.Username ?? "-"}    租户: {meta.Tenant ?? "-"}");
        ctx.OutText.WriteLine($"密码: {(meta.HasPassword ? vault.DecryptPassword(entry) : "（未设置）")}");
        foreach (var f in entry.Fields)
            ctx.OutText.WriteLine($"加密字段 {f.Name} = {vault.DecryptField(entry, f.Name)}");
        foreach (var kv in entry.PlainFields)
            ctx.OutText.WriteLine($"明文字段 {kv.Key} = {kv.Value}");
        return ExitCodes.Ok;
    }

    /// <summary>
    /// pwhide verify &lt;名&gt;（与 exec 平级的人工核验命令）：强制真实交互终端 + 手输主口令，解密显示密码与字段。
    /// 与 inspect &lt;名&gt; --verify 等价；非交互/重定向环境硬拒绝（密文绝不进管道/AI 上下文）。
    /// </summary>
    public static int Verify(CliContext ctx, string[] args)
    {
        var name = args.FirstOrDefault(a => !a.StartsWith('-'))
            ?? throw new UsageException("用法：pwhide verify <名>（人工核验：需交互终端手输主口令，解密显示密码与字段）");
        // 硬校验先于一切（与 exec --verify 同一原则：找不到条目等信息不构成绕过终端检查的理由）
        if (!IsHumanTerminal(ctx))
            throw new UsageException("verify 需要在真实交互终端运行并手动输入主口令（当前为非交互或 stdin/stdout 被重定向——这是防止密文进入 AI 上下文/日志/管道的硬性限制）");
        using var vault = Vault.Open(ctx.Home);
        var entry = vault.Find(name) ?? throw new VaultException($"条目不存在：{name}");
        return VerifyDisplay(ctx, vault, entry);
    }

    /// <summary>
    /// pwhide language en|zh：切换界面语言（默认英文）。写入 home/language；PWHIDE_LANG 环境变量优先。
    /// 输出用 Loc.T 双语直出——切换立即生效（下一条命令即按新语言）。
    /// </summary>
    public static int LanguageCmd(CliContext ctx, string[] args)
    {
        var sub = args.Length == 0 ? "status" : args[0];
        switch (sub)
        {
            case "en" or "zh":
                Loc.Save(ctx.Home, sub);
                ctx.OutText.WriteLine(Loc.T($"language set to {sub} (stored in {Path.Combine(ctx.Home, "language")}; applies to every command; PWHIDE_LANG env overrides)",
                    $"语言已切换为 {sub}（已写入 {Path.Combine(ctx.Home, "language")}，对所有命令生效；PWHIDE_LANG 环境变量优先）"));
                return ExitCodes.Ok;
            case "status":
                ctx.OutText.WriteLine(Loc.T($"language : {Loc.Lang} (source: {Loc.Source(ctx.Home)})",
                    $"语言     : {Loc.Lang}（来源：{Loc.Source(ctx.Home)}）"));
                return ExitCodes.Ok;
            default:
                throw new UsageException(Loc.T($"unknown language: {sub} (use en or zh)", $"未知的语言：{sub}（可用 en / zh）"));
        }
    }

    /// <summary>
    /// pwhide keychain set|clear|status：主口令存入系统钥匙串，之后所有命令（exec/set 等）自动取用、零交互。
    /// 存的是主口令（OS 负责静态加密与解锁策略）；口令只进本进程内存，永不回显、永不进入 AI 上下文。
    /// </summary>
    public static int KeychainCmd(CliContext ctx, string[] args)
    {
        var sub = args.Length == 0 ? "status" : args[0];
        switch (sub)
        {
            case "set":
            {
                if (!Keychain.IsSupported)
                    throw new VaultException($"当前平台钥匙串不可用：{Keychain.Describe()}。替代方案：PWHIDE_PASSPHRASE_FILE（chmod 600）");
                if (!Vault.Exists(ctx.Home))
                    throw new VaultException($"vault 不存在（{ctx.Home}）。请先 pwhide init，再 keychain set");
                var env = Environment.GetEnvironmentVariable("PWHIDE_PASSPHRASE");
                string pass;
                if (!string.IsNullOrEmpty(env))
                {
                    pass = CheckLength(env);   // 非交互（脚本/AI）配置路径：口令经环境变量提供一次
                }
                else
                {
                    if (!ctx.Interactive)
                        throw new VaultException("非交互环境请用 PWHIDE_PASSPHRASE=<主口令> pwhide keychain set 完成一次配置");
                    using var hidden = HiddenInput.Begin(ctx.In, ctx.Interactive);
                    ctx.ErrText.Write("主口令: ");
                    pass = CheckLength(HiddenInput.ReadLine(hidden, ctx.In));
                }
                // 尾随换行的口令无法经 macOS security 回读（回读会 TrimEnd \n）——直接拒绝，避免静默坏库
                if (pass.EndsWith('\n') || pass.EndsWith('\r'))
                    throw new UsageException("口令不能以换行/回车结尾（钥匙串回读无法保真）。请重新输入");
                // 先验证口令确实能解锁当前 vault，防止把错误口令入库导致后续全部命令失败
                using (var vault = Vault.Open(ctx.Home))
                    vault.Unlock(pass);
                Keychain.Store(ctx.Home, pass);
                ctx.OutText.WriteLine($"已存入 {Keychain.Describe()}（槽位绑定 {ctx.Home}）。之后 exec/set 等命令将自动取用，无需再输口令");
                ctx.OutText.WriteLine($"撤销：pwhide keychain clear；临时跳过：PWHIDE_NO_KEYCHAIN=1");
                return ExitCodes.Ok;
            }
            case "clear":
            {
                var removed = Keychain.Clear(ctx.Home);
                ctx.OutText.WriteLine(removed ? "已从钥匙串删除主口令" : "钥匙串中没有已存储的主口令（无需清理）");
                return ExitCodes.Ok;
            }
            case "status":
            {
                ctx.OutText.WriteLine($"平台支持 : {Keychain.Describe()}");
                var enabled = Environment.GetEnvironmentVariable("PWHIDE_NO_KEYCHAIN") == "1";
                if (enabled) { ctx.OutText.WriteLine("当前状态 : 已通过 PWHIDE_NO_KEYCHAIN=1 禁用钥匙串来源"); return ExitCodes.Ok; }
                if (!Keychain.IsSupported) { ctx.OutText.WriteLine("当前状态 : 不可用（见上）"); return ExitCodes.Ok; }
                var stored = Keychain.TryGet(ctx.Home, out _);
                ctx.OutText.WriteLine(stored
                    ? "当前状态 : 已存储主口令（exec/set 自动取用，零交互）"
                    : "当前状态 : 未存储。运行 pwhide keychain set 配置（配置后 exec 无需再输口令）");
                return ExitCodes.Ok;
            }
            default:
                throw new UsageException($"未知的 keychain 子命令：{sub}（可用 set / clear / status）");
        }
    }
}
