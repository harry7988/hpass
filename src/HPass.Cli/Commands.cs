using System.Text.Json;
using HPass.Core;

namespace HPass.Cli;

public static class Commands
{
    internal static string GetPassphrase(CliContext ctx, bool confirm)
    {
        var env = Environment.GetEnvironmentVariable("HPASS_PASSPHRASE");
        if (!string.IsNullOrEmpty(env)) return CheckLength(env);

        var file = Environment.GetEnvironmentVariable("HPASS_PASSPHRASE_FILE");
        if (!string.IsNullOrEmpty(file) && File.Exists(file))
        {
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                var mode = File.GetUnixFileMode(file);
                if (mode.HasFlag(UnixFileMode.GroupRead) || mode.HasFlag(UnixFileMode.OtherRead))
                    ctx.ErrText.WriteLine($"hpass: 警告：口令文件 {file} 对组/其他用户可读（主口令泄露=库可离线穷举），建议 chmod 600");
            }
            return CheckLength(File.ReadAllText(file).TrimEnd('\r', '\n'));
        }

        if (!ctx.Interactive)
            throw new VaultException("非交互环境需要解锁：请设置 HPASS_PASSPHRASE 或 HPASS_PASSPHRASE_FILE");

        ctx.ErrText.Write("主口令: ");
        var first = HiddenInput.ReadLineHidden(ctx.In, ctx.Interactive);
        first = CheckLength(first);
        if (first.Length < 8) throw new VaultException("口令至少需要 8 个字符");
        if (confirm)
        {
            ctx.ErrText.Write("再次确认: ");
            var second = HiddenInput.ReadLineHidden(ctx.In, ctx.Interactive);
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
        if (Vault.Exists(ctx.Home))
            throw new VaultException($"vault 已存在（{ctx.Home}）。如需重置请先手动删除该目录");

        var passphrase = GetPassphrase(ctx, confirm: true);
        using var vault = Vault.Create(ctx.Home, passphrase);
        ctx.OutText.WriteLine($"已初始化：{ctx.Home}");
        ctx.OutText.WriteLine(noHarden || !OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS() && !OperatingSystem.IsWindows()
            ? "文件保护：基础模式（目录 700 / 文件 600）。可随时运行 hpass harden 升级为管理员写保护"
            : "文件保护：基础模式（目录 700 / 文件 600）。可运行 hpass harden 启用管理员写保护（仅整体覆盖）");
        return ExitCodes.Ok;
    }

    public static int Set(CliContext ctx, string[] args)
    {
        string? name = null, type = null, username = null, tenant = null, password = null;
        var fields = new List<(string Name, string? Value)>();
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
                    fields.Add(eq < 0 ? (spec, null) : (spec[..eq], spec[(eq + 1)..]));
                    break;
                case "--password-stdin": passwordStdin = true; break;
                case "--force-weak": forceWeak = true; break;
                default:
                    if (name is null && !args[i].StartsWith('-')) name = args[i];
                    else throw new UsageException($"set：无法识别的参数 {args[i]}");
                    break;
            }
        }
        if (name is null) throw new UsageException("用法：hpass set <名> [-t 类型] [-u 账号] [-T 租户] [-f 字段=值]… [--password-stdin] [--force-weak]");

        if (passwordStdin)
        {
            password = ctx.In.ReadLine() ?? "";
            if (password.Length == 0) throw new UsageException("--password-stdin：未从 stdin 读到密码");
        }
        else if (ctx.Interactive)
        {
            ctx.ErrText.Write($"密码（{name}）: ");
            password = HiddenInput.ReadLineHidden(ctx.In, ctx.Interactive);
            ctx.ErrText.Write("再次确认: ");
            if (HiddenInput.ReadLineHidden(ctx.In, ctx.Interactive) != password)
                throw new VaultException("两次输入不一致");
        }
        else throw new UsageException("非交互环境请使用 --password-stdin 从 stdin 提供密码（禁止命令行明文传密码）");

        if (password.Length == 0)
            throw new UsageException("密码不能为空");

        // 弱密文拦截：密码=常见语句时会与正常输出碰撞，且"被替换的位置"会直接暴露密码内容
        if (!forceWeak && WeakSecret.Check(password) is { } reason)
            throw new UsageException($"拒绝保存弱密码：{reason}。如确要使用请追加 --force-weak（风险自担：输出中的常见文本会被大面积误替换为占位符，并可被据此推测）");

        using var vault = Vault.Open(ctx.Home);
        using var _lock = Vault.FileLock.Acquire(ctx.Home);
        vault.Unlock(GetPassphrase(ctx, confirm: false));
        var entry = vault.GetOrAdd(name, type, username, tenant);
        vault.SetPassword(entry, password);
        foreach (var (fname, fvalue) in fields)
        {
            string value = fvalue ?? (ctx.Interactive
                ? HiddenInputWithPrompt(ctx, $"字段 {fname} 的值: ")
                : throw new UsageException($"非交互环境请用 -f {fname}=<值> 提供字段值"));
            if (value.Length == 0)
                throw new UsageException($"字段 {fname} 的值不能为空");
            // 敏感字段名经 argv 传值会进 shell history/ps：提醒改用交互隐藏输入
            if (fvalue is not null && LooksSensitive(fname))
                ctx.ErrText.WriteLine($"hpass: 警告：字段 {fname} 形似敏感字段，命令行传值会进入 shell history——建议改用交互隐藏输入（hpass set … -f {fname}）");
            // 字段值（如 host=127.0.0.1 这类常见值）不阻断，仅警告：与密码不同，字段常为非敏感配置
            if (WeakSecret.Check(value) is { } fieldReason)
                ctx.ErrText.WriteLine($"hpass: 警告：字段 {fname} 的值{fieldReason}；作为密文注入时可能与正常输出碰撞，请确认");
            vault.SetField(entry, fname, value);
        }
        vault.Save();
        ctx.OutText.WriteLine($"已保存条目 {name}（{vault.Data.Entries.Count} 个条目）");
        return ExitCodes.Ok;
    }

    private static bool LooksSensitive(string fieldName)
    {
        foreach (var marker in new[] { "key", "token", "secret", "pin", "password", "passwd", "pwd" })
            if (fieldName.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string HiddenInputWithPrompt(CliContext ctx, string prompt)
    {
        ctx.ErrText.Write(prompt);
        return HiddenInput.ReadLineHidden(ctx.In, ctx.Interactive);
    }

    public static int List(CliContext ctx, string[] args)
    {
        var json = args.Contains("--json");
        using var vault = Vault.Open(ctx.Home);
        var metas = vault.Data.Entries.Select(e => ToMeta(e)).ToList();
        if (json)
        {
            ctx.OutText.Write(JsonSerializer.Serialize(metas, HPassJsonContext.Default.ListEntryMeta));
            return ExitCodes.Ok;
        }
        if (metas.Count == 0) { ctx.OutText.WriteLine("（vault 为空，用 hpass set <名> 录入）"); return ExitCodes.Ok; }
        ctx.OutText.WriteLine($"{"名称",-16}{"类型",-10}{"账号",-14}{"租户",-10}字段");
        foreach (var m in metas)
            ctx.OutText.WriteLine($"{m.Name,-16}{m.Type ?? "-",-10}{m.Username ?? "-",-14}{m.Tenant ?? "-",-10}{string.Join(",", m.Fields)}");
        return ExitCodes.Ok;
    }

    public static int Inspect(CliContext ctx, string[] args)
    {
        var name = args.FirstOrDefault(a => !a.StartsWith('-'))
            ?? throw new UsageException("用法：hpass inspect <名> [--json]");
        using var vault = Vault.Open(ctx.Home);
        var entry = vault.Find(name) ?? throw new VaultException($"条目不存在：{name}");
        var meta = ToMeta(entry);
        if (args.Contains("--json"))
            ctx.OutText.Write(JsonSerializer.Serialize(meta, HPassJsonContext.Default.EntryMeta));
        else
        {
            ctx.OutText.WriteLine($"名称: {meta.Name}");
            ctx.OutText.WriteLine($"类型: {meta.Type ?? "-"}    账号: {meta.Username ?? "-"}    租户: {meta.Tenant ?? "-"}");
            ctx.OutText.WriteLine($"密码: {(meta.HasPassword ? "已设置（只能经 {{" + meta.Name + "}} 注入）" : "未设置")}");
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
        return meta;
    }

    public static int Delete(CliContext ctx, string[] args)
    {
        var name = args.FirstOrDefault(a => !a.StartsWith('-')) ?? throw new UsageException("用法：hpass delete <名>");
        using var vault = Vault.Open(ctx.Home);
        using var _lock = Vault.FileLock.Acquire(ctx.Home);
        if (!vault.Delete(name)) throw new VaultException($"条目不存在：{name}");
        vault.Save();
        ctx.OutText.WriteLine($"已删除 {name}");
        return ExitCodes.Ok;
    }

    public static int Rename(CliContext ctx, string[] args)
    {
        var positional = args.Where(a => !a.StartsWith('-')).ToList();
        if (positional.Count != 2) throw new UsageException("用法：hpass rename <旧名> <新名>");
        using var vault = Vault.Open(ctx.Home);
        using var _lock = Vault.FileLock.Acquire(ctx.Home);
        vault.Unlock(GetPassphrase(ctx, confirm: false));
        vault.Rename(positional[0], positional[1]);
        vault.Save();
        ctx.OutText.WriteLine($"已重命名 {positional[0]} → {positional[1]}");
        return ExitCodes.Ok;
    }

    public static int Rotate(CliContext ctx, string[] args)
    {
        using var vault = Vault.Open(ctx.Home);
        using var _lock = Vault.FileLock.Acquire(ctx.Home);
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
            throw new VaultException($"未找到 vault（{ctx.Home}），请先 hpass init");

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
            ctx.OutText.WriteLine($"exec 读路径无需提权；后续 set/delete/rename/rotate 会自动经 sudo 搬运安装（也可手动：sudo hpass --home \"{ctx.Home}\" …）");
            return ExitCodes.Ok;
        }

        if (OperatingSystem.IsMacOS())
        {
            foreach (var f in Hardening.CoreFiles)
                Hardening.SetImmutable(Path.Combine(ctx.Home, f));
            ctx.OutText.WriteLine("已加固（用户级 uchg 不可变）：文件只能整体覆盖（hpass 内部自动清/复加）。");
            ctx.OutText.WriteLine($"升级为管理员级（root 属主 + schg）：sudo hpass --home \"{ctx.Home}\" harden");
            return ExitCodes.Ok;
        }

        // Linux 普通用户：chattr 需提权
        if (ctx.Interactive)
        {
            ctx.OutText.WriteLine("将以 sudo 重新执行加固（root 属主 + chattr +i）…");
            var exe = Environment.ProcessPath
                ?? throw new VaultException("无法定位 hpass 可执行文件");
            var (code, _) = Hardening.RunCapture("sudo", ["--", exe, "--home", ctx.Home, "harden"], showOutput: true, timeoutMs: 300_000);
            return code == 0 ? ExitCodes.Ok : ExitCodes.Vault;
        }
        ctx.OutText.WriteLine($"非交互环境（Linux 普通用户无法 chattr）：请手动运行 sudo hpass --home \"{ctx.Home}\" harden");
        return ExitCodes.Ok;
    }

    /// <summary>内部命令：提权子进程的"密文搬运"（清保护 → 原子覆盖 → 恢复 root 属主与保护）。仅在提权中使用。</summary>
    public static int InstallStaged(CliContext ctx, string[] args)
    {
        if (args.Length != 2) throw new UsageException("用法（内部）：hpass _install-staged <暂存文件> <最终路径>");
        var staging = Path.GetFullPath(args[0]);
        var final = Path.GetFullPath(args[1]);
        var stagingRoot = Path.GetFullPath(Path.Combine(ctx.Home, "run", "staging"));
        if (!staging.StartsWith(stagingRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new UsageException($"安全限制：暂存文件必须位于 {stagingRoot} 之下");
        var allowed = new[] { "vault.json", "master.key", "config.json" }
            .Select(n => Path.GetFullPath(Path.Combine(ctx.Home, n)));
        if (!allowed.Contains(final))
            throw new UsageException("安全限制：最终路径只能是 vault.json / master.key / config.json");

        // 手动恢复路径同样持锁：与并发 set 竞争同一 final 会丢更新
        using var _lock = Vault.FileLock.Acquire(ctx.Home);

        var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
        if (Hardening.IsRoot())
        {
            // root 搬运时校验暂存属主 = 调用用户（SUDO_USER），收窄跨用户伪造 staging 的面
            if (!string.IsNullOrEmpty(sudoUser))
            {
                var owner = Hardening.FileOwnerUid(staging);
                var caller = Hardening.UserIdOf(sudoUser);
                if (owner >= 0 && caller >= 0 && owner != caller)
                    throw new UsageException($"安全限制：暂存文件属主（uid {owner}）与调用用户（uid {caller}）不一致，拒绝安装");
            }
            // root 首次创建的 lock 若留在 root 名下，用户侧从此 EACCES——归还给调用用户
            var lockPath = Path.Combine(ctx.Home, "run", "lock");
            if (File.Exists(lockPath) && !string.IsNullOrEmpty(sudoUser))
                _ = Hardening.Sh($"chown {Hardening.Q(sudoUser)} {Hardening.Q(lockPath)} 2>/dev/null || true");
        }
        SecureFile.InstallStagedDirect(staging, final);
        return ExitCodes.Ok;
    }

    public static int Doctor(CliContext ctx, string[] args)
    {
        ctx.OutText.WriteLine($"home     : {ctx.Home}");
        ctx.OutText.WriteLine($"platform : {System.Runtime.InteropServices.RuntimeInformation.OSDescription} {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}");
        var ok = true;

        // 中断检测与恢复（I6 / §5.1）：清理残留暂存（仅密文，可安全删除）。
        // 持有写锁 + 跳过 60s 内的新鲜暂存，避免误删并发 set 正在等待提权搬运的内容
        if (Vault.Exists(ctx.Home))
        {
            using var _stagingLock = Vault.FileLock.Acquire(ctx.Home);
            var cleaned = Hardening.CleanStaging(ctx.Home);
            if (cleaned > 0)
                ctx.OutText.WriteLine($"中断残留 : 已清理 {cleaned} 个未安装的暂存文件（run/staging，仅密文）");
            // root 安装中断可能留下 *.hpass-orig-*（旧库唯一副本）/*.hpass-new-*：报告并给出恢复指引，不自动删除
            foreach (var pattern in new[] { "*.hpass-orig-*", "*.hpass-new-*" })
                foreach (var f in Directory.EnumerateFiles(ctx.Home, pattern))
                    ctx.OutText.WriteLine($"安装残留 : {Path.GetFileName(f)}（特权安装被中断的产物；orig 为旧库副本，可用 sudo 手动改名恢复，详见 threat-model §3）");
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
            ctx.OutText.WriteLine("vault    : 未初始化（hpass init）");
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
                    ctx.OutText.WriteLine("已自动补齐用户级不可变（uchg）；管理员级请 sudo hpass harden");
                }
                else
                {
                    ctx.OutText.WriteLine($"Linux 普通用户无法补齐 chattr，请运行 sudo hpass --home \"{ctx.Home}\" harden");
                }
                return;
            default:
                ctx.OutText.WriteLine("保护状态 : 基础模式（700/600）。可运行 hpass harden 启用不可变写保护");
                return;
        }
    }

    private static string Value(string[] args, ref int i, string err)
    {
        if (i + 1 >= args.Length) throw new UsageException(err);
        i++;
        return args[i];
    }
}
