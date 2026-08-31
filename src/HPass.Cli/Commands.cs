using System.Text.Json;
using HPass.Core;

namespace HPass.Cli;

public static class Commands
{
    internal static string GetPassphrase(CliContext ctx, bool confirm)
    {
        var env = Environment.GetEnvironmentVariable("HPASS_PASSPHRASE");
        if (!string.IsNullOrEmpty(env)) return env;

        var file = Environment.GetEnvironmentVariable("HPASS_PASSPHRASE_FILE");
        if (!string.IsNullOrEmpty(file) && File.Exists(file))
            return File.ReadAllText(file).TrimEnd('\r', '\n');

        if (!ctx.Interactive)
            throw new VaultException("非交互环境需要解锁：请设置 HPASS_PASSPHRASE 或 HPASS_PASSPHRASE_FILE");

        ctx.ErrText.Write("主口令: ");
        var first = HiddenInput.ReadLineHidden(ctx.In, ctx.Interactive);
        if (first.Length < 8) throw new VaultException("口令至少需要 8 个字符");
        if (confirm)
        {
            ctx.ErrText.Write("再次确认: ");
            var second = HiddenInput.ReadLineHidden(ctx.In, ctx.Interactive);
            if (first != second) throw new VaultException("两次输入不一致");
        }
        return first;
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
                default:
                    if (name is null && !args[i].StartsWith('-')) name = args[i];
                    else throw new UsageException($"set：无法识别的参数 {args[i]}");
                    break;
            }
        }
        if (name is null) throw new UsageException("用法：hpass set <名> [-t 类型] [-u 账号] [-T 租户] [-f 字段=值]… [--password-stdin]");

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
            vault.SetField(entry, fname, value);
        }
        vault.Save();
        ctx.OutText.WriteLine($"已保存条目 {name}（{vault.Data.Entries.Count} 个条目）");
        return ExitCodes.Ok;
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
    /// 特权加固（M3）：root/Admin 属主 + 不可变标志/ACL，密码文件只可整体覆盖。
    /// 当前进程非 root 时，交互环境提示经 sudo 重拉自身；非交互环境打印手动步骤。
    /// </summary>
    public static int Harden(CliContext ctx, string[] args)
    {
        if (!Vault.Exists(ctx.Home))
            throw new VaultException($"未找到 vault（{ctx.Home}），请先 hpass init");

        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            ctx.OutText.WriteLine("Windows 平台：请以管理员运行以下命令设置 ACL（用户只读，Administrators/SYSTEM 完全控制）：");
            ctx.OutText.WriteLine($"  icacls \"{ctx.Home}\" /inheritance:r /grant:r Administrators:F /grant:r SYSTEM:F /grant:r {Environment.UserName}:RX");
            return ExitCodes.Ok;
        }

        var isRoot = Environment.UserName == "root" || Environment.GetEnvironmentVariable("SUDO_USER") is not null && Environment.UserName == "root";
        if (!isRoot)
        {
            if (ctx.Interactive)
            {
                ctx.OutText.WriteLine("将以 sudo 重新执行加固（root 属主 + 不可变标志，密码文件将只可整体覆盖）。");
                ctx.OutText.WriteLine("如需自动化，请直接运行：sudo hpass --home \"" + ctx.Home + "\" harden");
                return ExitCodes.Ok;
            }
            ctx.OutText.WriteLine($"非交互环境：请手动运行 sudo hpass --home \"{ctx.Home}\" harden");
            return ExitCodes.Ok;
        }

        // root 路径：属主 root、目录 750、文件 440、不可变标志
        var user = Environment.GetEnvironmentVariable("SUDO_USER") ?? Environment.UserName;
        var group = Environment.GetEnvironmentVariable("SUDO_GROUP") ?? "wheel";
        foreach (var (dir, mode) in new[] { (ctx.Home, "750"), (Path.Combine(ctx.Home, "run"), "700") })
            Run("chown", $"root:{group} \"{dir}\" && chmod {mode} \"{dir}\"");
        foreach (var f in new[] { "vault.json", "master.key", "config.json" })
        {
            var p = Path.Combine(ctx.Home, f);
            if (!File.Exists(p)) continue;
            Run("chown", $"root:{group} \"{p}\" && chmod 440 \"{p}\"");
            if (OperatingSystem.IsMacOS()) _ = RunSh($"chflags schg \"{p}\"");
            else _ = RunSh($"chattr +i \"{p}\"");
        }
        ctx.OutText.WriteLine($"已加固：root 属主 + 不可变标志（用户 {user} 只读）。");
        ctx.OutText.WriteLine("提示：exec 读路径无需提权；后续 set/delete/rename 需先 sudo hpass … 或运行 hpass unharden（未实现，用 chflags nouchg/chattr -i）");
        return ExitCodes.Ok;

        static int Run(string _, string sh)
        {
            var psi = new System.Diagnostics.ProcessStartInfo("/bin/sh", ["-c", sh])
            { UseShellExecute = false, RedirectStandardError = true };
            using var p = System.Diagnostics.Process.Start(psi)!;
            p.WaitForExit(5000);
            return p.ExitCode;
        }

        static string RunSh(string sh)
        {
            var psi = new System.Diagnostics.ProcessStartInfo("/bin/sh", ["-c", sh])
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = System.Diagnostics.Process.Start(psi)!;
            p.WaitForExit(5000);
            return p.StandardOutput.ReadToEnd();
        }
    }

    public static int Doctor(CliContext ctx, string[] args)
    {
        ctx.OutText.WriteLine($"home     : {ctx.Home}");
        ctx.OutText.WriteLine($"platform : {System.Runtime.InteropServices.RuntimeInformation.OSDescription} {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture}");
        var ok = true;

        if (Vault.Exists(ctx.Home))
        {
            using var vault = Vault.Open(ctx.Home);
            ctx.OutText.WriteLine($"vault    : 正常（{vault.Data.Entries.Count} 个条目，元数据可查）");
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                var mode = File.GetUnixFileMode(ctx.Home);
                var tight = mode.HasFlag(UnixFileMode.UserRead) && mode.HasFlag(UnixFileMode.UserWrite) && !mode.HasFlag(UnixFileMode.GroupRead) && !mode.HasFlag(UnixFileMode.OtherRead);
                ctx.OutText.WriteLine($"目录权限 : {(tight ? "700（基础模式，符合预期）" : $"{Convert.ToString((int)mode, 8)}（建议 700；运行 hpass harden 可升级管理员写保护）")}");
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

    private static string Value(string[] args, ref int i, string err)
    {
        if (i + 1 >= args.Length) throw new UsageException(err);
        i++;
        return args[i];
    }
}
