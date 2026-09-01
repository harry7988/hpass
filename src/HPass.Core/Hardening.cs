using System.Diagnostics;
using System.Globalization;

namespace HPass.Core;

/// <summary>
/// 特权加固（PLAN §5.1 / M3）。
/// 保护语义：密码文件只能经"清保护 → 原子覆盖 → 重新加保护"这一条路径变更（I6）。
/// - macOS：root 用系统不可变标志 schg；普通用户可用 uchg（用户级不可变，同样阻止意外写，属主可清）。
/// - Linux：chattr +i（需要 root / CAP_LINUX_IMMUTABLE），普通用户无法设置 → 指引 sudo。
/// - Windows：无不可变标志，以"用户不可写"（Administrators/SYSTEM ACL）为保护信号，操作走 icacls 指引。
/// </summary>
public static class Hardening
{
    public enum Level { None, Basic, Hardened, Interrupted }

    /// <summary>参与保护判定的核心文件（config.json 非机密，保持用户可写）。</summary>
    public static readonly string[] CoreFiles = ["vault.json", "master.key"];

    private const int MacUfImmutable = 0x00000002; // uchg
    private const int MacSfImmutable = 0x00020000; // schg

    public static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern uint geteuid();

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int flock(int fd, int operation);

    private const int LockEx = 2;      // LOCK_EX
    private const int LockNb = 4;      // LOCK_NB

    /// <summary>跨进程互斥锁：.NET 的 FileShare 在 Unix 上无强制力（dotnet/runtime#59995），必须 flock。</summary>
    public static void FlockExclusive(Microsoft.Win32.SafeHandles.SafeFileHandle handle)
    {
        if (!Unix) return;
        var fd = handle.DangerousGetHandle().ToInt32();
        if (flock(fd, LockEx | LockNb) != 0)
            throw new IOException($"flock 失败（errno {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}）");
    }

    /// <summary>以 geteuid 判定（SUDO_USER 等环境变量可被任意进程伪造，只作展示参考）。</summary>
    public static bool IsRoot() => Unix && geteuid() == 0;

    public static bool IsImmutable(string path)
    {
        if (!File.Exists(path) || !Unix) return false;
        if (OperatingSystem.IsMacOS())
        {
            var hex = Sh($"stat -f %f {Q(path)}").Trim().Replace("0x", "");
            if (!int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var flags)) return false;
            return (flags & MacUfImmutable) != 0 || (flags & MacSfImmutable) != 0;
        }
        // Linux：lsattr 输出形如 "----i---------e------- /path"，取首个空白前的属性行判断 'i'
        var attrField = Sh($"lsattr {Q(path)} 2>/dev/null || true").Trim();
        var idx = attrField.IndexOf(' ');
        if (idx > 0) attrField = attrField[..idx];
        return attrField.Length > 0 && attrField.Contains('i');
    }

    /// <summary>当前用户能否写该文件（不可变、属主不同、无写位都视为不能）。</summary>
    public static bool IsUserWritable(string path)
    {
        if (!File.Exists(path)) return false;
        try
        {
            using var _ = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsProtected(string path) => IsImmutable(path) || !IsUserWritable(path);

    /// <summary>
    /// 符号链接检测（防提权：root 的 chown/chmod/rename 语义对 symlink 的处理会跟随/替换链接，
    /// 恶意进程可用 symlink 把 root 操作重定向到任意文件）。硬链接无法以路径区分，威胁模型如实声明。
    /// </summary>
    public static bool IsSymbolicLink(string path)
    {
        try
        {
            // 不得用 File.Exists 作前置门：它跟随链接 stat，目录链接与悬空链接都返回 false（fail-open）
            // LinkTarget 基于不跟随的 readlink：悬空/目录链接同样能识别
            return new FileInfo(path).LinkTarget is not null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>文件属主 uid（跨平台 stat；失败返回 -1）。root 安装时校验暂存属主=调用用户，收窄跨用户伪造面。</summary>
    public static int FileOwnerUid(string path)
    {
        var stat = OperatingSystem.IsMacOS() ? $"stat -f %u {Q(path)}" : $"stat -c %u {Q(path)}";
        return int.TryParse(Sh(stat).Trim(), out var uid) ? uid : -1;
    }

    /// <summary>用户名 → uid（失败返回 -1）。</summary>
    public static int UserIdOf(string userName) =>
        int.TryParse(Sh($"id -u {Q(userName)}").Trim(), out var uid) ? uid : -1;

    /// <summary>保护等级：全部核心文件受保护 = Hardened；部分 = Interrupted（中断态，等待恢复）。</summary>
    public static Level GetLevel(string home)
    {
        if (!Vault.Exists(home)) return Level.None;
        var flags = CoreFiles.Select(f => IsProtected(Path.Combine(home, f))).ToArray();
        if (flags.All(f => f)) return Level.Hardened;
        return flags.Any(f => f) ? Level.Interrupted : Level.Basic;
    }

    /// <summary>Hardened 细分描述：root 属主（管理员级）还是属主可写的 uchg（用户级）。</summary>
    public static string Describe(string home)
    {
        var file = Path.Combine(home, CoreFiles[0]);
        if (!File.Exists(file)) return "未知";
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            var mode = File.GetUnixFileMode(file);
            return mode.HasFlag(UnixFileMode.UserWrite) ? "用户级不可变（uchg）" : "管理员级（root 属主 + 不可变）";
        }
        return "ACL 拒写";
    }

    /// <summary>设置不可变标志：root → schg / chattr +i；普通用户 macOS → uchg；普通用户 Linux 无法设置（静默跳过，调用方负责检查）。</summary>
    public static void SetImmutable(string path)
    {
        if (OperatingSystem.IsMacOS())
            Sh($"chflags {(IsRoot() ? "schg" : "uchg")} {Q(path)}", check: true);
        else if (OperatingSystem.IsLinux())
            Sh($"chattr +i {Q(path)}", check: IsRoot());
    }

    /// <summary>清除不可变标志（uchg 属主可清；schg/​+i 需要 root，非 root 时静默失败）。</summary>
    public static void ClearImmutable(string path)
    {
        if (!Unix || !File.Exists(path)) return;
        if (IsSymbolicLink(path)) return;   // Linux chattr 经 open 跟随链接可清任意文件标志；链接交给上游拒绝
        if (OperatingSystem.IsMacOS())
        {
            Sh($"chflags nouchg {Q(path)}");
            Sh($"chflags noschg {Q(path)}");
        }
        else
        {
            Sh($"chattr -i {Q(path)}");
        }
    }

    /// <summary>root 路径：核心文件 root 属主 440 + 不可变。SUDO_GROUP 不含用户时降级 444/755 保住 exec 读路径。</summary>
    public static void ApplyRootOwnership(string home)
    {
        if (IsSymbolicLink(home)) throw new VaultException($"拒绝对符号链接执行特权操作：{home}（可能的提权攻击）");
        foreach (var f in CoreFiles)
        {
            var p = Path.Combine(home, f);
            if (File.Exists(p)) ApplyRootFilePerms(p);
        }
        var (group, member) = RootGroup();
        var grp = group ?? (OperatingSystem.IsMacOS() ? "wheel" : "root");
        var dirMode = member ? "750" : "755";
        Sh($"chown root:{grp} {Q(home)} && chmod {dirMode} {Q(home)}", check: true);
        // 操作后复核：目录/文件在窗口内被换成符号链接即中止（rename-dance 之外的最后防线）
        if (IsSymbolicLink(home)) throw new VaultException($"特权操作后 {home} 变成了符号链接，已中止（可能的提权攻击）");
    }

    /// <summary>仅 chown/chmod（不设不可变）——供"rename 前对新文件先行确权"使用；不可变必须在 rename 之后。</summary>
    public static void ApplyRootOwnershipOnly(string path)
    {
        if (IsSymbolicLink(path)) throw new VaultException($"拒绝对符号链接执行特权操作：{path}（可能的提权攻击）");
        var (group, member) = RootGroup();
        var grp = group ?? (OperatingSystem.IsMacOS() ? "wheel" : "root");
        var mode = member ? "440" : "444";
        Sh($"chown root:{grp} {Q(path)} && chmod {mode} {Q(path)}", check: true);
    }

    public static void ApplyRootFilePerms(string path)
    {
        if (IsSymbolicLink(path)) throw new VaultException($"拒绝对符号链接执行特权操作：{path}（可能的提权攻击）");
        var (group, member) = RootGroup();
        var grp = group ?? (OperatingSystem.IsMacOS() ? "wheel" : "root");
        var mode = member ? "440" : "444";
        Sh($"chown root:{grp} {Q(path)} && chmod {mode} {Q(path)}", check: true);
        SetImmutable(path);
        if (IsSymbolicLink(path)) throw new VaultException($"特权操作后 {path} 变成了符号链接，已中止（可能的提权攻击）");
    }

    private static (string? Group, bool Member) RootGroup()
    {
        var user = Environment.GetEnvironmentVariable("SUDO_USER") ?? Environment.UserName;
        var group = Environment.GetEnvironmentVariable("SUDO_GROUP");
        var member = !string.IsNullOrEmpty(group) && Sh($"id -Gn {Q(user)} 2>/dev/null || true").Contains(group!);
        if (!member)
        {
            // 回退：用调用用户的主组（id -gn），避免 444/755 把元数据与密文暴露给全机本地用户
            var primary = Sh($"id -gn {Q(user)} 2>/dev/null || true").Trim();
            if (primary.Length > 0 && !primary.Contains(' ') && !primary.Contains('\n'))
                return (primary, true);
        }
        return (group, member);
    }

    /// <summary>
    /// 清理中断残留的暂存文件（仅密文，可安全删除）。
    /// 跳过 minAgeSeconds 内的新鲜暂存——它们可能是并发 set 正在等待提权搬运的内容。
    /// </summary>
    public static int CleanStaging(string home, int minAgeSeconds = 60)
    {
        var dir = Path.Combine(home, "run", "staging");
        if (!Directory.Exists(dir)) return 0;
        var count = 0;
        foreach (var f in Directory.EnumerateFiles(dir))
        {
            try
            {
                if ((DateTime.UtcNow - File.GetLastWriteTimeUtc(f)).TotalSeconds < minAgeSeconds) continue;
                File.Delete(f);
                count++;
            }
            catch { }
        }
        return count;
    }

    public static string Q(string p) => "'" + p.Replace("'", "'\\''") + "'";

    /// <summary>执行 shell 命令；check=true 时非零退出抛 VaultException。返回 stdout。</summary>
    public static string Sh(string command, bool check = false)
    {
        var (code, output) = RunCapture("/bin/sh", ["-c", command]);
        if (check && code != 0)
            throw new VaultException($"加固命令失败（exit {code}）：{command}");
        return output;
    }

    /// <summary>同 RunCapture，但额外捕获 stderr（用于把提权子进程的失败原因带回给调用方）。</summary>
    public static (int Exit, string Output, string Stderr) RunCaptureEx(string fileName, IReadOnlyList<string> args, int timeoutMs = 10_000, Action<ProcessStartInfo>? configure = null)
    {
        var psi = new ProcessStartInfo(fileName) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment.Remove("HPASS_PASSPHRASE");
        psi.Environment.Remove("HPASS_PASSPHRASE_FILE");
        configure?.Invoke(psi);
        try
        {
            using var p = Process.Start(psi)!;
            var outTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                p.WaitForExit(2_000);
                outTask.Wait(2_000);
                errTask.Wait(2_000);
                return (-1, "", errTask.IsCompleted ? errTask.Result : "");
            }
            outTask.Wait(5_000);
            errTask.Wait(5_000);
            return (p.HasExited ? p.ExitCode : -1, outTask.IsCompleted ? outTask.Result : "", errTask.IsCompleted ? errTask.Result : "");
        }
        catch (Exception e)
        {
            return (-1, "", e.Message);
        }
    }

    public static (int Exit, string Output) RunCapture(string fileName, IReadOnlyList<string> args, bool showOutput = false, int timeoutMs = 10_000, Action<ProcessStartInfo>? configure = null)
    {
        var psi = new ProcessStartInfo(fileName) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = showOutput ? false : true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        // 提权子进程同样不透传主口令
        psi.Environment.Remove("HPASS_PASSPHRASE");
        psi.Environment.Remove("HPASS_PASSPHRASE_FILE");
        configure?.Invoke(psi);
        try
        {
            using var p = Process.Start(psi)!;
            var outputTask = p.StandardOutput.ReadToEndAsync();
            var errTask = showOutput ? null : p.StandardError.ReadToEndAsync();
            // 先等退出再收流：孤儿子孙持有管道不关时，先收流会永久阻塞、超时杀永远到不了
            if (!p.WaitForExit(timeoutMs))
            {
                // 超时必须杀掉：否则孤儿 sudo 可能稍后自行完成 root 安装，与用户重试形成竞争
                try { p.Kill(entireProcessTree: true); } catch { }
                p.WaitForExit(2_000);
                outputTask.Wait(2_000);
                return (-1, outputTask.IsCompleted ? outputTask.Result : "");
            }
            outputTask.Wait(5_000);
            if (errTask is not null) errTask.Wait(5_000);
            return (p.HasExited ? p.ExitCode : -1, outputTask.IsCompleted ? outputTask.Result : "");
        }
        catch (Exception e)
        {
            return (-1, e.Message);
        }
    }
}
