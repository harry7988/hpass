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

    public static bool IsRoot()
    {
        if (!Unix) return false;
        if (Environment.UserName == "root") return true;
        // 经 sudo 重拉：SUDO_USER/SUDO_UID 由 sudo 设置
        return Environment.GetEnvironmentVariable("SUDO_USER") is not null
            && Environment.GetEnvironmentVariable("SUDO_UID") is not null;
    }

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
        foreach (var f in CoreFiles)
        {
            var p = Path.Combine(home, f);
            if (File.Exists(p)) ApplyRootFilePerms(p);
        }
        var (group, member) = RootGroup();
        var grp = group ?? (OperatingSystem.IsMacOS() ? "wheel" : "root");
        var dirMode = member ? "750" : "755";
        Sh($"chown root:{grp} {Q(home)} && chmod {dirMode} {Q(home)}", check: true);
    }

    public static void ApplyRootFilePerms(string path)
    {
        var (group, member) = RootGroup();
        var grp = group ?? (OperatingSystem.IsMacOS() ? "wheel" : "root");
        var mode = member ? "440" : "444";
        Sh($"chown root:{grp} {Q(path)} && chmod {mode} {Q(path)}", check: true);
        SetImmutable(path);
    }

    private static (string? Group, bool Member) RootGroup()
    {
        var user = Environment.GetEnvironmentVariable("SUDO_USER") ?? Environment.UserName;
        var group = Environment.GetEnvironmentVariable("SUDO_GROUP");
        var member = !string.IsNullOrEmpty(group) && Sh($"id -Gn {Q(user)} 2>/dev/null || true").Contains(group!);
        return (group, member);
    }

    /// <summary>清理中断残留的暂存文件（仅密文，可安全删除）。返回清理数量。</summary>
    public static int CleanStaging(string home)
    {
        var dir = Path.Combine(home, "run", "staging");
        if (!Directory.Exists(dir)) return 0;
        var count = 0;
        foreach (var f in Directory.EnumerateFiles(dir))
        {
            try { File.Delete(f); count++; } catch { }
        }
        return count;
    }

    internal static string Q(string p) => "'" + p.Replace("'", "'\\''") + "'";

    /// <summary>执行 shell 命令；check=true 时非零退出抛 VaultException。返回 stdout。</summary>
    internal static string Sh(string command, bool check = false)
    {
        var (code, output) = RunCapture("/bin/sh", ["-c", command]);
        if (check && code != 0)
            throw new VaultException($"加固命令失败（exit {code}）：{command}");
        return output;
    }

    public static (int Exit, string Output) RunCapture(string fileName, IReadOnlyList<string> args, bool showOutput = false)
    {
        var psi = new ProcessStartInfo(fileName) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = showOutput ? false : true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            if (!showOutput) p.StandardError.ReadToEnd();
            p.WaitForExit(10_000);
            return (p.HasExited ? p.ExitCode : -1, output);
        }
        catch (Exception e)
        {
            return (-1, e.Message);
        }
    }
}
