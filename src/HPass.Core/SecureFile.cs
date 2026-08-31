using System.Diagnostics;

namespace HPass.Core;

/// <summary>
/// 原子安全写入与"暂存 → 安装"两段式写入（I6：vault 变更只走整体覆盖路径，永不就地修改）。
///
/// 安装流程（清保护 → 原子 rename 覆盖 → 收紧权限 → 重新加保护）：
/// - 普通文件：直接原子覆盖（600）；
/// - 用户级不可变（uchg）：清 uchg → 覆盖 → 重新 uchg，全程用户态完成；
/// - 管理员级保护（root 属主 + schg/+i）：用户态无法清保护 → 自动以 sudo（先 -n 免密，再交互）重拉
///   自身执行 <c>_install-staged</c> 搬运。统一原则：跨进程移动的只有密文，明文永不出用户态进程。
/// </summary>
public static class SecureFile
{
    /// <summary>原子写入（无保护场景的基础路径）：临时文件 → fsync → rename → 收紧权限。</summary>
    public static void WriteAtomic(string path, byte[] data)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
        var tmp = Path.Combine(dir, "." + Path.GetFileName(path) + ".tmp-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(data);
                fs.Flush(flushToDisk: true);
            }
            Restrict(tmp);
            File.Move(tmp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    /// <summary>
    /// 把暂存文件安装到最终路径（vault.json / master.key 的唯一变更入口）。
    /// 暂存文件必须只含密文。需要提权时自动尝试 sudo 搬运，仍失败抛 NeedsElevationException（退出码 3）。
    /// </summary>
    public static void InstallStaged(string stagingPath, string finalPath, string? homeDir)
    {
        if (!File.Exists(stagingPath))
            throw new VaultException($"暂存文件不存在：{stagingPath}");
        if (CanInstallDirect(finalPath, out var wasImmutable))
        {
            InstallDirect(stagingPath, finalPath, wasImmutable);
            return;
        }
        TryElevatedInstall(stagingPath, finalPath, homeDir);
    }

    /// <summary>提权子进程（_install-staged）使用的直装路径：不再触发二次提权。</summary>
    public static void InstallStagedDirect(string stagingPath, string finalPath)
    {
        if (!File.Exists(stagingPath))
            throw new VaultException($"暂存文件不存在：{stagingPath}");
        var wasImmutable = Hardening.IsImmutable(finalPath);   // 必须在清保护前记录，安装后原样恢复
        Hardening.ClearImmutable(finalPath);
        InstallDirect(stagingPath, finalPath, wasImmutable);
    }

    private static bool CanInstallDirect(string finalPath, out bool wasImmutable)
    {
        wasImmutable = Hardening.IsImmutable(finalPath);
        if (!File.Exists(finalPath)) return true;
        Hardening.ClearImmutable(finalPath);
        return Hardening.IsUserWritable(finalPath);
    }

    private static void InstallDirect(string stagingPath, string finalPath, bool wasImmutable)
    {
        try
        {
            File.Move(stagingPath, finalPath, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new NeedsElevationException(stagingPath, finalPath, "目标文件不可写（管理员写保护），需要提权安装");
        }
        if (Hardening.IsRoot())
            Hardening.ApplyRootFilePerms(finalPath);   // root 搬运：恢复 root 属主 + 不可变
        else
        {
            Restrict(finalPath);                        // 600
            if (wasImmutable) Hardening.SetImmutable(finalPath); // 重新加保护（用户级 uchg）
        }
    }

    /// <summary>Unix 0600 / Windows 沿用目录 ACL。</summary>
    public static void Restrict(string path)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch { }
        }
    }

    private static void TryElevatedInstall(string stagingPath, string finalPath, string? homeDir)
    {
        var hint = $"vault 处于管理员写保护。请手动执行：sudo hpass --home \"{homeDir}\" _install-staged \"{stagingPath}\" \"{finalPath}\"";
        if (!Hardening.Unix)
            throw new NeedsElevationException(stagingPath, finalPath, "Windows：文件 ACL 拒写，请以管理员重新运行本命令（hpass harden 输出含 icacls 指引）");
        if (Environment.GetEnvironmentVariable("HPASS_NO_SUDO") == "1")
            throw new NeedsElevationException(stagingPath, finalPath, hint + "（当前环境已禁用自动 sudo）");
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
            throw new NeedsElevationException(stagingPath, finalPath, hint + "（无法定位 hpass 可执行文件）");

        var home = homeDir ?? Vault.DefaultHome();
        // 1) 免密 sudo（CI / 自动化），只搬运密文
        var args = new List<string> { "--home", home, "_install-staged", stagingPath, finalPath };
        var (code, _) = Hardening.RunCapture("sudo", ["-n", "--", exe, .. args]);
        if (code == 0) return;
        // 2) 交互终端：sudo 自行提示密码（写入 /dev/tty，不经 argv）
        if (!Console.IsInputRedirected)
        {
            var (code2, _) = Hardening.RunCapture("sudo", ["--", exe, .. args], showOutput: true);
            if (code2 == 0) return;
        }
        throw new NeedsElevationException(stagingPath, finalPath, hint);
    }
}
