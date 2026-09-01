using System.Text.Json;

namespace HPass.Core;

/// <summary>
/// 原子安全写入与"暂存 → 安装"两段式写入（I6：vault 变更只走整体覆盖路径，永不就地修改）。
///
/// 安装流程（清保护 → 原子 rename 覆盖 → 收紧权限 → 重新加保护）：
/// - 普通文件：直接原子覆盖（600）；
/// - 用户级不可变（uchg）：清 uchg → 覆盖 → 重新 uchg，全程用户态完成；
/// - 管理员级保护（root 属主 + schg/+i）：用户态无法清保护 → 自动以 sudo（先 -n 免密，再交互）重拉
///   自身执行 <c>_install-staged</c> 搬运。统一原则：跨进程移动的只有密文，明文永不出用户态进程。
///
/// root 安装路径（InstallStagedAsRoot）针对检查-使用窗口（TOCTOU）做了三层防御：
/// 1) 暂存目录链（run/、run/staging/）不得为符号链接；
/// 2) 读入暂存内容后做结构验证（合法的 VaultFile/MasterKeyFile/Config JSON、大小上限），
///    使"root 安装任意字节"的面收敛为"安装结构合法的密文"（伪造整库属已文档化的同 UID 面）；
/// 3) rename-dance：先把目标 rename 成临时名（rename 不跟随符号链接，拿到的一定是真身），
///    对新建文件施加 chown/chmod/不可变，全程操作的都是我们创建的常规文件，失败可回滚。
/// </summary>
public static class SecureFile
{
    private const int MaxStagedBytes = 8 * 1024 * 1024;

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
        RejectSymlinks(stagingPath, finalPath);
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
        RejectSymlinks(stagingPath, finalPath);
        RejectSymlinkedStagingAncestors(stagingPath);
        var wasImmutable = Hardening.IsImmutable(finalPath);   // 必须在清保护前记录，安装后原样恢复
        if (Hardening.IsRoot())
        {
            InstallStagedAsRoot(stagingPath, finalPath);
            return;
        }
        Hardening.ClearImmutable(finalPath);
        InstallDirect(stagingPath, finalPath, wasImmutable);
    }

    /// <summary>root 专用安装：内容验证 + 两段 rename（见类注释）。</summary>
    private static void InstallStagedAsRoot(string stagingPath, string finalPath)
    {
        var content = ReadAndValidateStaged(stagingPath, finalPath);
        var dir = Path.GetDirectoryName(Path.GetFullPath(finalPath))!;
        var orig = finalPath + ".hpass-orig-" + Guid.NewGuid().ToString("N");
        var fresh = finalPath + ".hpass-new-" + Guid.NewGuid().ToString("N");
        var hadFinal = File.Exists(finalPath) || Hardening.IsSymbolicLink(finalPath);

        // 1) 真身转移到 orig：rename(2) 不跟随符号链接；转移后复核（悬空/目录链接已被入口拒绝，
        //    此处捕获的是竞态偷换），失败即恢复并中止
        if (hadFinal)
        {
            Hardening.ClearImmutable(finalPath);
            File.Move(finalPath, orig);
            if (Hardening.IsSymbolicLink(orig))
            {
                File.Move(orig, finalPath);
                throw new VaultException($"目标在安装瞬间被替换为符号链接，已中止：{finalPath}（可能的提权攻击）");
            }
        }
        try
        {
            // 2) 新内容写同目录随机名：CreateNew 语义为 O_CREAT|O_EXCL——已存在（含符号链接）即失败，
            //    绝不跟随链接，杜绝"按名写入被链接重定向到任意路径"
            using (var fs = new FileStream(fresh, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(content);
                fs.Flush(flushToDisk: true);
            }
            // 3) chown/chmod 可先做；**不可变标志必须在 rename 之后**——rename(2) 对不可变文件
            //    无条件 EPERM（root 也不例外），先加标志会让整条安装路径确定性失败
            Hardening.ApplyRootOwnershipOnly(fresh);
            // 4) rename 覆盖 final：同样不跟随链接
            File.Move(fresh, finalPath, overwrite: true);
            Hardening.SetImmutable(finalPath);
            if (Hardening.IsSymbolicLink(finalPath))
                throw new VaultException($"安装后目标变成符号链接，已中止：{finalPath}（可能的攻击）");
        }
        catch
        {
            // 回滚：优先恢复旧真身；恢复失败时保留 orig（唯一副本）并在错误信息中给出恢复指引
            try { if (File.Exists(fresh)) File.Delete(fresh); } catch { }
            if (hadFinal)
            {
                try { File.Move(orig, finalPath); }
                catch
                {
                    throw new VaultException($"安装失败且回滚失败：原文件已保留在 {orig}，请手动改名恢复为 {Path.GetFileName(finalPath)}");
                }
            }
            throw;
        }
        // 4) 仅在成功后删除旧真身（finally 无条件删除会在回滚失败时销毁唯一副本）
        try { if (File.Exists(orig)) File.Delete(orig); } catch { }
    }

    /// <summary>读入暂存内容并验证结构合法（按最终文件名选类型），root 只安装"结构合法的密文"。</summary>
    private static byte[] ReadAndValidateStaged(string stagingPath, string finalPath)
    {
        var pre = new FileInfo(stagingPath).Length;     // 读前预检：防超大文件先全量载入 root 内存
        if (pre > MaxStagedBytes)
            throw new VaultException($"暂存文件过大（{pre} > {MaxStagedBytes} 字节），拒绝安装");
        var content = File.ReadAllBytes(stagingPath);   // 单次打开读取，长度以读到的为准（缩小 check-use 窗口）
        if (content.Length > MaxStagedBytes)
            throw new VaultException($"暂存文件过大（{content.Length} > {MaxStagedBytes} 字节），拒绝安装");
        var name = Path.GetFileName(finalPath);
        try
        {
            object? parsed = name switch
            {
                "vault.json" => JsonSerializer.Deserialize(content, HPassJsonContext.Default.VaultFile),
                "master.key" => JsonSerializer.Deserialize(content, HPassJsonContext.Default.MasterKeyFile),
                "config.json" => JsonSerializer.Deserialize(content, HPassJsonContext.Default.HPassConfig),
                _ => throw new VaultException($"未知目标文件：{name}"),
            };
            if (parsed is null) throw new VaultException("暂存内容反序列化为空");
        }
        catch (JsonException e)
        {
            throw new VaultException($"暂存内容不是合法的 {name}（{e.GetType().Name}），拒绝安装");
        }
        return content;
    }

    /// <summary>暂存目录链（run/、run/staging/）含符号链接即拒绝：路径前缀白名单会被链接解析绕过。</summary>
    private static void RejectSymlinkedStagingAncestors(string stagingPath)
    {
        var stagingRoot = Path.GetDirectoryName(Path.GetFullPath(stagingPath))!;   // …/run/staging
        var runDir = Path.GetDirectoryName(stagingRoot);                            // …/run
        var home = runDir is null ? null : Path.GetDirectoryName(runDir);           // …/.hpass
        foreach (var d in new[] { home, runDir, stagingRoot })
        {
            if (d is not null && Hardening.IsSymbolicLink(d))
                throw new VaultException($"暂存目录链含符号链接：{d}（可能的路径劫持）");
        }
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
        {
            // 搬进来的若是被偷换的符号链接（rename 搬链接本体）：删除残留再报错，不留读取重定向
            if (Hardening.IsSymbolicLink(finalPath))
            {
                try { File.Delete(finalPath); } catch { }
                throw new VaultException($"暂存在安装前被替换为符号链接，已中止：{stagingPath}（可能的路径劫持）");
            }
            Hardening.ApplyRootFilePerms(finalPath);   // root 搬运：恢复 root 属主 + 不可变
        }
        else
        {
            Restrict(finalPath);                        // 600
            if (wasImmutable) Hardening.SetImmutable(finalPath); // 重新加保护（用户级 uchg）
        }
    }

    /// <summary>symlink 一律拒绝：rename/chmod/chown 对链接的语义差异会被用来把特权操作重定向到任意路径。</summary>
    private static void RejectSymlinks(string stagingPath, string finalPath)
    {
        if (Hardening.IsSymbolicLink(stagingPath))
            throw new VaultException($"暂存文件是符号链接，拒绝安装：{stagingPath}（可能的路径劫持）");
        if (Hardening.IsSymbolicLink(finalPath))
            throw new VaultException($"目标文件是符号链接，拒绝安装：{finalPath}（可能的提权攻击）");
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
        var hint = $"vault 处于管理员写保护。请手动执行：sudo hpass --home {Hardening.Q(homeDir ?? "")} _install-staged {Hardening.Q(stagingPath)} {Hardening.Q(finalPath)}";
        if (!Hardening.Unix)
            throw new NeedsElevationException(stagingPath, finalPath, "Windows：文件 ACL 拒写，请以管理员重新运行本命令（hpass harden 输出含 icacls 指引）");
        if (Environment.GetEnvironmentVariable("HPASS_NO_SUDO") == "1")
            throw new NeedsElevationException(stagingPath, finalPath, hint + "（当前环境已禁用自动 sudo）");
        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
            throw new NeedsElevationException(stagingPath, finalPath, hint + "（无法定位 hpass 可执行文件）");

        var home = homeDir ?? Vault.DefaultHome();
        // 1) 免密 sudo（CI / 自动化），只搬运密文。子进程带 HPASS_CHILD_INSTALL 标记：
        //    写锁由父进程持有（临界区保护不变），子进程跳过重复获取以免自锁
        // 可信性校验：hpass 自身位于用户可写路径（如 ~/.local/bin）时不自动提权——
        // 同 UID 替换木马可借"hpass 例行 sudo 提示"收割密码；改打手动指引让用户看清 sudo 目标
        if (!Hardening.IsTrustedBinaryPath(exe))
            throw new NeedsElevationException(stagingPath, finalPath,
                $"hpass 位于不受信任的路径（{exe}，用户可写位置），已禁用自动 sudo。请先校验该二进制或安装到 /usr/local/bin 后重试；" + hint);

        // 子进程标志经 argv 传递（--child-install）：sudo 的 env_reset 会剥离环境变量，argv 不会被改动
        var args = new List<string> { "--home", home, "_install-staged", "--child-install", stagingPath, finalPath };
        var (code, _, err1) = Hardening.RunCaptureEx("sudo", ["-n", "--", exe, .. args]);
        if (code == 0) return;
        // 2) 交互终端：先给一行可识别的先行信号（防钓鱼条件反射），再由 sudo 自行提示密码（/dev/tty，不经 argv）
        if (!Console.IsInputRedirected)
        {
            Console.Error.WriteLine("hpass: 即将请求 sudo 密码以安装 vault 变更（仅搬运密文，目标为上述 vault 文件）");
            var (code2, _, _) = Hardening.RunCaptureEx("sudo", ["--", exe, .. args], timeoutMs: 300_000);
            if (code2 == 0) return;
        }
        // 提权子进程的失败原因（固定文案，不含密文）带回给用户定位
        var childErr = err1.Length > 0 ? "；提权子进程输出：" + (err1.Length > 300 ? err1[..300] : err1).Trim() : "";
        throw new NeedsElevationException(stagingPath, finalPath, hint + childErr);
    }
}
