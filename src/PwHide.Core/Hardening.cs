using System.Diagnostics;
using System.Globalization;

namespace PwHide.Core;

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

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int open(string path, int flags);

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int fchown(int fd, uint owner, uint group);

    // Linux 64 位（x64/arm64 同布局）struct stat 前 16 字节 = st_dev(8) + st_ino(8)
    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int fstat(int fd, byte[] buf);

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int lstat(string path, byte[] buf);

    /// <summary>路径的 lstat 快照 (st_dev, st_ino)，用于跨操作复核路径未被偷换。</summary>
    public static (long Dev, long Ino) PathSnapshot(string path) => LStatPath(path);

    /// <summary>复核路径仍指向快照时的 inode（防"入口一次检查、后续按路径重解析"的偷换窗口）。</summary>
    public static void AssertUnchanged(string path, (long Dev, long Ino) snapshot, string what)
    {
        if (!OperatingSystem.IsLinux()) return;   // macOS 无 inode 复核（布局不同），依赖 O_NOFOLLOW
        var now = LStatPath(path);
        if (now.Dev < 0 || now != snapshot)
            throw new VaultException($"安全限制：{what} 在操作期间被替换（inode 不一致），已中止：{path}");
    }

    /// <summary>fd 的 (st_dev, st_ino)。缓冲必须 ≥ sizeof(struct stat)（Linux x64=144/arm64=128，macOS=144）——
    /// 只读前 16 字节但内核会写满整个结构体，16 字节缓冲会造成 root 进程堆越界写（实测复现）。</summary>
    private static (long Dev, long Ino) StatFd(int fd)
    {
        var buf = new byte[256];
        return fstat(fd, buf) != 0 ? (-1, -1) : (BitConverter.ToInt64(buf, 0), BitConverter.ToInt64(buf, 8));
    }

    /// <summary>路径的 lstat（不跟随链接）(st_dev, st_ino)。缓冲同上。</summary>
    private static (long Dev, long Ino) LStatPath(string path)
    {
        var buf = new byte[256];
        return lstat(path, buf) != 0 ? (-1, -1) : (BitConverter.ToInt64(buf, 0), BitConverter.ToInt64(buf, 8));
    }

    /// <summary>
    /// Linux inode 级同一性：fstat(fd) 与 lstat(path) 的 dev+ino 必须一致。免疫两个方向的偷换——
    /// open 前被换成链接（fd=链接目标，lstat=链接自身 inode）与 open 后被换（fd=原 inode，lstat=新 inode）。
    /// （字符串路径比较是"自洽"的：path 本身是链接时两侧都解析到攻击目标，恒等——已实证可绕过。）
    /// macOS 不适用（struct 布局不同）：依赖 O_NOFOLLOW（实测生效）+ 事后非链接复核。
    /// </summary>
    private static bool FdMatchesPathByInode(int fd, string path)
    {
        if (!OperatingSystem.IsLinux()) return true;
        var a = StatFd(fd);
        var b = LStatPath(path);
        return a.Dev >= 0 && b.Dev >= 0 && a == b;
    }

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int fchmod(int fd, uint mode);

    /// <summary>组名 → gid（失败 -1）。经 shell（getent/dscl）解析——getgrnam 的结构体编组在 AOT 下崩溃，弃用。</summary>
    public static int GroupGid(string name)
    {
        if (string.IsNullOrEmpty(name)) return -1;
        if (OperatingSystem.IsLinux())
        {
            var parts = Sh($"getent group {Q(name)} 2>/dev/null").Trim().Split(':');
            if (parts.Length >= 3 && int.TryParse(parts[2], out var g)) return g;
            return -1;
        }
        var ds = Sh($"dscl . -read /Groups/{Q(name)} PrimaryGroupID 2>/dev/null").Trim().Split(':');
        return ds.Length == 2 && int.TryParse(ds[1].Trim(), out var g2) ? g2 : -1;
    }

    /// <summary>
    /// sudo 绝对路径：裸名 "sudo" 经 execvp 沿用户可控 PATH 解析，攻击者植入假 sudo 可收割
    /// 口令（pwhide 先打印信任背书文案再 exec 假 sudo）或伪造 exit 0 假成功。找不到 → null（调用方降级手动指引）。
    /// </summary>
    public static string? SudoPath() =>
        File.Exists("/usr/bin/sudo") ? "/usr/bin/sudo"
        : File.Exists("/bin/sudo") ? "/bin/sudo"
        : File.Exists("/usr/local/bin/sudo") ? "/usr/local/bin/sudo"
        : null;

    /// <summary>
    /// fd-based 特权施权（root 核心）：open → 同一性复核（fd 真实路径==目标路径，防链接偷换）→
    /// fchown(root,gid) + fchmod。作用于 fd 锁定的 inode，永不被符号链接重定向——替代跟随链接的
    /// 按路径 chown/chmod（后者在"检查→执行"窗口内被换链可把任意文件过户/改权 = 提权，Docker 实证）。
    /// modeOctal 形如 0m440 的十进制值（0440=288, 0444=292）。
    /// </summary>
    public static void ApplyRootPermsFd(string path, string? group, bool member)
    {
        const int oRdonly = 0;
        var oNoFollow = OperatingSystem.IsMacOS() ? 0x0100 : 0x20000;
        var fd = open(path, oRdonly | oNoFollow);
        if (fd < 0)
            throw new VaultException($"无法打开目标执行特权施权（可能被替换为符号链接）：{path}");
        try
        {
            if (!FdMatchesPathByInode(fd, path))
                throw new VaultException($"安全限制：目标在施权瞬间被替换（fd 与路径 inode 不一致）：{path}");
            var gid = -1;
            if (group is not null)
            {
                gid = GroupGid(group);
                if (gid < 0) group = null;   // 组解析失败 → 仅 root 属主
            }
            if (fchown(fd, 0, gid < 0 ? 0 : (uint)gid) != 0)
                throw new VaultException($"fchown 失败（errno {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}）：{path}");
            var mode = member ? 288u : 292u;   // 0440 / 0444
            if (fchmod(fd, mode) != 0)
                throw new VaultException($"fchmod 失败（errno {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}）：{path}");
        }
        finally
        {
            close(fd);
        }
    }

    /// <summary>fd 解析路径与传入路径的同一性（双侧 final-target 解析，兼容符号链接祖先如 /tmp→/private/tmp）。</summary>
    private static bool SameFile(string resolvedRealPath, string path)
    {
        var a = resolvedRealPath.EndsWith(" (deleted)") ? "" : resolvedRealPath;
        var b = File.ResolveLinkTarget(path, returnFinalTarget: true)?.FullName ?? Path.GetFullPath(path);
        return string.Equals(a, b, StringComparison.Ordinal);
    }

    /// <summary>
    /// fd-based 安全读取：open 后经 /proc/self/fd/&lt;fd&gt; 对**已打开的 inode** 复核属主/大小再读。
    /// 消除"路径检查→按路径读"的 check-then-use 竞态（同 UID 攻击者在窗口内把 staging 换成指向
    /// root 专属文件的符号链接 → root 读取并安装为用户可读文件 = 跨特权泄露）。Linux 专用；
    /// open(O_RDONLY|O_NOFOLLOW) 尽力而为（该 flag 经 P/Invoke 的生效性平台不一），真正的闭环
    /// 在于 fd 已锁定 inode：即使 open 跟随了链接，基于 fd 的属主复核（==expectedUid）仍会拒绝。
    /// </summary>
    public static byte[] ReadStagedFdBased(string path, int expectedOwnerUid)
    {
        const int oRdonly = 0;
        var oNoFollow = OperatingSystem.IsMacOS() ? 0x0100 : 0x20000;   // 两平台常量均经实测验证
        var fd = open(path, oRdonly | oNoFollow);
        if (fd < 0)
            throw new VaultException($"无法打开暂存文件（可能被替换或为符号链接）：{path}");
        try
        {
            // fd 已锁定 inode：在 pwhide 进程内解析 fd 链接（Linux=/proc/self/fd/N，Darwin=/dev/fd/N）
            // 得到真实路径后复核属主/大小。即使 open 跟随了被换入的链接，属主复核仍会拒绝。
            // 注意 FileOwnerUid 经 shell 执行，不能用 /proc/self（那是 shell 的），必须用解析出的普通路径。
            var fdLink = OperatingSystem.IsLinux() ? $"/proc/self/fd/{fd}" : $"/dev/fd/{fd}";
            var resolved = File.ResolveLinkTarget(fdLink, returnFinalTarget: false)?.FullName;
            // 注：Darwin 的 /dev/fd/N 非符号链接（readlink EINVAL）→ resolved=null，
            // macOS 依赖 O_NOFOLLOW（实测生效）；Linux 走 inode 同一性 + 路径复核双保险
            var realPath = resolved ?? path;
            // inode 同一性（Linux，免疫 open 前后双向偷换）+ macOS 的字符串复核（防跟随链接）+ "(deleted)" 显式拒绝
            if (!FdMatchesPathByInode(fd, path)
                || (resolved is not null && (!SameFile(resolved, path) || resolved.EndsWith(" (deleted)"))))
                throw new VaultException("安全限制：暂存文件在打开瞬间被替换（fd 与路径不一致），拒绝安装");
            var info = new FileInfo(realPath);
            if (expectedOwnerUid >= 0 && FileOwnerUid(realPath) != expectedOwnerUid)
                throw new VaultException("安全限制：暂存文件在打开瞬间被替换（属主与校验时不一致），拒绝安装");
            if (info.Length > 8 * 1024 * 1024)
                throw new VaultException($"暂存文件过大（{info.Length} 字节），拒绝安装");
            using var fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle((IntPtr)fd, ownsHandle: false),
                FileAccess.Read);
            using var ms = new MemoryStream();
            var buf = new byte[64 * 1024];
            int n;
            while ((n = fs.Read(buf, 0, buf.Length)) > 0)
            {
                ms.Write(buf, 0, n);
                if (ms.Length > 8 * 1024 * 1024)   // 读入中强制上限（防 FIFO/持续追加的无限读）
                    throw new VaultException("暂存文件超出大小上限，拒绝安装");
            }
            return ms.ToArray();
        }
        finally
        {
            close(fd);
        }
    }

    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    /// <summary>
    /// 裸 open(O_RDWR|O_NOFOLLOW)：不经 .NET 的共享模拟（其把写访问变为排他 fcntl，并发 open 即冲突），
    /// 且绝不跟随符号链接——root 侧后续的属主归还/加锁若落在链接上会把特权操作重定向到任意文件（提权）。
    /// 文件由 .NET 预创建并收紧 600——libc 的 open 是变参函数，mode 参数经默认 P/Invoke 传参
    /// 在 arm64 macOS 上会丢失/错乱（实测），因此只做两参数调用（无 O_CREAT，无需 mode）。
    /// </summary>
    public static Microsoft.Win32.SafeHandles.SafeFileHandle OpenLockFile(string path)
    {
        const int oRdwr = 2;
        var oNoFollow = OperatingSystem.IsMacOS() ? 0x0100 : 0x20000;   // 平台常量不同（实测 macOS=0x100；Linux=0o400000=0x20000）
        if (!File.Exists(path))
        {
            try { using var _ = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite); }
            catch (IOException) { /* 并发首建：败者直接走后续 open */ }
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch { }
        }
        // 托管 LinkTarget 判定为主防线（P/Invoke open 的 O_NOFOLLOW 在 Linux 实测不生效、macOS 生效——
        // 平台行为不一致，故不依赖）。检查与 open 之间的残余竞态由 root 侧 chown -h（lchown）兜底。
        if (IsSymbolicLink(path))
            throw new VaultException($"run/lock 是符号链接（可能的攻击或残留）：请检查并删除 {path} 后重试");
        var fd = open(path, oRdwr | oNoFollow);
        if (fd < 0)
        {
            var errno = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            throw new IOException($"无法打开锁文件 {path}（errno {errno}）。若为 sudo 运行遗留的属主异常，可删除该文件后重试");
        }
        return new Microsoft.Win32.SafeHandles.SafeFileHandle((IntPtr)fd, ownsHandle: true);
    }

    /// <summary>
    /// 跨进程互斥锁：.NET 的 FileShare 在 Unix 上无强制力（dotnet/runtime#59995），必须 flock。
    /// 限时阻塞等待（默认 60s）而非立即失败——并发写（AI 同时触发多条 set）应排队而非大量报错。
    /// 返回是否获得锁；false = 超时。
    /// </summary>
    public static bool FlockExclusive(Microsoft.Win32.SafeHandles.SafeFileHandle handle, int timeoutMs = 60_000)
    {
        if (!Unix) return true;
        var fd = handle.DangerousGetHandle().ToInt32();
        var deadline = Environment.TickCount64 + timeoutMs;
        while (true)
        {
            if (flock(fd, LockEx | LockNb) == 0) return true;
            if (Environment.TickCount64 >= deadline) return false;
            System.Threading.Thread.Sleep(100);
        }
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
        if (!File.Exists(file)) return Loc.T("unknown", "未知");
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            var mode = File.GetUnixFileMode(file);
            return mode.HasFlag(UnixFileMode.UserWrite)
                ? Loc.T("user-level immutable (uchg)", "用户级不可变（uchg）")
                : Loc.T("admin level (root-owned + immutable)", "管理员级（root 属主 + 不可变）");
        }
        return Loc.T("ACL write-denied", "ACL 拒写");
    }

    /// <summary>
    /// 设置不可变标志：root → schg / chattr +i；普通用户 macOS → uchg。
    /// 返回是否成功：Linux 上 chattr 需 root 且文件系统须支持（overlayfs/tmpfs/NFS 等不支持）——
    /// 不支持时降级返回 false（加密与原子覆盖不受影响，保护等级由 doctor/GetLevel 如实报告），
    /// 调用方不得因不可变不可用而阻断安装。
    /// </summary>
    public static bool SetImmutable(string path)
    {
        if (OperatingSystem.IsMacOS())
        {
            Sh($"chflags {(IsRoot() ? "schg" : "uchg")} {Q(path)}", check: true);
            return true;
        }
        if (OperatingSystem.IsLinux())
        {
            _ = Sh($"chattr +i {Q(path)} 2>/dev/null");
            return LastShellExit == 0;   // 文件系统不支持 chattr（overlayfs 等）→ false，调用方降级
        }
        return false;
    }

    /// <summary>最近一次 Sh 调用的退出码（供需要"不抛但要看结果"的调用方读取）。</summary>
    private static int LastShellExit;

    private static string ShImpl(string command, bool check)
    {
        var (code, output) = RunCapture("/bin/sh", ["-c", command]);
        LastShellExit = code;
        if (check && code != 0)
            throw new VaultException($"加固命令失败（exit {code}）：{command}");
        return output;
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
        // 目录先打开并校验：入口检查到文件施权之间隔着多次 shell 派生（毫秒级窗口），先钉住 inode 再动文件
        var earlyNoFollow = OperatingSystem.IsMacOS() ? 0x0100 : 0x20000;
        var earlyFd = open(home, 0 | earlyNoFollow);
        if (earlyFd < 0)
            throw new VaultException($"安全限制：无法打开 home 目录执行施权前校验：{home}");   // fail-closed，不静默跳过
        try
        {
            if (!FdMatchesPathByInode(earlyFd, home))
                throw new VaultException($"安全限制：home 目录在施权前校验失败（可能被替换）：{home}");
        }
        finally { close(earlyFd); }
        foreach (var f in CoreFiles)
        {
            var p = Path.Combine(home, f);
            if (File.Exists(p)) ApplyRootFilePerms(p);
        }
        // 目录属主收紧只在能识别真实调用用户时进行：root 直接运行（su / sudo-from-root，SUDO_USER 缺失或为 root）
        // 时保持目录原属主——否则 chown root:root 750 会让用户连进入 home 都做不到，exec 读路径全部锁死
        var fromRealUser = RealSudoUser() is not null;
        if (fromRealUser)
        {
            // 目录施权同样 fd 化：按路径 chown/chmod 在检查→执行窗口被换链会把任意目录过户改权（实证）。
            // O_RDONLY+O_NOFOLLOW 打开目录即得 dirfd（实测可用；O_DIRECTORY 常量跨平台有坑故不用）：
            // macOS 上 O_NOFOLLOW 实测生效挡住链接偷换；Linux 上该 flag 被丢弃但 inode 同一性兜底。
            const int oRdonly = 0;
            var oNoFollowDir = OperatingSystem.IsMacOS() ? 0x0100 : 0x20000;
            var dirFd = open(home, oRdonly | oNoFollowDir);
            if (dirFd < 0 || !FdMatchesPathByInode(dirFd, home))
                throw new VaultException($"安全限制：home 目录在施权瞬间被替换或无法打开：{home}");
            try
            {
                var (group, member) = RootGroup();
                var gid = group is null ? 0 : GroupGid(group is null ? "" : group);
                if (gid < 0) gid = 0;   // 组解析失败 → root 组（fail-closed：宁可收紧）
                if (fchown(dirFd, 0, (uint)gid) != 0 || fchmod(dirFd, member ? 488u : 493u) != 0)   // 0750(=488) / 0755(=493)，注意八进制换算
                    throw new VaultException($"home 目录 fd 施权失败：{home}");
            }
            finally
            {
                close(dirFd);
            }
        }
        // 操作后复核：目录/文件在窗口内被换成符号链接即中止（rename-dance 之外的最后防线）
        if (IsSymbolicLink(home)) throw new VaultException($"特权操作后 {home} 变成了符号链接，已中止（可能的提权攻击）");
    }

    /// <summary>仅 chown/chmod（不设不可变）——供"rename 前对新文件先行确权"使用；不可变必须在 rename 之后。
    /// fd-based（fchown/fchmod 作用于锁定的 inode + 同一性复核）：按路径 chown/chmod 会跟随符号链接，
    /// 检查与执行窗口内被换链可把任意文件过户/改权（Docker 实证提权）。</summary>
    public static void ApplyRootOwnershipOnly(string path)
    {
        if (IsSymbolicLink(path)) throw new VaultException($"拒绝对符号链接执行特权操作：{path}（可能的提权攻击）");
        if (RealSudoUser() is null)
        {
            ApplyRootPermsFd(path, group: null, member: false);   // root 直接运行：不改组对齐，444
            return;
        }
        var (group, member) = RootGroup();
        ApplyRootPermsFd(path, group ?? (OperatingSystem.IsMacOS() ? "wheel" : "root"), member);
    }

    public static void ApplyRootFilePerms(string path)
    {
        if (IsSymbolicLink(path)) throw new VaultException($"拒绝对符号链接执行特权操作：{path}（可能的提权攻击）");
        if (RealSudoUser() is null)
        {
            // root 直接运行：不改属主（用户仍可读），444 + 不可变已构成"只可整体覆盖"保护
            ApplyRootPermsFd(path, group: null, member: false);
            _ = SetImmutable(path);
            return;
        }
        var (group, member) = RootGroup();
        ApplyRootPermsFd(path, group ?? (OperatingSystem.IsMacOS() ? "wheel" : "root"), member);
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
        var runDir = Path.Combine(home, "run");
        var dir = Path.Combine(runDir, "staging");
        // run/ 或 staging/ 是符号链接 → 拒绝清理：root 运行 doctor 时可被重定向为
        // "root 删除任意目录文件"（Docker 实证）；用户态同样是异常状态，统一 fail-closed
        if (IsSymbolicLink(runDir) || IsSymbolicLink(dir))
            throw new VaultException($"run/staging 是符号链接（可能的攻击或残留），拒绝清理：{dir}");
        if (!Directory.Exists(dir)) return 0;
        var count = 0;
        foreach (var f in Directory.EnumerateFiles(dir))
        {
            try
            {
                if (IsSymbolicLink(f)) continue;   // 链接项不删除（防经 EnumerateFiles 跟随列举出的目标侧效应）
                if ((DateTime.UtcNow - File.GetLastWriteTimeUtc(f)).TotalSeconds < minAgeSeconds) continue;
                File.Delete(f);
                count++;
            }
            catch { }
        }
        return count;
    }

    /// <summary>
    /// sudo 前校验自身可执行路径可信，分两档：
    /// - 宽松（免密 sudo -n 分支）：属主为当前用户或 root + 目录链无 group/other 写 + 无链接
    ///   （NOPASSWD 环境下同 UID 本就可 sudo 任意命令，无增量风险）；
    /// - 严格（交互输密码分支）：二进制及目录链必须全为 root 属主——用户属主的 pwhide 位于
    ///   用户可写位置（如 ~/.local/bin），同 UID 替换木马后借"pwhide 例行 sudo 提示"获得
    ///   密码认证过的 root 代码执行。严格档不过则降级为手动指引（用户亲眼看清 sudo 目标）。
    /// </summary>
    public static bool IsTrustedBinaryPath(string path, bool requireRootOwner = false)
    {
        if (!Unix) return true;
        try
        {
            var full = Path.GetFullPath(path);
            var uid = geteuid();
            var owner = FileOwnerUid(full);
            if (owner != (int)uid && owner != 0) return false;
            if (requireRootOwner && owner != 0) return false;
            var dir = Path.GetDirectoryName(full);
            while (!string.IsNullOrEmpty(dir))
            {
                if (IsSymbolicLink(dir)) return false;
                var mode = File.GetUnixFileMode(dir);
                if (mode.HasFlag(UnixFileMode.GroupWrite) || mode.HasFlag(UnixFileMode.OtherWrite)) return false;
                if (requireRootOwner)
                {
                    var dirOwner = FileOwnerUid(dir);
                    if (dirOwner != 0) return false;
                }
                var parent = Path.GetDirectoryName(dir);
                if (parent is null || parent == dir) break;
                dir = parent;
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>真实调用用户（sudo 由普通用户发起时才有；su/root-shell 下为 null）。找不到时特权操作不得改变属主。</summary>
    public static string? RealSudoUser()
    {
        var u = Environment.GetEnvironmentVariable("SUDO_USER");
        return string.IsNullOrEmpty(u) || u == "root" ? null : u;
    }

    public static string Q(string p) => "'" + p.Replace("'", "'\\''") + "'";

    /// <summary>执行 shell 命令；check=true 时非零退出抛 VaultException。返回 stdout。</summary>
    public static string Sh(string command, bool check = false) => ShImpl(command, check);

    /// <summary>同 RunCapture，但额外捕获 stderr（用于把提权子进程的失败原因带回给调用方）。</summary>
    public static (int Exit, string Output, string Stderr) RunCaptureEx(string fileName, IReadOnlyList<string> args, int timeoutMs = 10_000, Action<ProcessStartInfo>? configure = null)
    {
        var psi = new ProcessStartInfo(fileName) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment.Remove("PWHIDE_PASSPHRASE");
        psi.Environment.Remove("PWHIDE_PASSPHRASE_FILE");
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
        psi.Environment.Remove("PWHIDE_PASSPHRASE");
        psi.Environment.Remove("PWHIDE_PASSPHRASE_FILE");
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
