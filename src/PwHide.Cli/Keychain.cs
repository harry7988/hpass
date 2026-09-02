using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using PwHide.Core;

namespace PwHide.Cli;

/// <summary>
/// 系统钥匙串：把主口令存入 OS 安全存储（macOS Keychain / Windows 凭据管理器 / Linux Secret Service），
/// 之后 exec/set 等全部命令自动取用、零交互——口令只进 pwhide 进程内存，永不进入 AI 对话上下文。
/// 存储的是主口令本身（非 DEK），信任边界与 PWHIDE_PASSPHRASE_FILE（600 文件）同类：
/// 由操作系统负责静态加密与解锁策略；与本机同权限恶意软件不在威胁模型内（threat-model §5）。
/// PWHIDE_NO_KEYCHAIN=1 可全局跳过钥匙串读取。
///
/// 平台实现：
///   macOS  /usr/bin/security generic-password（service=pwhide, account=home 路径；每 --home 独立槽位）。
///          注意：add 的 -w 经 argv 传递，写入瞬间本机 ps 可见（与 exec 内联模式同类暴露，声明于 threat-model）。
///   Windows advapi32 CredWriteW/CredReadW（generic credential，blob=UTF-16 口令，进程内传递不经 argv）。
///   Linux   secret-tool（store 经 stdin 传口令；未安装即视为不支持）。
/// </summary>
public static class Keychain
{
    private const string Service = "pwhide";

    // 测试钩子：设置后绕过真实 OS 钥匙串（集成测试注入假实现；用完必须置回 null）
    internal static Func<bool>? HookIsSupported;
    internal static Func<string, string?>? HookTryGet;
    internal static Action<string, string>? HookStore;
    internal static Func<string, bool>? HookClear;

    public static bool IsSupported =>
        HookIsSupported is not null ? HookIsSupported()
        : OperatingSystem.IsMacOS() || OperatingSystem.IsWindows() || FindOnPath("secret-tool") is not null;

    public static string Describe() =>
        OperatingSystem.IsMacOS() ? "macOS Keychain（/usr/bin/security）"
        : OperatingSystem.IsWindows() ? "Windows 凭据管理器"
        : FindOnPath("secret-tool") is not null ? "Linux Secret Service（secret-tool）"
        : "当前平台不可用（Linux 需安装 secret-tool / libsecret）";

    /// <summary>读取当前 home 对应槽位的主口令。未存储返回 false。</summary>
    public static bool TryGet(string home, out string passphrase)
    {
        passphrase = "";
        if (HookTryGet is not null)
        {
            var hooked = HookTryGet(home);
            if (hooked is null) return false;
            passphrase = hooked;
            return true;
        }
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                var (exit, stdout, _) = Run("/usr/bin/security", ["find-generic-password", "-a", home, "-s", Service, "-w"]);
                if (exit != 0 || stdout.Length == 0) return false;
                passphrase = stdout;
                return true;
            }
            if (OperatingSystem.IsWindows())
                return TryGetWindows(Target(home), out passphrase);
            var tool = FindOnPath("secret-tool");
            if (tool is null) return false;
            var (lxExit, lxOut, _) = Run(tool, ["lookup", "service", Service, "account", home]);
            if (lxExit != 0 || lxOut.Length == 0) return false;
            passphrase = lxOut;
            return true;
        }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;   // 钥匙串不可用（无解锁会话等）：静默回退到下一口令来源
        }
    }

    /// <summary>存入（覆盖）主口令。失败抛 VaultException（含平台指引）。</summary>
    public static void Store(string home, string passphrase)
    {
        if (HookStore is not null) { HookStore(home, passphrase); return; }
        int exit;
        string error;
        if (OperatingSystem.IsMacOS())
            (exit, _, error) = Run("/usr/bin/security",
                ["add-generic-password", "-a", home, "-s", Service, "-w", passphrase, "-U"]);
        else if (OperatingSystem.IsWindows())
        {
            StoreWindows(Target(home), passphrase);
            return;
        }
        else
        {
            var tool = FindOnPath("secret-tool") ?? throw new VaultException("当前平台无钥匙串支持：Linux 需安装 secret-tool（libsecret-tools）；或改用 PWHIDE_PASSPHRASE_FILE（chmod 600）");
            (exit, _, error) = Run(tool, ["store", "--label=pwhide", "service", Service, "account", home],
                stdinData: passphrase + "\n");
        }
        if (exit != 0)
            throw new VaultException($"写入钥匙串失败（exit {exit}）：{error.Trim()}。可改用 PWHIDE_PASSPHRASE_FILE（chmod 600）");
    }

    /// <summary>删除槽位。返回 false = 本就没有存储。</summary>
    public static bool Clear(string home)
    {
        if (HookClear is not null) return HookClear(home);
        try
        {
            if (OperatingSystem.IsMacOS())
                return Run("/usr/bin/security", ["delete-generic-password", "-a", home, "-s", Service]).ExitCode == 0;
            if (OperatingSystem.IsWindows())
                return CredDeleteW(Target(home), CredTypeGeneric, 0);
            var tool = FindOnPath("secret-tool");
            if (tool is null) return false;
            return Run(tool, ["clear", "service", Service, "account", home]).ExitCode == 0;
        }
        catch (Exception e) when (e is IOException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    private static string Target(string home) => $"{Service}:{home}";

    private static (int ExitCode, string Stdout, string Stderr) Run(string file, string[] args, string? stdinData = null)
    {
        var psi = new ProcessStartInfo(file)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdinData is not null,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"无法启动 {file}");
        if (stdinData is not null)
        {
            p.StandardInput.Write(stdinData);
            p.StandardInput.Close();
        }
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit(10_000);
        return (p.ExitCode, stdout.TrimEnd('\n'), stderr);
    }

    private static string? FindOnPath(string exe)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var full = Path.Combine(dir, exe);
                if (File.Exists(full)) return full;
            }
            catch (ArgumentException) { }
        }
        return null;
    }

    // ---------- Windows 凭据管理器（advapi32，进程内 P/Invoke，不经命令行参数） ----------

    private const int CredTypeGeneric = 1;
    private const int CredPersistLocalMachine = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public int Flags;
        public int Type;
        public nint TargetName;      // LPWSTR
        public nint Comment;         // LPWSTR
        public int LastWrittenLow;
        public int LastWrittenHigh;
        public int CredentialBlobSize;
        public nint CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public nint Attributes;
        public nint TargetAlias;     // LPWSTR
        public nint UserName;        // LPWSTR
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWriteW(ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredReadW(string target, int type, int reservedFlag, out nint credentialPtr);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDeleteW(string target, int type, int flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(nint cred);

    private static void StoreWindows(string target, string passphrase)
    {
        var blob = Encoding.Unicode.GetBytes(passphrase);
        var blobPtr = Marshal.AllocHGlobal(blob.Length);
        var namePtr = Marshal.StringToHGlobalUni(target);
        try
        {
            System.Runtime.InteropServices.Marshal.Copy(blob, 0, blobPtr, blob.Length);
            var cred = new CREDENTIAL
            {
                Type = CredTypeGeneric,
                TargetName = namePtr,
                CredentialBlobSize = blob.Length,
                CredentialBlob = blobPtr,
                Persist = CredPersistLocalMachine,
                UserName = namePtr,
            };
            if (!CredWriteW(ref cred, 0))
                throw new VaultException($"写入 Windows 凭据管理器失败（Win32 {Marshal.GetLastWin32Error()}）");
        }
        finally
        {
            Marshal.FreeHGlobal(blobPtr);
            Marshal.FreeHGlobal(namePtr);
        }
    }

    private static bool TryGetWindows(string target, out string passphrase)
    {
        passphrase = "";
        if (!CredReadW(target, CredTypeGeneric, 0, out var ptr)) return false;
        try
        {
            var cred = Marshal.PtrToStructure<CREDENTIAL>(ptr);
            if (cred.CredentialBlobSize <= 0) return false;
            var blob = new byte[cred.CredentialBlobSize];
            Marshal.Copy(cred.CredentialBlob, blob, 0, blob.Length);
            passphrase = Encoding.Unicode.GetString(blob);
            return passphrase.Length > 0;
        }
        finally { CredFree(ptr); }
    }
}
