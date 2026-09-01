using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace HPass.Core;

public sealed record ExecRequest
{
    /// <summary>命令模式：argv 形式（占位符在参数内）。脚本模式下忽略。</summary>
    public IReadOnlyList<string> Args { get; init; } = [];
    /// <summary>脚本模式：脚本路径（用于诊断；执行内容以 ScriptText 为准）。</summary>
    public string? ScriptPath { get; init; }
    /// <summary>脚本模式：脚本内容（由调用方一次性读入，避免"校验读一次、执行再读一次"的 TOCTOU）。</summary>
    public string? ScriptText { get; init; }
    /// <summary>auto|bash|sh|pwsh|cmd|none。</summary>
    public string Shell { get; init; } = "auto";
    /// <summary>环境变量注入：VAR → 密文值（如 db → MYSQL_PWD）。</summary>
    public IReadOnlyDictionary<string, string> EnvInject { get; init; } = new Dictionary<string, string>();
    public int TimeoutSeconds { get; init; } = 120;
    /// <summary>占位符解析（未知条目抛 PlaceholderException）。绝不能直接回显解析结果。</summary>
    public Func<string, string> Resolve { get; init; } = _ => throw new UsageException("no resolver");
    /// <summary>脱敏规则：secret → token。</summary>
    public IReadOnlyDictionary<string, string> RedactionRules { get; init; } = new Dictionary<string, string>();
}

public sealed class ExecResult
{
    public int ExitCode { get; init; }
    public bool TimedOut { get; init; }
    /// <summary>各占位符在输出中的替换次数（stdout+stderr 合计），用于高频碰撞检测。</summary>
    public IReadOnlyDictionary<string, int> ReplacementCounts { get; init; } = new Dictionary<string, int>();
}

/// <summary>
/// 执行引擎：解析占位符 → 组装子进程 → 流式脱敏转发 stdout/stderr → 超时杀进程（组）。
/// </summary>
public static class ShellLauncher
{
    private static readonly string[] AutoOrderUnix = ["bash", "sh"];
    private static readonly string[] AutoOrderWindows = ["pwsh", "powershell", "cmd"];

    [DllImport("libc", SetLastError = true)]
    private static extern int setpgid(int pid, int pgid);

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int sig);

    /// <summary>解析 shell 名称为绝对路径（不命中当前目录，防 CWD 可执行文件种植）。找不到抛 UsageException。</summary>
    public static string ResolveShell(string name)
    {
        if (name is "auto") name = DetectAuto();
        if (name is "none") return "none";
        var exe = name switch
        {
            "cmd" => OperatingSystem.IsWindows() ? "cmd.exe" : throw new UsageException("cmd 仅在 Windows 可用"),
            _ => name,
        };
        return FindOnPath(exe)
            ?? throw new UsageException($"找不到 shell：{exe}（可用 --shell 指定 bash/sh/pwsh/cmd，或 --shell none 直连执行）");
    }

    private static string DetectAuto()
    {
        string[] order = OperatingSystem.IsWindows() ? AutoOrderWindows : AutoOrderUnix;
        foreach (var s in order)
        {
            var exe = s == "cmd" ? "cmd.exe" : s;
            var full = FindOnPath(exe);
            if (full is not null) return full;
        }
        throw new UsageException("未探测到可用 shell，请用 --shell 显式指定");
    }

    /// <summary>只在 PATH（或绝对路径）上查找；相对路径的当前目录命中会被拒绝（Windows CreateProcess 也会搜 CWD）。</summary>
    private static string? FindOnPath(string exe)
    {
        if (OperatingSystem.IsWindows() && Path.GetExtension(exe).Length == 0)
            exe += ".exe";
        if (Path.IsPathRooted(exe))
            return File.Exists(exe) ? exe : null;
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        var sep = OperatingSystem.IsWindows() ? ';' : ':';
        foreach (var dir in pathVar.Split(sep, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), exe);
                if (File.Exists(candidate)) return candidate;
            }
            catch { }
        }
        return null;
    }

    public static ExecResult Run(ExecRequest req, Stream stdoutSink, Stream stderrSink)
    {
        var shell = ResolveShell(req.Shell);
        var scriptMode = req.ScriptPath is not null || req.ScriptText is not null;

        var psi = new ProcessStartInfo();
        psi.UseShellExecute = false;

        if (scriptMode)
        {
            // 先归一 CRLF（必须在占位符替换之前：注入的密文值本身可能含 \r\n，替换后归一会改写值导致脱敏失配）
            var script = req.ScriptText ?? File.ReadAllText(req.ScriptPath!);
            var scriptShellName = Path.GetFileName(shell);
            var isPwshScript = scriptShellName is "pwsh" or "pwsh.exe" or "powershell" or "powershell.exe";
            if (shell != "none" && !isPwshScript && scriptShellName is not "cmd" and not "cmd.exe")
                script = script.Replace("\r\n", "\n");   // Windows 编辑的 CRLF 会让 POSIX shell 把 \r 带进词法
            script = Placeholder.Replace(script, BuildTokenMap(req, script));
            switch (scriptShellName)
            {
                case "none":
                    throw new UsageException("脚本模式需要 shell（--shell auto|bash|sh|pwsh）");
                case "cmd" or "cmd.exe":
                    // cmd 无 stdin 脚本入口，按计划拒绝，引导用户改用 pwsh
                    throw new UsageException("cmd 不支持脚本 stdin 模式，请改用 pwsh（--shell pwsh）");
                case "pwsh" or "pwsh.exe" or "powershell" or "powershell.exe":
                    psi.FileName = shell;
                    psi.ArgumentList.Add("-NoProfile");
                    psi.ArgumentList.Add("-Command");
                    psi.ArgumentList.Add("-");
                    break;
                default: // bash / sh / zsh / dash …
                    psi.FileName = shell;
                    psi.ArgumentList.Add("-s");
                    break;
            }
            psi.RedirectStandardInput = true;
            return StartAndWait(psi, req, stdoutSink, stderrSink, stdinText: script);
        }

        // 命令模式
        var resolved = req.Args.Select(a => Placeholder.Replace(a, BuildTokenMap(req, a))).ToArray();
        if (resolved.Length == 0)
            throw new UsageException("缺少要执行的命令（hpass exec [-- 参数…] 或 -f 脚本）");

        var shellName = Path.GetFileName(shell);
        if (shell == "none")
        {
            psi.FileName = resolved[0];
            foreach (var a in resolved.Skip(1)) psi.ArgumentList.Add(a);
        }
        else if (shellName is "cmd" or "cmd.exe")
        {
            // cmd 的引号规则与 MSVCRT 不同：直接拼 raw 命令串交给 /c，不做参数级加引号
            psi.FileName = shell;
            psi.ArgumentList.Add("/c");
            psi.ArgumentList.Add(string.Join(' ', resolved));
        }
        else if (shellName is "pwsh" or "pwsh.exe" or "powershell" or "powershell.exe")
        {
            psi.FileName = shell;
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-Command");
            psi.ArgumentList.Add(string.Join(' ', resolved.Select(QuoteForPwsh)));
        }
        else
        {
            psi.FileName = shell;
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(string.Join(' ', resolved.Select(QuoteForPosix)));
        }
        return StartAndWait(psi, req, stdoutSink, stderrSink, stdinText: null);
    }

    private static Dictionary<string, string> BuildTokenMap(ExecRequest req, string text)
    {
        var map = new Dictionary<string, string>();
        foreach (var r in Placeholder.Extract(text))
        {
            var token = r.Token;
            if (!map.ContainsKey(token))
                map[token] = req.Resolve(token);
        }
        return map;
    }

    private static ExecResult StartAndWait(ProcessStartInfo psi, ExecRequest req, Stream stdoutSink, Stream stderrSink, string? stdinText)
    {
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.StandardOutputEncoding = Encoding.UTF8;
        psi.StandardErrorEncoding = Encoding.UTF8;
        // stdin 固定 UTF-8 且不带 BOM（BOM 会让 shell 把首行 shebang 当命令）：
        // 仅在真正重定向 stdin 时设置——未重定向时设置该属性会让 Process.Start 抛异常
        if (stdinText is not null)
            psi.StandardInputEncoding = new UTF8Encoding(false);

        foreach (var (var, value) in req.EnvInject)
            psi.Environment[var] = value;
        // 子进程环境不透传主口令（防 printenv/env 直接把口令打进输出——口令不在脱敏规则内）
        psi.Environment.Remove("HPASS_PASSPHRASE");
        psi.Environment.Remove("HPASS_PASSPHRASE_FILE");

        Process process;
        try
        {
            process = new Process { StartInfo = psi };
            process.Start();
        }
        catch (Exception)
        {
            // 固定文案：.NET 启动失败消息含 FileName——none 模式下 FileName 可能就是解析后的密文（I5 泄露）
            throw new UsageException("无法启动子进程（命令不存在或不可执行）");
        }
        using var _ = process;

        // Unix：把子进程放入独立进程组，超时可 kill(-pgid) 杀整组（尽力；double-fork 逃逸见 threat-model）
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            setpgid(process.Id, process.Id);

        var outRedactor = new StreamRedactor(req.RedactionRules);
        var errRedactor = new StreamRedactor(req.RedactionRules);

        var pumpOut = PumpAsync(process.StandardOutput.BaseStream, stdoutSink, outRedactor);
        var pumpErr = PumpAsync(process.StandardError.BaseStream, stderrSink, errRedactor);

        // stdin 异步写：子进程不读 stdin 且脚本大于管道容量时，同步写会永久阻塞并使 --timeout 失效
        Task? stdinTask = null;
        if (stdinText is not null)
        {
            var text = stdinText;
            stdinTask = Task.Run(() =>
            {
                try
                {
                    process.StandardInput.Write(text);
                    process.StandardInput.Flush();
                }
                catch (IOException) { /* 子进程提前退出 */ }
                catch (ObjectDisposedException) { }
                finally
                {
                    try { process.StandardInput.Close(); } catch { }
                }
            });
        }

        var timeoutMs = req.TimeoutSeconds <= 0 ? -1 : (int)Math.Min((long)req.TimeoutSeconds * 1000, int.MaxValue);
        if (!process.WaitForExit(timeoutMs))
        {
            KillProcessTree(process);
            process.WaitForExit(5_000);
            if (stdinTask is not null)
            {
                try { process.StandardInput.Close(); } catch { }
                stdinTask.Wait(2_000);
            }
            Task.WaitAll([pumpOut, pumpErr], 5_000);
            return new ExecResult { ExitCode = ExitCodes.Timeout, TimedOut = true, ReplacementCounts = MergeCounts(outRedactor, errRedactor) };
        }

        Task.WaitAll([pumpOut, pumpErr], 10_000);
        return new ExecResult { ExitCode = process.ExitCode, ReplacementCounts = MergeCounts(outRedactor, errRedactor) };
    }

    private static void KillProcessTree(Process process)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            _ = kill(-process.Id, 9); // 独立进程组：SIGKILL 整组（含已 reparent 的组员，尽力而为）
        try { process.Kill(entireProcessTree: true); } catch { }
    }

    private static IReadOnlyDictionary<string, int> MergeCounts(StreamRedactor a, StreamRedactor b)
    {
        var d = new Dictionary<string, int>(a.ReplacementCounts);
        foreach (var (k, v) in b.ReplacementCounts)
            d[k] = d.TryGetValue(k, out var cur) ? cur + v : v;
        return d;
    }

    private static async Task PumpAsync(Stream source, Stream sink, StreamRedactor redactor)
    {
        var buffer = new byte[8192];
        try
        {
            int n;
            while ((n = await source.ReadAsync(buffer).ConfigureAwait(false)) > 0)
            {
                var safe = redactor.Process(buffer.AsSpan(0, n));
                if (safe.Length > 0) await sink.WriteAsync(safe).ConfigureAwait(false);
            }
            var tail = redactor.Flush();
            if (tail.Length > 0) await sink.WriteAsync(tail).ConfigureAwait(false);
            await sink.FlushAsync().ConfigureAwait(false);
        }
        catch (IOException) { /* 管道关闭 */ }
        catch (ObjectDisposedException) { }
    }

    /// <summary>POSIX 单引号包裹，内部单引号转义为 '\''。</summary>
    public static string QuoteForPosix(string arg)
    {
        if (arg.Length == 0) return "''";
        if (!arg.Any(c => char.IsWhiteSpace(c) || c is '\'' or '"' or '$' or '`' or '\\' or '*' or '?' or '[' or ']' or '(' or ')' or ';' or '&' or '|' or '<' or '>' or '#' or '~' or '!' or '=' or '{' or '}'))
            return arg;
        return "'" + arg.Replace("'", "'\\''") + "'";
    }

    /// <summary>pwsh 无条件单引号包裹（内部 ' 双写）。PowerShell 元字符集大（反引号/逗号/@/# 起始等），快速通道必挂一漏万。</summary>
    public static string QuoteForPwsh(string arg) =>
        arg.Length == 0 ? "''" : "'" + arg.Replace("'", "''") + "'";
}
