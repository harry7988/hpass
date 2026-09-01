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
            // 相对条目（"."、"./bin" 等）会随 CWD 解析——拒绝，防共享目录种植假 shell
            if (!Path.IsPathRooted(dir)) continue;
            try
            {
                var candidate = Path.Combine(dir.Trim(), exe);
                if (File.Exists(candidate) && Path.IsPathRooted(Path.GetFullPath(candidate))) return candidate;
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
            if (req.ScriptText is null)
                throw new UsageException("脚本模式必须由调用方一次读入内容（ScriptText）；按路径二次读取会重新引入 TOCTOU");
            // 先归一 CRLF（必须在占位符替换之前：注入的密文值本身可能含 \r\n，替换后归一会改写值导致脱敏失配）
            var script = req.ScriptText;
            var scriptShellName = ShellNameOf(shell);
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
                    if (OperatingSystem.IsWindows() && scriptShellName is "powershell" or "powershell.exe")
                        // 5.1 对重定向 stdin 按 OEM 代码页解码：非 ASCII 密文被改写 → 脱敏失配（I3 绕过面）
                        throw new UsageException("Windows PowerShell 5.1 的 stdin 按 OEM 代码页解码，会改写非 ASCII 密文导致脱敏失配——请安装 pwsh 7+（--shell pwsh）");
                    psi.FileName = shell;
                    psi.ArgumentList.Add("-NoProfile");
                    psi.ArgumentList.Add("-Command");
                    psi.ArgumentList.Add("-");
                    // -Command - 是逐语句 REPL 语义：退出码由最后一条语句决定（外部命令非 0/1 一律折叠为 1，
                    // 失败后跟一条成功语句则变 0）。合成 exit $LASTEXITCODE 保退出码透传（用户显式 exit 会提前返回，无害）
                    script += "\nexit $LASTEXITCODE\n";
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

        var shellName = ShellNameOf(shell);
        if (shell == "none")
        {
            psi.FileName = ResolveCommandName(resolved[0]);
            foreach (var a in resolved.Skip(1)) psi.ArgumentList.Add(a);
        }
        else if (shellName is "cmd" or "cmd.exe")
        {
            // cmd 的引号规则与 MSVCRT 不同：直接拼 raw 命令串交给 /c，不做参数级加引号；
            // chcp 65001：cmd 对管道输出用 OEM 代码页——非 ASCII 密文会与 UTF-8 脱敏规则失配
            psi.FileName = shell;
            psi.ArgumentList.Add("/c");
            psi.ArgumentList.Add("chcp 65001 >nul & " + string.Join(' ', resolved.Select((a, i) => i == 0 ? ResolveCommandName(a) : a)));
        }
        else if (shellName is "pwsh" or "pwsh.exe" or "powershell" or "powershell.exe")
        {
            psi.FileName = shell;
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-Command");
            var quoted = resolved.Select(QuoteForPwsh).ToArray();
            // Windows PowerShell 5.1 对重定向输出用 OEM/ANSI 代码页编码——非 ASCII 密文的字节形态会
            // 与 UTF-8 脱敏规则失配（I3 绕过）。前置强制 UTF-8 输出（pwsh 7 默认 UTF-8，无副作用）
            var prelude = OperatingSystem.IsWindows() ? "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " : "";
            var line = prelude + string.Join(' ', quoted);
            // 引号包裹的命令名在 pwsh -Command 里是字符串表达式而非调用——需要调用运算符 &
            if (quoted[0].StartsWith('\'')) line = "& " + line;
            psi.ArgumentList.Add(line);
        }
        else
        {
            psi.FileName = shell;
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(string.Join(' ', resolved.Select(QuoteForPosix)));
        }
        return StartAndWait(psi, req, stdoutSink, stderrSink, stdinText: null);
    }

    /// <summary>
    /// Windows 上裸命令名按"父目录→CWD→System32→PATH"解析（CreateProcessW 语义），预植可执行文件
    /// 能收割以密文为 argv 的进程——统一解析为 PATH 上的绝对路径，拒绝相对/CWD 命中。Unix 的
    /// execvp 走 PATH（不搜 CWD），保持原样。
    /// </summary>
    private static string ResolveCommandName(string command)
    {
        if (!OperatingSystem.IsWindows() || Path.IsPathRooted(command)) return command;
        // 固定文案：command 可能是解析后的密文（argv[0] 为占位符场景），不得回显（I5）
        return FindOnPath(command)
            ?? throw new UsageException("命令未在 PATH 中找到（拒绝当前目录命中，防可执行文件种植）；命令可能不存在、未安装，或首参数不是命令名");
    }

    /// <summary>Windows 文件系统大小写不敏感：统一小写匹配，避免 --shell PowerShell/CMD 落入错误分支。</summary>
    private static string ShellNameOf(string shellPath) =>
        OperatingSystem.IsWindows() ? Path.GetFileName(shellPath).ToLowerInvariant() : Path.GetFileName(shellPath);

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

    /// <summary>
    /// pwsh 按需单引号包裹（内部 ' 双写）。元字符集覆盖：空白/引号/反引号/逗号/流操作符/变量/通配/赋值，
    /// 以及 token 起始的 @（splatting）/ #（注释）/ --%（停止解析）。
    /// 注意：命令名（argv[0]）被引号包裹后在 -Command 模式是字符串表达式——调用方需加 &（见上）。
    /// </summary>
    public static string QuoteForPwsh(string arg) =>
        NeedsPwshQuote(arg) ? "'" + arg.Replace("'", "''") + "'" : arg;

    private static bool NeedsPwshQuote(string arg)
    {
        if (arg.Length == 0) return true;
        if (arg[0] is '@' or '#' || arg.StartsWith("--%")) return true;
        foreach (var c in arg)
            if (char.IsWhiteSpace(c) || c is '\'' or '"' or '`' or ',' or ';' or '&' or '|' or '(' or ')' or '<' or '>' or '{' or '}' or '$' or '*' or '?' or '[' or ']' or '=' or '^')
                return true;
        return false;
    }
}
