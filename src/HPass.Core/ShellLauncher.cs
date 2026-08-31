using System.Diagnostics;
using System.Text;

namespace HPass.Core;

public sealed record ExecRequest
{
    /// <summary>命令模式：argv 形式（占位符在参数内）。脚本模式下忽略。</summary>
    public IReadOnlyList<string> Args { get; init; } = [];
    /// <summary>脚本模式：脚本路径（内容含占位符，经 stdin 交给 shell，不落盘替换结果）。</summary>
    public string? ScriptPath { get; init; }
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
}

/// <summary>
/// 执行引擎：解析占位符 → 组装子进程 → 流式脱敏转发 stdout/stderr → 超时杀进程树。
/// </summary>
public static class ShellLauncher
{
    private static readonly string[] UnixShells = ["bash", "sh"];
    private static readonly string[] AutoOrderUnix = ["bash", "sh"];
    private static readonly string[] AutoOrderWindows = ["pwsh", "powershell", "cmd"];

    /// <summary>解析 shell 名称为可执行文件。找不到抛 UsageException。</summary>
    public static string ResolveShell(string name)
    {
        if (name is "auto") name = DetectAuto();
        if (name is "none") return "none";
        var exe = name switch
        {
            "cmd" => OperatingSystem.IsWindows() ? "cmd.exe" : throw new UsageException("cmd 仅在 Windows 可用"),
            _ => name,
        };
        if (!ExistsOnPath(exe))
            throw new UsageException($"找不到 shell：{exe}（可用 --shell 指定 bash/sh/pwsh/cmd，或 --shell none 直连执行）");
        return exe;
    }

    private static string DetectAuto()
    {
        string[] order = OperatingSystem.IsWindows() ? AutoOrderWindows : AutoOrderUnix;
        foreach (var s in order)
        {
            var exe = s == "cmd" ? "cmd.exe" : s;
            if (ExistsOnPath(exe)) return s;
        }
        throw new UsageException("未探测到可用 shell，请用 --shell 显式指定");
    }

    private static bool ExistsOnPath(string exe)
    {
        if (File.Exists(exe)) return true;
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        var sep = OperatingSystem.IsWindows() ? ';' : ':';
        foreach (var dir in pathVar.Split(sep, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), exe);
                if (File.Exists(candidate)) return true;
                if (OperatingSystem.IsLinux() && File.Exists(candidate)) return true;
            }
            catch { }
        }
        return false;
    }

    public static ExecResult Run(ExecRequest req, Stream stdoutSink, Stream stderrSink)
    {
        var shell = ResolveShell(req.Shell);
        var scriptMode = req.ScriptPath is not null;

        var psi = new ProcessStartInfo();
        psi.UseShellExecute = false;

        if (scriptMode)
        {
            var script = File.ReadAllText(req.ScriptPath!);
            script = Placeholder.Replace(script, BuildTokenMap(req, script));
            switch (shell)
            {
                case "none":
                    throw new UsageException("脚本模式需要 shell（--shell auto|bash|sh|pwsh）");
                case "cmd" or "cmd.exe":
                    // cmd 无 stdin 脚本入口，按计划拒绝，引导用户改用 pwsh
                    throw new UsageException("cmd 不支持脚本 stdin 模式，请改用 pwsh（--shell pwsh）");
                case "pwsh" or "powershell":
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

        if (shell == "none")
        {
            psi.FileName = resolved[0];
            foreach (var a in resolved.Skip(1)) psi.ArgumentList.Add(a);
        }
        else if (shell is "cmd" or "cmd.exe")
        {
            // cmd 的引号规则与 MSVCRT 不同：直接拼 raw 命令串交给 /c，不做参数级加引号
            psi.FileName = shell;
            psi.ArgumentList.Add("/c");
            psi.ArgumentList.Add(string.Join(' ', resolved));
        }
        else if (shell is "pwsh" or "powershell")
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

        foreach (var (var, value) in req.EnvInject)
            psi.Environment[var] = value;

        using var process = new Process { StartInfo = psi };
        if (!process.Start()) throw new UsageException("子进程启动失败");

        var outRedactor = new StreamRedactor(req.RedactionRules);
        var errRedactor = new StreamRedactor(req.RedactionRules);

        var pumpOut = PumpAsync(process.StandardOutput.BaseStream, stdoutSink, outRedactor);
        var pumpErr = PumpAsync(process.StandardError.BaseStream, stderrSink, errRedactor);

        if (stdinText is not null)
        {
            try
            {
                process.StandardInput.Write(stdinText);
                process.StandardInput.Flush();
            }
            catch (IOException) { /* 子进程提前退出 */ }
            process.StandardInput.Close();
        }

        var timeoutMs = req.TimeoutSeconds <= 0 ? -1 : req.TimeoutSeconds * 1000;
        if (!process.WaitForExit(timeoutMs))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            process.WaitForExit(5_000);
            Task.WaitAll([pumpOut, pumpErr], 5_000);
            return new ExecResult { ExitCode = ExitCodes.Timeout, TimedOut = true };
        }

        Task.WaitAll([pumpOut, pumpErr], 10_000);
        return new ExecResult { ExitCode = process.ExitCode };
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

    internal static string QuoteForPwsh(string arg)
    {
        if (arg.Length == 0) return "''";
        if (!arg.Any(c => char.IsWhiteSpace(c) || c is '\'' or '"' or '$' or ';' or '&' or '|' or '(' or ')' or '<' or '>' or '{' or '}'))
            return arg;
        return "'" + arg.Replace("'", "''") + "'";
    }
}
