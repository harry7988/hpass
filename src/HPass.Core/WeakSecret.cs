namespace HPass.Core;

/// <summary>
/// 弱密文检测（防"密码=常见语句"）：
/// 若密码本身是常见口令/常见日志与 SQL 语句，会与正常输出大量碰撞 —— 既把日志大面积误替换成占位符，
/// 更严重的是"被替换的位置"会直接暴露密码内容（看到哪句变成 {{名}}，就猜到密码是那句）。
/// 因此在录入源头拦截；确需保留用 --force-weak 显式覆盖（风险自担）。
/// </summary>
public static class WeakSecret
{
    /// <summary>整串匹配（大小写不敏感、忽略首尾空白）。覆盖常见口令与高频日志/SQL/配置语句。</summary>
    private static readonly HashSet<string> CommonSecrets = new(StringComparer.OrdinalIgnoreCase)
    {
        // 常见口令
        "password", "password1", "password123", "passwd", "p@ssw0rd", "passw0rd", "changeme", "letmein",
        "qwerty", "qwerty123", "qwertyuiop", "asdfgh", "zxcvbn", "123456", "1234567", "12345678", "123456789",
        "1234567890", "111111", "000000", "121212", "123123", "654321", "888888", "abc123", "abcd1234",
        "iloveyou", "monkey", "dragon", "master", "admin", "administrator", "root", "guest", "user", "test",
        "test123", "demo", "secret", "welcome", "login", "pass", "qwerty12", "football", "baseball",
        // 常见 SQL / 日志 / 配置语句（整句作为密码时与正常输出高频碰撞）
        "select 1", "select *", "select all", "select * from", "show databases", "show tables",
        "describe table", "explain select", "begin", "commit", "rollback",
        "error", "warning", "info", "debug", "trace", "fatal", "panic", "success", "failed", "failure",
        "exception", "stack trace", "stacktrace", "timeout", "retrying", "retries",
        "connection refused", "connection reset", "connection closed", "connection timeout",
        "permission denied", "access denied", "operation not permitted", "not found", "no such file",
        "file not found", "out of memory", "segmentation fault", "bus error", "killed", "exited",
        "null", "nullpointerexception", "undefined", "true", "false", "none", "nil", "nan",
        "ok", "yes", "no", "hello", "hello world", "lorem ipsum", "test test", "dummy", "placeholder",
        "localhost", "127.0.0.1", "0.0.0.0", "::1", "example.com", "example.org", "test.com",
        "user-agent", "content-type", "accept-encoding", "authorization", "bearer", "basic",
        "username", "password:", "secretkey", "accesskey", "apikey", "api_key", "token", "jwt",
        "true ", "the quick brown fox jumps over the lazy dog",
    };

    /// <summary>返回拒绝原因；null 表示通过。</summary>
    public static string? Check(string secret)
    {
        var s = secret.Trim();
        if (s.Length < 8) return "长度不足 8 个字符";
        if (s.Any(char.IsDigit) && s.All(char.IsDigit)) return "纯数字";
        if (s.Distinct().Count() < 4) return "字符种类过少（少于 4 种）";
        if (s.ToLowerInvariant() == s && s.Length <= 10 && s.All(char.IsLetter)) return "全小写字母且过短";
        if (CommonSecrets.Contains(s)) return "属于常见口令/常见语句（会与正常输出碰撞，且替换位置会暴露密码内容）";
        return null;
    }
}
