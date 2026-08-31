using System.Text.RegularExpressions;

namespace HPass.Core;

/// <summary>
/// 回显探测检测："回显原语（echo/printf/Write-Output/puts…）与密文占位符出现在同一语句"。
///
/// 动机：把 {{db}} 直接 echo 出来，对正常业务命令毫无意义 —— 它要么是无意的密码回显，
/// 要么是 Agent 在做探测字典攻击（换各种候选语句跑 echo，看哪个被替换成占位符，即可确认密码）。
/// 替换位置本身就是信息泄露面，因此在命令入口直接拒绝（--allow-echo 显式放行，用于人工验证脱敏）。
/// 注意：只拦"密文占位符"（{{名}}/{{名.<字段>}}），明文字段 {{名.user}}/{{名.tenant}} 不拦。
/// 这是启发式防护（威胁模型如实声明），不做完备性承诺。
/// </summary>
public static partial class EchoProbe
{
    // 回显原语后需跟空白，避免误伤 echo-backup.txt 这类名字；占位符须在同一语句内（无 ; | & 分隔）
    [GeneratedRegex(@"\b(echo|printf|puts|print|write-output|write-host|console\.log)\b\s[^;|&\n]*\{\{([A-Za-z0-9_.\-]+)\}\}", RegexOptions.IgnoreCase)]
    private static partial Regex ProbeRegex();

    /// <summary>文本中是否存在"回显 + 密文占位符"同语句。命中返回 true，out 参数为首个命中的占位符。</summary>
    public static bool IsProbe(string text, out string token)
    {
        foreach (Match m in ProbeRegex().Matches(text))
        {
            var body = m.Groups[2].Value;
            var dot = body.IndexOf('.');
            var field = dot < 0 ? null : body[(dot + 1)..];
            if (field is "user" or "tenant") continue; // 明文字段，回显无泄露
            token = $"{{{{{body}}}}}";
            return true;
        }
        token = "";
        return false;
    }

    public static string DenyMessage(string token) =>
        $"检测到回显密文的命令（{token} 与 echo/printf 等出现在同一语句）。回显密码没有正常用途，且会被人利用来推测密码内容。" +
        "如确需人工验证脱敏行为，请追加 --allow-echo。";
}
