using System.Text.RegularExpressions;

namespace HPass.Core;

/// <summary>
/// 回显探测检测（全文共现语义）。
///
/// 动机：把候选字符串 echo 出来、同时让脱敏规则处于激活状态（命令中引用了密文占位符），
/// 就构成一次"等值判定 oracle"——输出被替换成占位符 ⟺ 候选 == 密码，逐候选重跑即字典攻击。
/// 早期"同语句"规则（回显原语与占位符之间无 ;|& 分隔）可被语序绕过（`x={{db}}; echo swordfish`），
/// 因此现在采用全文共现：同一次调用中同时出现"回显原语"与"密文占位符"即拒绝。
///
/// 代价（如实声明）：`echo deploy start && mysql -p{{db}} …` 这类"回显进度 + 使用密码"的组合也会被拒，
/// 需 --allow-echo 显式放行（人工确认意图）。明文字段 {{名.user}}/{{名.tenant}} 不算密文占位符。
/// 这是启发式防护，不做完备性承诺（详见 threat-model §5）。
/// </summary>
public static partial class EchoProbe
{
    // 回显原语后需跟空白或行尾，避免误伤 echo-backup.txt 这类名字
    [GeneratedRegex(@"\b(echo|printf|puts|print|write-output|write-host|console\.log)\b(\s|\(|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EchoRegex();

    [GeneratedRegex(@"\{\{([A-Za-z0-9_.\-]+)\}\}")]
    private static partial Regex SecretTokenRegex();

    /// <summary>文本中是否存在回显原语（与密文引用无关的独立判定，供 --env 场景组合使用）。</summary>
    public static bool HasEchoPrimitive(string text) => EchoRegex().IsMatch(text);

    /// <summary>同一文本中"回显原语"与"密文占位符"共现即判定为探测。命中返回 true，out 参数为首个密文占位符。</summary>
    public static bool IsProbe(string text, out string token)
    {
        token = "";
        if (!EchoRegex().IsMatch(text)) return false;
        foreach (Match m in SecretTokenRegex().Matches(text))
        {
            var body = m.Groups[1].Value;
            var dot = body.IndexOf('.');
            var field = dot < 0 ? null : body[(dot + 1)..];
            if (field is "user" or "tenant") continue; // 明文字段，回显无泄露
            token = m.Value;
            return true;
        }
        return false;
    }

    public static string DenyMessage(string token) =>
        $"检测到回显命令与密文占位符（{token}）在同一次调用中共现。回显 + 已激活的脱敏规则可被逐候选探测出密码内容" +
        "（输出被替换成占位符 ⟺ 候选即密码）。如确属正常用途（如回显进度同时使用密码），请追加 --allow-echo 确认放行。";
}
