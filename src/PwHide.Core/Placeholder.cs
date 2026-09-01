using System.Text;
using System.Text.RegularExpressions;

namespace PwHide.Core;

public readonly record struct PlaceholderRef(string Entry, string? Field);

public static class Placeholder
{
    /// <summary>
    /// 提取文本中的占位符。name → 密码；name.user/name.tenant/name.&lt;字段&gt; → 明文/加密字段。
    /// 名字以第一个 '.' 分隔：条目名与字段名自身不允许含 '.'（创建时校验）。
    /// syntax 决定定界符（默认 {{…}}；exec --ph 可切换 #name# / @name@）。
    /// </summary>
    public static List<PlaceholderRef> Extract(string text, TokenSyntax? syntax = null)
    {
        var regex = (syntax ?? TokenSyntax.Braces).NewRegex();
        var result = new List<PlaceholderRef>();
        foreach (Match m in regex.Matches(text))
        {
            var body = m.Groups[1].Value;
            var dot = body.IndexOf('.');
            var (entry, field) = dot < 0 ? (body, (string?)null) : (body[..dot], body[(dot + 1)..]);
            result.Add(new PlaceholderRef(entry, field));
        }
        return result;
    }

    /// <summary>
    /// 单遍替换：一次扫描当前语法的占位符并拼接替换值，值中的占位符字面量不会被再次替换。
    /// （多遍 Replace 存在注入：若条目 a 的值恰好含 b 的占位符，会把 b 的密文二次注入且不参与脱敏。）
    /// </summary>
    public static string Replace(string text, IReadOnlyDictionary<string, string> tokenValues, TokenSyntax? syntax = null)
    {
        if (tokenValues.Count == 0) return text;
        var regex = (syntax ?? TokenSyntax.Braces).NewRegex();
        var sb = new StringBuilder(text.Length);
        var last = 0;
        foreach (Match m in regex.Matches(text))
        {
            sb.Append(text.AsSpan(last, m.Index - last));
            sb.Append(tokenValues.TryGetValue(m.Value, out var value) ? value : m.Value);
            last = m.Index + m.Length;
        }
        sb.Append(text.AsSpan(last));
        return sb.ToString();
    }
}
