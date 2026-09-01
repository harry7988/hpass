using System.Text;
using System.Text.RegularExpressions;

namespace PwHide.Core;

public readonly record struct PlaceholderRef(string Entry, string? Field)
{
    public string Token => Vault.Token(Entry, Field);
}

public static partial class Placeholder
{
    [GeneratedRegex(@"\{\{([A-Za-z0-9_.\-]+)\}\}")]
    private static partial Regex TokenRegex();

    /// <summary>
    /// 提取文本中的占位符。{{name}} → 密码；{{name.user}}/{{name.tenant}}/{{name.<字段>}} → 明文/加密字段。
    /// 名字以第一个 '.' 分隔：条目名与字段名自身不允许含 '.'（创建时校验）。
    /// </summary>
    public static List<PlaceholderRef> Extract(string text)
    {
        var result = new List<PlaceholderRef>();
        foreach (Match m in TokenRegex().Matches(text))
        {
            var body = m.Groups[1].Value;
            var dot = body.IndexOf('.');
            var (entry, field) = dot < 0 ? (body, (string?)null) : (body[..dot], body[(dot + 1)..]);
            result.Add(new PlaceholderRef(entry, field));
        }
        return result;
    }

    /// <summary>
    /// 单遍替换：一次扫描所有占位符并拼接替换值，值中的 {{…}} 字面量不会被再次替换。
    /// （多遍 Replace 存在注入：若条目 a 的值恰好含 "{{b}}"，会把 b 的密文二次注入且不参与脱敏。）
    /// </summary>
    public static string Replace(string text, IReadOnlyDictionary<string, string> tokenValues)
    {
        if (tokenValues.Count == 0) return text;
        var sb = new StringBuilder(text.Length);
        var last = 0;
        foreach (Match m in TokenRegex().Matches(text))
        {
            sb.Append(text.AsSpan(last, m.Index - last));
            sb.Append(tokenValues.TryGetValue(m.Value, out var value) ? value : m.Value);
            last = m.Index + m.Length;
        }
        sb.Append(text.AsSpan(last));
        return sb.ToString();
    }
}
