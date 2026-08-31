using System.Text.RegularExpressions;

namespace HPass.Core;

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

    public static string Replace(string text, IReadOnlyDictionary<string, string> tokenValues)
    {
        foreach (var (token, value) in tokenValues)
            text = text.Replace(token, value);
        return text;
    }
}
