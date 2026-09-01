using System.Text.RegularExpressions;

namespace PwHide.Core;

/// <summary>
/// 占位符书写语法。默认 {{name}}（Braces）；exec --ph 可切换为单符号包裹（#name# / @name@），
/// 规避 {{ 与 Helm / Jinja / Go template 等模板语言的转义冲突。
/// 符号走白名单（仅 # 与 @）：动态拼接正则只接受固定输入，且两类符号与名字字符集（字母数字_.-）无交集。
/// </summary>
public readonly record struct TokenSyntax
{
    public required string Begin { get; init; }
    public required string End { get; init; }

    public static TokenSyntax Braces { get; } = new() { Begin = "{{", End = "}}" };

    /// <summary>解析 --ph 取值。null = 未指定（默认大括号）；仅接受 # 或 @，空串与其余取值为用法错误。</summary>
    public static TokenSyntax Parse(string? symbol) => symbol switch
    {
        null => Braces,
        "#" => new() { Begin = "#", End = "#" },
        "@" => new() { Begin = "@", End = "@" },
        _ => throw new UsageException($"--ph 仅支持 # 或 @（收到 {symbol}）；不指定时默认语法为 {{{{name}}}}"),
    };

    public string Render(string entry, string? field = null) =>
        field is null ? $"{Begin}{entry}{End}" : $"{Begin}{entry}.{field}{End}";

    /// <summary>token 反解 entry[.field] 主体（剥离首尾定界符；用于警告与错误信息，绝不含密文）。</summary>
    public string Body(string token)
    {
        if (token.StartsWith(Begin, StringComparison.Ordinal)) token = token[Begin.Length..];
        if (token.EndsWith(End, StringComparison.Ordinal)) token = token[..^End.Length];
        return token;
    }

    /// <summary>当前语法的 token 匹配正则（与默认大括号语法同一名字字符集）。每次 exec 构造一次，非热路径。</summary>
    public Regex NewRegex() => new(
        Regex.Escape(Begin) + @"([A-Za-z0-9_.\-]+)" + Regex.Escape(End),
        RegexOptions.CultureInvariant);
}
