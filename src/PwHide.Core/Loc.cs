using System.Text;

namespace PwHide.Core;

/// <summary>
/// CLI 消息本地化（en 默认 / zh 可选）。
///
/// 设计：翻译发生在输出边界（CliContext 的 LocalizingWriter 按行翻译），源码中的中文消息串
/// 保持原样作为查找键，调用点零改动——既有断言中文输出的测试在 zh 模式下原样成立。
/// 查找顺序：精确匹配 → 通配模板（* 分段按序匹配，动态部分原样保留——绝不触碰密文值）→ 原样输出。
/// 未命中只是优雅降级（该行保持中文），不会崩溃、不会吞消息。
///
/// 语言解析优先级：PWHIDE_LANG 环境变量 &gt; home/language 文件（pwhide language 写入）&gt; 默认 en。
/// 子进程输出（exec 的原始字节流）不经此层——永不翻译用户程序输出。
/// 翻译表在 LocTable.cs（"zh||en" 原始条目，含 * 者为通配模板）。
/// </summary>
public static partial class Loc
{
    public static string Lang { get; private set; } = "en";

    /// <summary>解析并设置语言（CliRunner 在分发命令前调用一次；home 用于读 language 文件）。</summary>
    public static void Load(string home)
    {
        var env = Environment.GetEnvironmentVariable("PWHIDE_LANG");
        if (env is "en" or "zh") { Lang = env; return; }
        try
        {
            var file = Path.Combine(home, "language");
            var v = File.Exists(file) ? File.ReadAllText(file).Trim() : "";
            if (v is "en" or "zh") { Lang = v; return; }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException) { }
        Lang = "en";
    }

    public static void SetLang(string lang) => Lang = lang;

    /// <summary>持久化语言选择（pwhide language 命令）。</summary>
    public static void Save(string home, string lang)
    {
        Directory.CreateDirectory(home);
        File.WriteAllText(Path.Combine(home, "language"), lang);
        Lang = lang;
    }

    /// <summary>当前语言来源描述（doctor/language status 用）。</summary>
    public static string Source(string home)
    {
        var env = Environment.GetEnvironmentVariable("PWHIDE_LANG");
        if (env is "en" or "zh") return $"env PWHIDE_LANG={env}";
        try
        {
            var file = Path.Combine(home, "language");
            if (File.Exists(file) && File.ReadAllText(file).Trim() is "en" or "zh")
                return $"file {file}";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException) { }
        return "default en";
    }

    /// <summary>en 模式下翻译一行输出；zh 或不含 CJK 时原样返回。</summary>
    private const string CliPrefix = "pwhide: ";

    public static string Tr(string s)
    {
        if (Lang != "en" || s.Length == 0 || !ContainsCjk(s)) return s;
        if (Table.TryGetValue(s, out var exact)) return exact;
        foreach (var (pattern, en) in Wildcards)
            if (MatchWildcard(pattern, s, out var parts))
                return BuildEn(en, parts);
        // 异常路径消息被 CliRunner 拼上 "pwhide: " 前缀：迭代剥前缀再试（防御超长输入的栈溢出）
        while (s.StartsWith(CliPrefix, StringComparison.Ordinal))
        {
            var inner = Tr(s[CliPrefix.Length..]);
            if (inner != s[CliPrefix.Length..]) return CliPrefix + inner;
            return s;   // 剥前缀也无命中：原样
        }
        return s;
    }

    /// <summary>双语直出助手：按当前语言返回 en/zh 之一（用于命令自身需要即时切换的输出）。</summary>
    public static string T(string en, string zh) => Lang == "zh" ? zh : en;

    public static bool ContainsCjk(string s)
    {
        foreach (var c in s)
            if (c >= 0x4E00 && c <= 0x9FFF) return true;
        return false;
    }

    /// <summary>pattern 形如 "前缀*中缀*后缀"：s 须以首段开头、末段结尾、中段按序出现；段间动态部分原样保留。</summary>
    private static bool MatchWildcard(string pattern, string s, out List<string> parts)
    {
        parts = [];
        var segs = pattern.Split('*');
        var stars = segs.Length - 1;
        var pos = 0;
        for (var i = 0; i < segs.Length; i++)
        {
            var seg = segs[i];
            if (i == 0)
            {
                if (!s.StartsWith(seg, StringComparison.Ordinal)) return false;
                pos = seg.Length;
            }
            else if (i == segs.Length - 1)
            {
                if (!s.EndsWith(seg, StringComparison.Ordinal) || s.Length - seg.Length < pos) return false;
                parts.Add(s[pos..(s.Length - seg.Length)]);
            }
            else
            {
                var idx = s.IndexOf(seg, pos, StringComparison.Ordinal);
                if (idx < 0) return false;
                parts.Add(s[pos..idx]);
                pos = idx + seg.Length;
            }
        }
        return parts.Count == stars;
    }

    private static string BuildEn(string enTemplate, List<string> parts)
    {
        var segs = enTemplate.Split('*');
        if (segs.Length - 1 != parts.Count) return enTemplate;
        var sb = new StringBuilder();
        for (var i = 0; i < segs.Length; i++)
        {
            sb.Append(segs[i]);
            if (i < parts.Count) sb.Append(parts[i]);
        }
        return sb.ToString();
    }
}
