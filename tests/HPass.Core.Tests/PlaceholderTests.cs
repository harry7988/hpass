using HPass.Core;
using Xunit;

namespace HPass.Core.Tests;

public class PlaceholderTests
{
    [Fact]
    public void Extract_BasicPassword()
    {
        var refs = Placeholder.Extract("mysql -p{{db}} -e x");
        var r = Assert.Single(refs);
        Assert.Equal("db", r.Entry);
        Assert.Null(r.Field);
        Assert.Equal("{{db}}", r.Token);
    }

    [Fact]
    public void Extract_QualifiedFields()
    {
        var refs = Placeholder.Extract("{{db.user}} {{db.tenant}} {{db.host}}");
        Assert.Equal(3, refs.Count);
        Assert.Equal(("db", "user"), (refs[0].Entry, refs[1].Field is null ? null : refs[0].Field));
        Assert.Equal("user", refs[0].Field);
        Assert.Equal("tenant", refs[1].Field);
        Assert.Equal("host", refs[2].Field);
    }

    [Fact]
    public void Extract_EmptyAndInvalid_NoMatch()
    {
        Assert.Empty(Placeholder.Extract("{{}}"));
        Assert.Empty(Placeholder.Extract("{{ }}"));
        Assert.Empty(Placeholder.Extract("{db}"));  // 单层花括号
    }

    [Fact]
    public void Extract_TripleBraces_MatchesInner()
    {
        // "{{{db}}}" 中从第 1 字符起匹配到内层 {{db}}
        var r = Assert.Single(Placeholder.Extract("{{{db}}}"));
        Assert.Equal("db", r.Entry);
        Assert.Null(r.Field);
    }

    [Fact]
    public void Extract_OnlyAllowedCharset()
    {
        Assert.Empty(Placeholder.Extract("{{a b}}"));
        Assert.Empty(Placeholder.Extract("{{a/b}}"));
        Assert.Empty(Placeholder.Extract("{{a'b}}"));
        var refs = Placeholder.Extract("{{a-b_C9}}");
        Assert.Equal("a-b_C9", Assert.Single(refs).Entry);
    }

    [Fact]
    public void Extract_MultipleAndDuplicates()
    {
        var refs = Placeholder.Extract("{{a}} {{b}} {{a.user}} {{a}}");
        Assert.Equal(4, refs.Count);
        Assert.Equal(["a", "b", "a", "a"], refs.Select(r => r.Entry));
    }

    [Fact]
    public void Extract_UnicodeTextUnaffected()
    {
        var refs = Placeholder.Extract("中文测试 密码：{{db}} 🚀 备份 {{db2}}");
        Assert.Equal(2, refs.Count);
    }

    [Fact]
    public void Extract_InnerDotsBelongToField()
    {
        // 第一个 '.' 是分隔符，其余属于字段名（字段名含 '.' 会在解析时报未知字段）
        var r = Assert.Single(Placeholder.Extract("{{a.b.c}}"));
        Assert.Equal("a", r.Entry);
        Assert.Equal("b.c", r.Field);
    }

    [Fact]
    public void Extract_EmbeddedInArg()
    {
        var r = Assert.Single(Placeholder.Extract("--password={{db}}"));
        Assert.Equal("db", r.Entry);
    }

    [Fact]
    public void Replace_AllOccurrences()
    {
        var map = new Dictionary<string, string> { ["{{a}}"] = "X", ["{{b}}"] = "Y" };
        Assert.Equal("X-Y-X", Placeholder.Replace("{{a}}-{{b}}-{{a}}", map));
        Assert.Equal("--password=X", Placeholder.Replace("--password={{a}}", map));
    }

    [Fact]
    public void Replace_SinglePass_ValueContainingTokenIsNotReplaced()
    {
        // 条目 a 的值里含 "{{b}}" 字面量：单遍替换后保持字面，b 的密文绝不能被二次注入
        var map = new Dictionary<string, string> { ["{{a}}"] = "pre {{b}} post", ["{{b}}"] = "SECRET-B" };
        Assert.Equal("x pre {{b}} post y", Placeholder.Replace("x {{a}} y", map));
        Assert.DoesNotContain("SECRET-B", Placeholder.Replace("x {{a}} y", map));
    }

    [Fact]
    public void Replace_UnknownTokenKeptVerbatim()
    {
        var map = new Dictionary<string, string> { ["{{a}}"] = "X" };
        Assert.Equal("X {{unknown}}", Placeholder.Replace("{{a}} {{unknown}}", map));
    }
}
