using PwHide.Core;
using Xunit;

namespace PwHide.Core.Tests;

public class PlaceholderTests
{
    [Fact]
    public void Extract_BasicPassword()
    {
        var refs = Placeholder.Extract("mysql -p{{db}} -e x");
        var r = Assert.Single(refs);
        Assert.Equal("db", r.Entry);
        Assert.Null(r.Field);
        Assert.Equal("{{db}}", TokenSyntax.Braces.Render(r.Entry, r.Field));
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

    // ---------- --ph 自定义定界符（#name# / @name@） ----------

    [Fact]
    public void Syntax_Parse_Whitelist()
    {
        Assert.Equal(("{{", "}}"), (TokenSyntax.Parse(null).Begin, TokenSyntax.Parse(null).End));
        Assert.Equal(("#", "#"), (TokenSyntax.Parse("#").Begin, TokenSyntax.Parse("#").End));
        Assert.Equal(("@", "@"), (TokenSyntax.Parse("@").Begin, TokenSyntax.Parse("@").End));
        Assert.Throws<UsageException>(() => TokenSyntax.Parse("%"));
        Assert.Throws<UsageException>(() => TokenSyntax.Parse("{{"));
        Assert.Throws<UsageException>(() => TokenSyntax.Parse(""));
    }

    [Fact]
    public void Syntax_RenderAndBody_Roundtrip()
    {
        var hash = TokenSyntax.Parse("#");
        Assert.Equal("#db#", hash.Render("db"));
        Assert.Equal("#db.user#", hash.Render("db", "user"));
        Assert.Equal("db.user", hash.Body("#db.user#"));
        Assert.Equal("db", TokenSyntax.Braces.Body("{{db}}"));
    }

    [Fact]
    public void Extract_HashSyntax()
    {
        var hash = TokenSyntax.Parse("#");
        var refs = Placeholder.Extract("mysql -p#db# -h #db.host# --opt", hash);
        Assert.Equal(2, refs.Count);
        Assert.Equal(("db", null), (refs[0].Entry, refs[0].Field));
        Assert.Equal(("db", "host"), (refs[1].Entry, refs[1].Field));
    }

    [Fact]
    public void Extract_AtSyntax_IgnoresBracesAndLooseSymbols()
    {
        var at = TokenSyntax.Parse("@");
        var refs = Placeholder.Extract("@db@ user@host.com {{db}} @@ a @ b @", at);
        var r = Assert.Single(refs);
        Assert.Equal("db", r.Entry);
        // @db@ 生效时 {{db}} 是字面量（正是 --ph 的存在意义：模板语法不再冲突）
        Assert.Empty(Placeholder.Extract("{{db}}", at));
    }

    [Fact]
    public void Extract_HashSyntax_IgnoresShellCommentsWithoutClose()
    {
        var hash = TokenSyntax.Parse("#");
        // 注释里的 # 与单个/带空格的 # 不构成占位符；紧贴的 #name# 才匹配（fail-closed：误命中只是拒跑）
        Assert.Empty(Placeholder.Extract("# comment about db here", hash));
        Assert.Empty(Placeholder.Extract("# spaced #", hash));
        Assert.Equal("db", Assert.Single(Placeholder.Extract("x #db# y", hash)).Entry);
    }

    [Fact]
    public void Replace_HashSyntax()
    {
        var hash = TokenSyntax.Parse("#");
        var map = new Dictionary<string, string> { ["#a#"] = "X", ["#b#"] = "Y" };
        Assert.Equal("X-Y-X", Placeholder.Replace("#a#-#b#-#a#", map, hash));
        Assert.Equal("--password=X", Placeholder.Replace("--password=#a#", map, hash));
    }

    [Fact]
    public void Replace_HashSyntax_SinglePass_NoReinjection()
    {
        // 值里含 "#b#" 字面量不得被二次替换（与大括号语法同一条不变式）
        var hash = TokenSyntax.Parse("#");
        var map = new Dictionary<string, string> { ["#a#"] = "pre #b# post", ["#b#"] = "SECRET-B" };
        Assert.Equal("x pre #b# post y", Placeholder.Replace("x #a# y", map, hash));
        Assert.DoesNotContain("SECRET-B", Placeholder.Replace("x #a# y", map, hash));
    }

    [Fact]
    public void Replace_HashSyntax_DoesNotTouchBraceLiterals()
    {
        var hash = TokenSyntax.Parse("#");
        var map = new Dictionary<string, string> { ["#a#"] = "X" };
        Assert.Equal("X {{a}} literal", Placeholder.Replace("#a# {{a}} literal", map, hash));
    }
}
