using System.Text;
using HPass.Core;
using Xunit;

namespace HPass.Core.Tests;

public class RedactorTests
{
    private static string Run(string input, IReadOnlyDictionary<string, string> rules)
    {
        var redactor = new StreamRedactor(rules);
        var out1 = redactor.Process(Encoding.UTF8.GetBytes(input));
        var out2 = redactor.Flush();
        return Encoding.UTF8.GetString(out1.Concat(out2).ToArray());
    }

    [Fact]
    public void EmptySecretRule_Filtered_NoInfiniteLoop()
    {
        // 空 secret 曾使 IndexOf 恒命中 0 → 死循环 OOM；构造时必须过滤
        var redactor = new StreamRedactor(new Dictionary<string, string> { [""] = "{{x}}" });
        var out1 = redactor.Process("normal output"u8);
        var out2 = redactor.Flush();
        Assert.Equal("normal output", Encoding.UTF8.GetString(out1.Concat(out2).ToArray()));
    }

    [Fact]
    public void NoRules_PassthroughExactBytes()
    {
        var redactor = new StreamRedactor(new Dictionary<string, string>());
        var bytes = new byte[] { 0, 1, 2, 255, 254, 0 };
        Assert.Equal(bytes, redactor.Process(bytes));
        Assert.Empty(redactor.Flush());
    }

    [Fact]
    public void SingleSecret_ReplacedWithToken()
    {
        var rules = new Dictionary<string, string> { ["S3cret!"] = "{{db}}" };
        Assert.Equal("user={{db}}\n", Run("user=S3cret!\n", rules));
    }

    [Fact]
    public void SecretSplitAcrossChunks_ByteByByte()
    {
        var rules = new Dictionary<string, string> { ["S3cret!"] = "{{db}}" };
        var redactor = new StreamRedactor(rules);
        var chunks = "xxS3cret!yy".Select(c => redactor.Process([(byte)c])).ToList();
        var tail = redactor.Flush();
        var result = Encoding.UTF8.GetString(chunks.SelectMany(c => c).Concat(tail).ToArray());
        Assert.Equal("xx{{db}}yy", result);
    }

    [Fact]
    public void SecretSplitAtEveryPossibleBoundary()
    {
        var secret = "S3cret!";
        var rules = new Dictionary<string, string> { [secret] = "{{db}}" };
        for (var split = 1; split < secret.Length; split++)
        {
            var redactor = new StreamRedactor(rules);
            var a = redactor.Process(Encoding.UTF8.GetBytes("A" + secret[..split]));
            var b = redactor.Process(Encoding.UTF8.GetBytes(secret[split..] + "B"));
            var result = Encoding.UTF8.GetString(a.Concat(b).Concat(redactor.Flush()).ToArray());
            Assert.Equal("A{{db}}B", result);
        }
    }

    [Fact]
    public void SecretAtVeryEnd_FlushReturnsTail()
    {
        var rules = new Dictionary<string, string> { ["tail9"] = "{{x}}" };
        var redactor = new StreamRedactor(rules);
        var emitted = redactor.Process(Encoding.UTF8.GetBytes("value=tail9"));
        var tail = redactor.Flush();
        Assert.Equal("value={{x}}", Encoding.UTF8.GetString(emitted.Concat(tail).ToArray()));
    }

    [Fact]
    public void MultipleSecrets_AllReplaced()
    {
        var rules = new Dictionary<string, string> { ["alpha-1"] = "{{a}}", ["beta-2"] = "{{b}}" };
        Assert.Equal("{{a}}+{{b}}+{{a}}", Run("alpha-1+beta-2+alpha-1", rules));
    }

    [Fact]
    public void OverlappingSecrets_LongestWins()
    {
        // "abc" 与 "abcd" 同点匹配，应替换更长者，避免残留 "d"
        var rules = new Dictionary<string, string> { ["abc"] = "{{s1}}", ["abcd"] = "{{s2}}" };
        Assert.Equal("X{{s2}}Y", Run("XabcdY", rules));
        Assert.Equal("X{{s1}}Y", Run("XabcY", rules));
    }

    [Fact]
    public void AdjacentRepeatedSecrets()
    {
        var rules = new Dictionary<string, string> { ["s"] = "{{x}}" };
        Assert.Equal("{{x}}{{x}}{{x}}", Run("sss", rules));
    }

    [Fact]
    public void SecretWithSpecialChars()
    {
        var secret = "p@ss'\"$ \\`中文🔐";
        var rules = new Dictionary<string, string> { [secret] = "{{db}}" };
        Assert.Equal("ok {{db}} ok", Run($"ok {secret} ok", rules));
    }

    [Fact]
    public void NonMatchingTextPartiallyOverlappingSecretPrefix()
    {
        // 文本只含 secret 前缀，不能误替换、不能丢字节
        var rules = new Dictionary<string, string> { ["abcdef"] = "{{x}}" };
        Assert.Equal("abc", Run("abc", rules));
        Assert.Equal("xxabcdeyy", Run("xxabcdeyy", rules));
    }
}
