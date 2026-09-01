using PwHide.Core;
using Xunit;

namespace PwHide.Core.Tests;

public class WeakSecretTests
{
    [Theory]
    [InlineData("password")]            // 常见口令
    [InlineData("P@ssw0rd")]
    [InlineData("12345678")]
    [InlineData("select 1")]            // 常见 SQL 语句（短）
    [InlineData(" SELECT * FROM ")]     // 常见语句 + 首尾空白 + 大小写
    [InlineData("Select * From")]
    [InlineData("connection refused")]
    [InlineData("Connection Reset")]
    [InlineData("hello world")]
    [InlineData("localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("aaaaaaa1")]            // 字符种类过少
    [InlineData("111111111111")]        // 纯数字
    [InlineData("abcdefgh")]            // 全小写字母且 ≤10
    [InlineData("short7")]              // 长度不足
    [InlineData("123456789012")]        // 纯数字（长）
    public void CommonOrWeak_Rejected(string secret)
    {
        Assert.NotNull(WeakSecret.Check(secret));
    }

    [Theory]
    [InlineData("admin1234")]           // 字典未含的普通口令不应被误拦（避免过严）
    [InlineData("welcome123")]
    public void OrdinaryPasswords_NotOverBlocked(string secret)
    {
        Assert.Null(WeakSecret.Check(secret));
    }

    [Theory]
    [InlineData("S3cret!Value-9")]
    [InlineData("Int3gr!tion-pw-9")]
    [InlineData("中文密码-执⾏91")]
    [InlineData("Xk9#mQ2$vL7z")]
    [InlineData("p@ss w0rd-Extra")]
    public void StrongSecrets_Pass(string secret)
    {
        Assert.Null(WeakSecret.Check(secret));
    }

    [Fact]
    public void Reason_IsActionable()
    {
        var reason = WeakSecret.Check("select 1");
        Assert.Contains("常见", reason);
        reason = WeakSecret.Check("abc12");
        Assert.Contains("长度", reason);
    }
}
