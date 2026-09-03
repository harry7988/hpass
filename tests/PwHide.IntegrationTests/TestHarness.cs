using System.Text;
using PwHide.Cli;
using Xunit;

namespace PwHide.IntegrationTests;

/// <summary>端到端测试夹具：临时 home + 初始化 vault + 录入标准测试条目。</summary>
public sealed class CliFixture : IDisposable
{
    public const string DbPassword = "Int3gr!tion-pw-9";
    public string Home { get; } = Path.Combine(Path.GetTempPath(), "pwhide-it-" + Guid.NewGuid().ToString("N"));

    public CliFixture()
    {
        Environment.SetEnvironmentVariable("PWHIDE_HOME", null);
        // 测试环境禁用自动 sudo 提权（提权路径用 PWHIDE_NO_SUDO 短路；真实 sudo 流程由 CI 的 AOT 冒烟覆盖）
        Environment.SetEnvironmentVariable("PWHIDE_NO_SUDO", "1");
        // 既有测试断言中文输出：固定 zh（产品默认 en，en 由 LanguageTests 专测）
        Environment.SetEnvironmentVariable("PWHIDE_LANG", "zh");
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
        try
        {
            Assert.Equal(0, Run("init", "--no-harden").Exit);
            Assert.Equal(0, RunWithInput(DbPassword, "set", "db", "-t", "database", "-u", "root", "-T", "prod",
                "-f", "host=127.0.0.1", "-f", "api_key=ak-9", "--password-stdin").Exit);
            Assert.Equal(0, RunWithInput("ssh-pw-77", "set", "ssh-box", "-t", "ssh", "-u", "ec2-user", "--password-stdin").Exit);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);
        }
    }

    public (int Exit, string Stdout, string Stderr) Run(params string[] args) => RunWithInput(null, args);

    public (int Exit, string Stdout, string Stderr) RunWithInput(string? input, params string[] args) =>
        RunIn(Home, input, args);

    /// <summary>在指定 home 上运行（加固流程测试使用独立 home，避免污染共享 fixture）。</summary>
    public (int Exit, string Stdout, string Stderr) RunIn(string home, string? input, params string[] args)
    {
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var full = new[] { "--home", home }.Concat(args).ToArray();
        using var stdin = new StringReader(input ?? "");
        var exit = CliRunner.Run(full, stdout, stderr, stdin, interactive: false);
        var enc = new UTF8Encoding(false);
        return (exit, enc.GetString(stdout.ToArray()), enc.GetString(stderr.ToArray()));
    }

    /// <summary>以指定主口令运行（默认口令为 init-pass-123）。</summary>
    public (int Exit, string Stdout, string Stderr) RunAs(string passphrase, params string[] args)
    {
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", passphrase);
        try { return Run(args); }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    /// <summary>以指定主口令 + stdin 输入运行。</summary>
    public (int Exit, string Stdout, string Stderr) RunAsWithInput(string passphrase, string? input, params string[] args)
    {
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", passphrase);
        try { return RunWithInput(input, args); }
        finally { Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null); }
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("PWHIDE_NO_SUDO", null);
        Environment.SetEnvironmentVariable("PWHIDE_LANG", null);
        try { Directory.Delete(Home, recursive: true); } catch { }
    }
}

[CollectionDefinition("sequential")]
public sealed class SequentialCollection : ICollectionFixture<CliFixture> { }
