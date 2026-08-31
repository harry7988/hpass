using System.Text;
using HPass.Cli;
using Xunit;

namespace HPass.IntegrationTests;

/// <summary>端到端测试夹具：临时 home + 初始化 vault + 录入标准测试条目。</summary>
public sealed class CliFixture : IDisposable
{
    public const string DbPassword = "Int3gr!tion-pw-9";
    public string Home { get; } = Path.Combine(Path.GetTempPath(), "hpass-it-" + Guid.NewGuid().ToString("N"));

    public CliFixture()
    {
        Environment.SetEnvironmentVariable("HPASS_HOME", null);
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", "init-pass-123");
        try
        {
            Assert.Equal(0, Run("init", "--no-harden").Exit);
            Assert.Equal(0, RunWithInput(DbPassword, "set", "db", "-t", "database", "-u", "root", "-T", "prod",
                "-f", "host=127.0.0.1", "-f", "api_key=ak-9", "--password-stdin").Exit);
            Assert.Equal(0, RunWithInput("ssh-pw-77", "set", "ssh-box", "-t", "ssh", "-u", "ec2-user", "--password-stdin").Exit);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null);
        }
    }

    public (int Exit, string Stdout, string Stderr) Run(params string[] args) => RunWithInput(null, args);

    public (int Exit, string Stdout, string Stderr) RunWithInput(string? input, params string[] args)
    {
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var full = new[] { "--home", Home }.Concat(args).ToArray();
        using var stdin = new StringReader(input ?? "");
        var exit = CliRunner.Run(full, stdout, stderr, stdin, interactive: false);
        var enc = new UTF8Encoding(false);
        return (exit, enc.GetString(stdout.ToArray()), enc.GetString(stderr.ToArray()));
    }

    /// <summary>以指定主口令运行（默认口令为 init-pass-123）。</summary>
    public (int Exit, string Stdout, string Stderr) RunAs(string passphrase, params string[] args)
    {
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", passphrase);
        try { return Run(args); }
        finally { Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null); }
    }

    /// <summary>以指定主口令 + stdin 输入运行。</summary>
    public (int Exit, string Stdout, string Stderr) RunAsWithInput(string passphrase, string? input, params string[] args)
    {
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", passphrase);
        try { return RunWithInput(input, args); }
        finally { Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null); }
    }

    public void Dispose()
    {
        try { Directory.Delete(Home, recursive: true); } catch { }
    }
}

[CollectionDefinition("sequential")]
public sealed class SequentialCollection : ICollectionFixture<CliFixture> { }
