using System.Text.Json;
using HPass.Core;
using Xunit;

namespace HPass.IntegrationTests;

[Collection("sequential")]
public class CliFlowTests
{
    private static bool Unix => OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();
    private readonly CliFixture F;

    public CliFlowTests(CliFixture f) => F = f;

    // ---------- M0/M1：版本、初始化、条目 CRUD、元数据查询 ----------

    [Fact]
    public void Version_ReturnsZero()
    {
        var (exit, stdout, _) = F.Run("version");
        Assert.Equal(0, exit);
        Assert.Contains("hpass", stdout);
    }

    [Fact]
    public void Init_SecondTime_Fails()
    {
        var (exit, _, stderr) = F.Run("init", "--no-harden");
        Assert.Equal(ExitCodes.Vault, exit);
        Assert.Contains("已存在", stderr);
    }

    [Fact]
    public void ListJson_MetadataOnly_NoSecretsAnywhere()
    {
        var (exit, stdout, _) = F.Run("list", "--json");
        Assert.Equal(0, exit);
        Assert.DoesNotContain(CliFixture.DbPassword, stdout);
        Assert.DoesNotContain("ak-9", stdout);          // 字段值不可见
        Assert.DoesNotContain("127.0.0.1", stdout);     // 字段值不可见

        var metas = JsonSerializer.Deserialize<List<EntryMeta>>(stdout, HPassJsonContext.Default.ListEntryMeta)!;
        var db = metas.Single(m => m.Name == "db");
        Assert.Equal("database", db.Type);
        Assert.Equal("root", db.Username);
        Assert.Equal("prod", db.Tenant);
        Assert.True(db.HasPassword);
        Assert.Equal(["host", "api_key"], db.Fields);
        Assert.Contains("{{db}}", db.Placeholders);
        Assert.Contains("{{db.user}}", db.Placeholders);
        Assert.Contains("{{db.tenant}}", db.Placeholders);
        Assert.Contains("{{db.host}}", db.Placeholders);
        Assert.Contains("{{db.api_key}}", db.Placeholders);
    }

    [Fact]
    public void List_TextTable_ShowsMetadata()
    {
        var (exit, stdout, _) = F.Run("list");
        Assert.Equal(0, exit);
        Assert.Contains("db", stdout);
        Assert.Contains("root", stdout);
        Assert.DoesNotContain(CliFixture.DbPassword, stdout);
    }

    [Fact]
    public void Inspect_SingleEntry_Json()
    {
        var (exit, stdout, _) = F.Run("inspect", "db", "--json");
        Assert.Equal(0, exit);
        var meta = JsonSerializer.Deserialize<EntryMeta>(stdout, HPassJsonContext.Default.EntryMeta)!;
        Assert.Equal("db", meta.Name);
        Assert.True(meta.HasPassword);
        Assert.Contains("{{db.api_key}}", meta.Placeholders);
    }

    [Fact]
    public void Set_InvalidName_WithDot_Fails()
    {
        var (exit, _, stderr) = F.RunAsWithInput("init-pass-123", "some-pw", "set", "bad.name", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("非法", stderr);
    }

    [Fact]
    public void Set_ReservedFieldName_Fails()
    {
        var (exit, _, stderr) = F.RunAsWithInput("init-pass-123", "some-pw", "set", "x1", "-f", "user=v", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("保留字", stderr);
    }

    [Fact]
    public void Set_WithPassphrase_UpdatesAndExecutes()
    {
        if (!Unix) return;
        const string newPw = "Rotated-Pass-55";
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", "init-pass-123");
        try
        {
            var (exit, _, _) = F.RunWithInput(newPw, "set", "db", "--password-stdin");
            Assert.Equal(0, exit);
            var (execExit, stdout, _) = F.Run("exec", "--",
                "/bin/sh", "-c", $"[ \"{{{{db}}}}\" = \"{newPw}\" ] && echo MATCH");
            Assert.Equal(0, execExit);
            Assert.Contains("MATCH", stdout);
            Assert.DoesNotContain(newPw, stdout);
        }
        finally
        {
            // 恢复原密码，避免影响其他测试
            F.RunWithInput(CliFixture.DbPassword, "set", "db", "--password-stdin");
            Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null);
        }
    }

    [Fact]
    public void Set_WrongPassphrase_VaultUnchanged()
    {
        var vaultPath = Path.Combine(F.Home, "vault.json");
        var before = File.ReadAllBytes(vaultPath);
        var (exit, _, _) = F.RunAsWithInput("totally-wrong-pass", "some-pw", "set", "newentry", "--password-stdin");
        Assert.Equal(ExitCodes.Vault, exit);
        Assert.Equal(before, File.ReadAllBytes(vaultPath));
    }

    [Fact]
    public void Delete_RemovesEntry()
    {
        if (!Unix) return;
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", "init-pass-123");
        F.RunWithInput("tmp-pw-1", "set", "tmp-entry", "--password-stdin");
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null);

        var (delExit, _, _) = F.Run("delete", "tmp-entry");
        Assert.Equal(0, delExit);

        var (execExit, _, _) = F.Run("exec", "--", "/bin/echo", "{{tmp-entry}}");
        Assert.Equal(ExitCodes.UnknownPlaceholder, execExit);
    }

    [Fact]
    public void Rename_OldTokenFails_NewWorks()
    {
        if (!Unix) return;
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", "init-pass-123");
        F.RunWithInput("rn-pw-1", "set", "ren-me", "-u", "u1", "--password-stdin");
        var (renameExit, _, _) = F.Run("rename", "ren-me", "renamed");
        Assert.Equal(0, renameExit);
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null);

        var (oldExit, _, _) = F.Run("exec", "--", "/bin/echo", "{{ren-me}}");
        Assert.Equal(ExitCodes.UnknownPlaceholder, oldExit);

        var (newExit, stdout, _) = F.Run("exec", "--", "/bin/echo", "user={{renamed.user}}");
        Assert.Equal(0, newExit);
        Assert.Equal("user=u1\n", stdout);
        F.Run("delete", "renamed");
    }

    // ---------- M2：执行引擎（I2/I3/I5 + 三模式 + 超时 + 退出码） ----------

    [Fact]
    public void Exec_InlineMode_RedactsPassword()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--", "/bin/echo", "{{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("{{db}}\n", stdout);
    }

    [Fact]
    public void Exec_InlineMode_EchoThroughShell_Redacted()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--", "/bin/sh", "-c", "echo pw={{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("pw={{db}}\n", stdout);
    }

    [Fact]
    public void Exec_PlaintextFieldsVisible_SecretFieldsRedacted()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--",
            "/bin/sh", "-c", "echo {{db.user}} {{db.tenant}} {{db.host}} {{db.api_key}} {{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("root prod {{db.host}} {{db.api_key}} {{db}}\n", stdout);
    }

    [Fact]
    public void Exec_EnvInjection_SecretNotInArgv_RedactedInOutput()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--env", "db:HPASS_IT_V", "--",
            "/bin/sh", "-c", "printf '%s' \"$HPASS_IT_V\"");
        Assert.Equal(0, exit);
        Assert.Equal("{{db}}", stdout);
    }

    [Fact]
    public void Exec_ScriptMode_RedactsAndLeavesFileUntouched()
    {
        if (!Unix) return;
        var script = Path.Combine(Path.GetTempPath(), "hpass-it-script-" + Guid.NewGuid().ToString("N") + ".sh");
        File.WriteAllText(script, "#!/bin/sh\necho host={{db.host}} pw={{db}}\n");
        try
        {
            var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "-f", script, "--shell", "sh");
            Assert.Equal(0, exit);
            Assert.Equal("host={{db.host}} pw={{db}}\n", stdout);
            Assert.Contains("{{db}}", File.ReadAllText(script)); // 替换只发生在内存（I6 精神：不落盘）
        }
        finally { File.Delete(script); }
    }

    [Fact]
    public void Exec_ScriptMode_Pwsh()
    {
        if (!Unix) return;
        var which = F.Run("exec", "--shell", "none", "--", "/usr/bin/env", "pwsh", "-NoProfile", "-Command", "Write-Output ok");
        if (which.Exit != 0) return; // 无 pwsh 环境跳过

        var script = Path.Combine(Path.GetTempPath(), "hpass-it-script-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(script, "Write-Output \"pw={{db}}\"\n");
        try
        {
            var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "-f", script, "--shell", "pwsh");
            Assert.Equal(0, exit);
            Assert.Equal("pw={{db}}\n", stdout);
        }
        finally { File.Delete(script); }
    }

    [Fact]
    public void Exec_UnknownPlaceholder_RefusesToRun()
    {
        if (!Unix) return;
        var marker = Path.Combine(Path.GetTempPath(), "hpass-it-marker-" + Guid.NewGuid().ToString("N"));
        var (exit, _, stderr) = F.Run("exec", "--", "/bin/sh", "-c", $"echo {{{{nope}}}} > {marker}");
        Assert.Equal(ExitCodes.UnknownPlaceholder, exit);
        Assert.False(File.Exists(marker), "未知占位符时命令绝不能被执行（I2）");
        Assert.Contains("{{nope}}", stderr);
    }

    [Fact]
    public void Exec_UnknownField_RefusesToRun()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.Run("exec", "--", "/bin/echo", "{{db.nosuchfield}}");
        Assert.Equal(ExitCodes.UnknownPlaceholder, exit);
        Assert.Contains("nosuchfield", stderr);
    }

    [Fact]
    public void Exec_WrongPassphrase_FailsWithoutLeak()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.RunAs("wrong-passphrase-x", "exec", "--", "/bin/echo", "{{db}}");
        Assert.Equal(ExitCodes.Vault, exit);
        Assert.DoesNotContain(CliFixture.DbPassword, stderr);
    }

    [Fact]
    public void Exec_NoPassphraseAvailable_NonInteractive_Fails()
    {
        if (!Unix) return;
        var (exit, _, _) = F.Run("exec", "--", "/bin/echo", "{{db}}");
        Assert.Equal(ExitCodes.Vault, exit);
    }

    [Fact]
    public void Exec_TamperedVault_Fails()
    {
        if (!Unix) return;
        var vaultPath = Path.Combine(F.Home, "vault.json");
        var original = File.ReadAllText(vaultPath);
        try
        {
            // 精准篡改 db 条目的密码密文（GCM 认证必须失败 → 退出码 3）
            var json = JsonSerializer.Deserialize<VaultFile>(original, HPassJsonContext.Default.VaultFile)!;
            var entry = json.Entries.Single(x => x.Name == "db");
            var ct = Convert.FromBase64String(entry.Ct);
            ct[0] ^= 0xFF;
            entry.Ct = Convert.ToBase64String(ct);
            File.WriteAllText(vaultPath, JsonSerializer.Serialize(json, HPassJsonContext.Default.VaultFile));

            var (exit, _, _) = F.RunAs("init-pass-123", "exec", "--", "/bin/echo", "{{db}}");
            Assert.Equal(ExitCodes.Vault, exit);
        }
        finally { File.WriteAllText(vaultPath, original); }
    }

    [Fact]
    public void Exec_Timeout_Returns124_AndKillsTree()
    {
        if (!Unix) return;
        var start = DateTime.UtcNow;
        var (exit, _, stderr) = F.RunAs("init-pass-123", "exec", "--timeout", "1", "--",
            "/bin/sh", "-c", "sleep 20 && echo {{db}}");
        Assert.Equal(ExitCodes.Timeout, exit);
        Assert.True((DateTime.UtcNow - start).TotalSeconds < 15);
        Assert.DoesNotContain(CliFixture.DbPassword, stderr); // I5：超时信息不含密文
    }

    [Fact]
    public void Exec_ExitCodePassthrough()
    {
        if (!Unix) return;
        var (exit, _, _) = F.RunAs("init-pass-123", "exec", "--", "/bin/sh", "-c", "exit 7");
        Assert.Equal(7, exit);
    }

    [Fact]
    public void Exec_ShellNone_DirectExec()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--shell", "none", "--",
            "/bin/echo", "plain-{{db.user}}");
        Assert.Equal(0, exit);
        Assert.Equal("plain-root\n", stdout);
    }

    [Fact]
    public void Exec_ShellNone_DoesNotNeedPassphrase_WhenOnlyPlaintextUsed()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.Run("exec", "--shell", "none", "--", "/bin/echo", "{{db.user}}");
        Assert.Equal(0, exit);
        Assert.Equal("root\n", stdout);
    }

    [Fact]
    public void Exec_PasswordArgWithSpaces_SingleArg()
    {
        if (!Unix) return;
        // 密码含空格：bash 引号保护下仍是单个参数，echo 原样输出后脱敏
        Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", "init-pass-123");
        try
        {
            F.RunWithInput("space pass 77", "set", "spacey", "--password-stdin");
            var (exit, stdout, _) = F.Run("exec", "--", "/bin/echo", "x={{spacey}}x");
            Assert.Equal(0, exit);
            Assert.Equal("x={{spacey}}x\n", stdout);
        }
        finally
        {
            Environment.SetEnvironmentVariable("HPASS_PASSPHRASE", null);
            F.Run("delete", "spacey");
        }
    }

    // ---------- M3：rotate / doctor / harden / 权限 ----------

    [Fact]
    public void Rotate_ExecStillWorks()
    {
        if (!Unix) return;
        // rotate 同时改写 vault.json（新公钥+新包裹）与 master.key（新私钥），必须成对快照与恢复
        var vaultPath = Path.Combine(F.Home, "vault.json");
        var keyPath = Path.Combine(F.Home, "master.key");
        var vaultBefore = File.ReadAllText(vaultPath);
        var keyBefore = File.ReadAllText(keyPath);
        try
        {
            var (rotExit, _, _) = F.RunAs("init-pass-123", "rotate");
            Assert.Equal(0, rotExit);
            var (execExit, stdout, _) = F.RunAs("init-pass-123", "exec", "--", "/bin/echo", "{{db}}");
            Assert.Equal(0, execExit);
            Assert.Equal("{{db}}\n", stdout);
        }
        finally
        {
            File.WriteAllText(vaultPath, vaultBefore);
            File.WriteAllText(keyPath, keyBefore);
        }
    }

    [Fact]
    public void Doctor_ReportsHealthyVault()
    {
        var (exit, stdout, _) = F.Run("doctor");
        Assert.Equal(0, exit);
        Assert.Contains("vault", stdout);
        Assert.Contains("shell", stdout);
    }

    [Fact]
    public void Harden_NonInteractive_PrintsGuidance_NoDamage()
    {
        var before = File.ReadAllText(Path.Combine(F.Home, "vault.json"));
        var (exit, stdout, _) = F.Run("harden");
        Assert.Equal(0, exit);
        Assert.Contains("sudo", stdout);
        Assert.Equal(before, File.ReadAllText(Path.Combine(F.Home, "vault.json")));
    }

    [Fact]
    public void VaultFiles_HaveTightPermissions()
    {
        if (!Unix) return;
        var mode = File.GetUnixFileMode(Path.Combine(F.Home, "vault.json"));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        var dirMode = File.GetUnixFileMode(F.Home);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, dirMode);
    }
}
