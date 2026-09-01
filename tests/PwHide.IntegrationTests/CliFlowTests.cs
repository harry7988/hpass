using System.Text.Json;
using PwHide.Core;
using Xunit;

namespace PwHide.IntegrationTests;

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
        Assert.Contains("pwhide", stdout);
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

        var metas = JsonSerializer.Deserialize<List<EntryMeta>>(stdout, PwHideJsonContext.Default.ListEntryMeta)!;
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
        var meta = JsonSerializer.Deserialize<EntryMeta>(stdout, PwHideJsonContext.Default.EntryMeta)!;
        Assert.Equal("db", meta.Name);
        Assert.True(meta.HasPassword);
        Assert.Contains("{{db.api_key}}", meta.Placeholders);
    }

    [Fact]
    public void Set_InvalidName_WithDot_Fails()
    {
        var (exit, _, stderr) = F.RunAsWithInput("init-pass-123", "some-pw-99", "set", "bad.name", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("非法", stderr);
    }

    [Fact]
    public void Set_ReservedFieldName_Fails()
    {
        var (exit, _, stderr) = F.RunAsWithInput("init-pass-123", "some-pw-99", "set", "x1", "-f", "user=v", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("保留字", stderr);
    }

    [Fact]
    public void Set_WithPassphrase_UpdatesAndExecutes()
    {
        if (!Unix) return;
        const string newPw = "Rotated-Pass-55";
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
        try
        {
            var (exit, _, _) = F.RunWithInput(newPw, "set", "db", "--password-stdin");
            Assert.Equal(0, exit);
            var (execExit, stdout, _) = F.Run("exec", "--allow-echo", "--",
                "/bin/sh", "-c", $"[ \"{{{{db}}}}\" = \"{newPw}\" ] && echo MATCH");
            Assert.Equal(0, execExit);
            Assert.Contains("MATCH", stdout);
            Assert.DoesNotContain(newPw, stdout);
        }
        finally
        {
            // 恢复原密码，避免影响其他测试
            F.RunWithInput(CliFixture.DbPassword, "set", "db", "--password-stdin");
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);
        }
    }

    [Fact]
    public void Set_WrongPassphrase_VaultUnchanged()
    {
        var vaultPath = Path.Combine(F.Home, "vault.json");
        var before = File.ReadAllBytes(vaultPath);
        var (exit, _, _) = F.RunAsWithInput("totally-wrong-pass", "some-pw-99", "set", "newentry", "--password-stdin");
        Assert.Equal(ExitCodes.Vault, exit);
        Assert.Equal(before, File.ReadAllBytes(vaultPath));
    }

    [Fact]
    public void Delete_RemovesEntry()
    {
        if (!Unix) return;
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
        F.RunWithInput("tmp-pw-11", "set", "tmp-entry", "--password-stdin");
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);

        var (delExit, _, _) = F.Run("delete", "tmp-entry");
        Assert.Equal(0, delExit);

        var (execExit, _, _) = F.Run("exec", "--", "/bin/echo", "{{tmp-entry}}");
        Assert.Equal(ExitCodes.UnknownPlaceholder, execExit);
    }

    [Fact]
    public void Rename_OldTokenFails_NewWorks()
    {
        if (!Unix) return;
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
        F.RunWithInput("rn-pw-11", "set", "ren-me", "-u", "u1", "--password-stdin");
        var (renameExit, _, _) = F.Run("rename", "ren-me", "renamed");
        Assert.Equal(0, renameExit);
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);

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
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--", "/bin/echo", "{{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("{{db}}\n", stdout);
    }

    [Fact]
    public void Exec_InlineMode_EchoThroughShell_Redacted()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--", "/bin/sh", "-c", "echo pw={{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("pw={{db}}\n", stdout);
    }

    [Fact]
    public void Exec_PlaintextFieldsVisible_SecretFieldsRedacted()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--",
            "/bin/sh", "-c", "echo {{db.user}} {{db.tenant}} {{db.host}} {{db.api_key}} {{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("root prod {{db.host}} {{db.api_key}} {{db}}\n", stdout);
    }

    [Fact]
    public void Exec_EnvInjection_SecretNotInArgv_RedactedInOutput()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--env", "db:PWHIDE_IT_V", "--",
            "/bin/sh", "-c", "printf '%s' \"$PWHIDE_IT_V\"");
        Assert.Equal(0, exit);
        Assert.Equal("{{db}}", stdout);
    }

    // ---------- --ph 自定义占位符定界符（#name# / @name@，规避 {{ 模板语法冲突） ----------

    [Fact]
    public void Exec_PhHash_ResolvesAndRedacts()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--ph", "#", "--allow-echo", "--",
            "/bin/sh", "-c", "echo pw=#db#");
        Assert.Equal(0, exit);
        Assert.Equal("pw=#db#\n", stdout);
    }

    [Fact]
    public void Exec_PhHash_BraceLiteralsArePlainText()
    {
        if (!Unix) return;
        // --ph # 下 {{db}} 是字面量：不解析、不脱敏、原样输出（Helm/Jinja 模板不再冲突）
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--ph", "#", "--",
            "/bin/sh", "-c", "echo template={{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("template={{db}}\n", stdout);
    }

    [Fact]
    public void Exec_PhHash_UnknownPlaceholder_Exit4WithHashToken()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.RunAs("init-pass-123", "exec", "--ph", "#", "--", "/bin/echo", "#nope#");
        Assert.Equal(ExitCodes.UnknownPlaceholder, exit);
        Assert.Contains("#nope#", stderr);
        Assert.DoesNotContain(CliFixture.DbPassword, stderr);
    }

    [Fact]
    public void Exec_PhHash_EchoProbeStillEnforced()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.RunAs("init-pass-123", "exec", "--ph", "#", "--", "/bin/echo", "#db#");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("--allow-echo", stderr);
        Assert.Contains("#db#", stderr);
    }

    [Fact]
    public void Exec_PhHash_EnvInjection_RedactsToHashToken()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--ph", "#", "--allow-echo", "--env", "db:PWHIDE_IT_V", "--",
            "/bin/sh", "-c", "printf '%s' \"$PWHIDE_IT_V\"");
        Assert.Equal(0, exit);
        Assert.Equal("#db#", stdout);
    }

    [Fact]
    public void Exec_PhAt_ScriptMode_FieldAndSecret()
    {
        if (!Unix) return;
        var script = Path.Combine(Path.GetTempPath(), "pwhide-ph-" + Guid.NewGuid().ToString("N") + ".sh");
        File.WriteAllText(script, "#!/bin/sh\necho pw=@db@ user=@db.user@\n");
        try
        {
            var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--ph", "@", "--allow-echo", "-f", script, "--shell", "sh");
            Assert.Equal(0, exit);
            Assert.Equal("pw=@db@ user=root\n", stdout);
            Assert.Contains("@db@", File.ReadAllText(script));   // 脚本文件保持占位符（替换只在内存）
        }
        finally { File.Delete(script); }
    }

    [Fact]
    public void Exec_PhInvalidSymbol_UsageError()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.Run("exec", "--ph", "%", "--", "/bin/echo", "x");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("--ph", stderr);
    }

    [Fact]
    public void Exec_ScriptMode_RedactsAndLeavesFileUntouched()
    {
        if (!Unix) return;
        var script = Path.Combine(Path.GetTempPath(), "pwhide-it-script-" + Guid.NewGuid().ToString("N") + ".sh");
        File.WriteAllText(script, "#!/bin/sh\necho host={{db.host}} pw={{db}}\n");
        try
        {
            var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "-f", script, "--shell", "sh");
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

        var script = Path.Combine(Path.GetTempPath(), "pwhide-it-script-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(script, "Write-Output \"pw={{db}}\"\n");
        try
        {
            var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "-f", script, "--shell", "pwsh");
            Assert.Equal(0, exit);
            // runner 上 pwsh 会包裹 VT 转义序列：断言脱敏存在、密文不存在即可
            Assert.Contains("pw={{db}}", stdout);
            Assert.DoesNotContain(CliFixture.DbPassword, stdout);
        }
        finally { File.Delete(script); }
    }

    [Fact]
    public void Exec_UnknownPlaceholder_RefusesToRun()
    {
        if (!Unix) return;
        var marker = Path.Combine(Path.GetTempPath(), "pwhide-it-marker-" + Guid.NewGuid().ToString("N"));
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
        var (exit, _, stderr) = F.RunAs("wrong-passphrase-x", "exec", "--allow-echo", "--", "/bin/echo", "{{db}}");
        Assert.Equal(ExitCodes.Vault, exit);
        Assert.DoesNotContain(CliFixture.DbPassword, stderr);
    }

    [Fact]
    public void Exec_NoPassphraseAvailable_NonInteractive_Fails()
    {
        if (!Unix) return;
        var (exit, _, _) = F.Run("exec", "--allow-echo", "--", "/bin/echo", "{{db}}");
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
            var json = JsonSerializer.Deserialize<VaultFile>(original, PwHideJsonContext.Default.VaultFile)!;
            var entry = json.Entries.Single(x => x.Name == "db");
            var ct = Convert.FromBase64String(entry.Ct);
            ct[0] ^= 0xFF;
            entry.Ct = Convert.ToBase64String(ct);
            File.WriteAllText(vaultPath, JsonSerializer.Serialize(json, PwHideJsonContext.Default.VaultFile));

            var (exit, _, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--", "/bin/echo", "{{db}}");
            Assert.Equal(ExitCodes.Vault, exit);
        }
        finally { File.WriteAllText(vaultPath, original); }
    }

    [Fact]
    public void Exec_Timeout_Returns124_AndKillsTree()
    {
        if (!Unix) return;
        var start = DateTime.UtcNow;
        var (exit, _, stderr) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--timeout", "1", "--",
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
    public void Exec_ShellNone_WorksOnAllPlatforms_WithPwsh()
    {
        // 覆盖 Windows：--shell none 直接 spawn（不经 shell 引号转换）
        var (probe, _, _) = F.Run("exec", "--shell", "none", "--", "pwsh", "-NoProfile", "-Command", "Write-Output ok");
        if (probe != 0) return; // 无 pwsh 环境跳过

        var (exit, stdout, _) = F.Run("exec", "--shell", "none", "--",
            "pwsh", "-NoProfile", "-Command", "Write-Output u={{db.user}}");
        Assert.Equal(0, exit);
        Assert.Contains("u=root", stdout);
    }

    [Fact]
    public void Exec_AutoShell_Detected_AcrossPlatforms()
    {
        // auto 在 Windows 应找到 pwsh（带 .exe 探测），Unix 找到 bash/sh
        var (exit, stdout, _) = F.Run("doctor");
        Assert.Equal(0, exit);
        if (OperatingSystem.IsWindows())
            Assert.Contains("pwsh", stdout);
        else
            Assert.Matches(new System.Text.RegularExpressions.Regex(@"auto → \S*(bash|sh|zsh)"), stdout);
    }

    [Fact]
    public void Exec_PasswordArgWithSpaces_SingleArg()
    {
        if (!Unix) return;
        // 密码含空格：bash 引号保护下仍是单个参数，echo 原样输出后脱敏
        Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
        try
        {
            F.RunWithInput("space pass 77", "set", "spacey", "--password-stdin");
            var (exit, stdout, _) = F.Run("exec", "--allow-echo", "--", "/bin/echo", "x={{spacey}}x");
            Assert.Equal(0, exit);
            Assert.Equal("x={{spacey}}x\n", stdout);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);
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
            var (execExit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--", "/bin/echo", "{{db}}");
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
    public void Harden_NonInteractive_NoDamage()
    {
        if (!Hardening.Unix) return;
        // 独立 home：harden 会改变保护标志（不改变内容）
        var home = Path.Combine(Path.GetTempPath(), "pwhide-it-hn-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
            Assert.Equal(0, F.RunIn(home, null, "init", "--no-harden").Exit);
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);
            var before = File.ReadAllText(Path.Combine(home, "vault.json"));

            var (exit, stdout, stderr) = F.RunIn(home, null, "harden");
            if (OperatingSystem.IsMacOS())
            {
                // macOS 普通用户可直接 uchg：应成功且文件被保护
                Assert.Equal(0, exit);
                Assert.Contains("uchg", stdout);
                Assert.True(Hardening.IsImmutable(Path.Combine(home, "vault.json")));
            }
            else
            {
                // Linux 普通用户无法 chattr 且 sudo -n 不可用：必须非 0（假成功会让加固被静默跳过）
                Assert.Equal(ExitCodes.Vault, exit);
                Assert.Contains("sudo pwhide", stderr);
            }
            Assert.Equal(before, File.ReadAllText(Path.Combine(home, "vault.json")));
        }
        finally
        {
            Hardening.ClearImmutable(Path.Combine(home, "vault.json"));
            Hardening.ClearImmutable(Path.Combine(home, "master.key"));
            try { Directory.Delete(home, true); } catch { }
        }
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

    // ---------- 安全增强：弱密码拦截 / 回显探测拦截 / 输出泄露审计 ----------

    [Fact]
    public void Set_WeakCommonStatement_Rejected()
    {
        if (!Unix) return;
        var vaultPath = Path.Combine(F.Home, "vault.json");
        var before = File.ReadAllBytes(vaultPath);
        // 密码恰为"日志里非常常见的语句"：必须拒绝，否则会误替换日志且替换位置暴露密码
        var (exit, _, stderr) = F.RunAsWithInput("init-pass-123", "select 1", "set", "weak1", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("弱密码", stderr);
        Assert.Contains("--force-weak", stderr);
        var (exit2, _, _) = F.RunAsWithInput("init-pass-123", "password", "set", "weak2", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit2);
        var (exit3, _, _) = F.RunAsWithInput("init-pass-123", "short7", "set", "weak3", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit3);
        Assert.Equal(before, File.ReadAllBytes(vaultPath));
    }

    [Fact]
    public void Set_ForceWeak_Overrides()
    {
        if (!Unix) return;
        try
        {
            var (exit, _, _) = F.RunAsWithInput("init-pass-123", "aaaaaaaa1", "set", "noisy", "--password-stdin", "--force-weak");
            Assert.Equal(0, exit);
        }
        finally { F.Run("delete", "noisy"); }
    }

    [Fact]
    public void Set_WeakFieldValue_WarnsButSaves()
    {
        if (!Unix) return;
        try
        {
            var (exit, _, stderr) = F.RunAsWithInput("init-pass-123", "Str0ng-Pass-77",
                "set", "fieldwarn", "-f", "host=localhost", "--password-stdin");
            Assert.Equal(0, exit);
            Assert.Contains("警告", stderr);   // 字段值常见只警告不阻断
            Assert.DoesNotContain("localhost", F.Run("inspect", "fieldwarn").Stdout); // 值仍不可见
        }
        finally { F.Run("delete", "fieldwarn"); }
    }

    [Fact]
    public void Exec_EchoProbe_Refused_CommandNotRun()
    {
        if (!Unix) return;
        var marker = Path.Combine(Path.GetTempPath(), "pwhide-probe-" + Guid.NewGuid().ToString("N"));
        var (exit, _, stderr) = F.RunAs("init-pass-123", "exec", "--",
            "/bin/sh", "-c", $"echo {{{{db}}}} > {marker}");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("--allow-echo", stderr);
        Assert.False(File.Exists(marker), "回显探测命令必须被拒绝执行");
    }

    [Fact]
    public void Exec_EchoProbe_AllowEcho_Redacts()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--",
            "/bin/sh", "-c", "echo pw={{db}}");
        Assert.Equal(0, exit);
        Assert.Equal("pw={{db}}\n", stdout);
    }

    [Fact]
    public void Exec_EchoProbe_PlaintextFieldsNotBlocked()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.Run("exec", "--", "/bin/echo", "u={{db.user}}");
        Assert.Equal(0, exit);
        Assert.Equal("u=root\n", stdout);
    }

    [Fact]
    public void Exec_HighFrequencyCollision_Warns()
    {
        if (!Unix) return;
        try
        {
            F.RunAsWithInput("init-pass-123", "aaaaaaaa1", "set", "noisy", "--password-stdin", "--force-weak");
            // 弱密码与输出高频碰撞（40 次）→ 必须给出换密码警告
            var (exit, _, stderr) = F.RunAs("init-pass-123", "exec", "--",
                "/bin/sh", "-c", "yes {{{{noisy}}}} | head -40");
            Assert.Equal(0, exit);
            Assert.Contains("建议更换强密码", stderr);
            Assert.DoesNotContain("aaaaaaaa1", stderr);
        }
        finally { F.Run("delete", "noisy"); }
    }

    [Fact]
    public void Exec_SecondDoubleDash_PreservedInCommand()
    {
        if (!Unix) return;
        // 首个 -- 是分隔符；命令自身的 --（git log -- path 等）必须原样保留
        var (exit, stdout, _) = F.Run("exec", "--", "/bin/echo", "--", "marker={{db.user}}");
        Assert.Equal(0, exit);
        Assert.Equal("-- marker=root\n", stdout);
    }

    [Fact]
    public void Exec_OptionsAfterPositional_NotHijacked()
    {
        if (!Unix) return;
        // exec /bin/echo -f x：-f 属于 echo，不得被 pwhide 当作脚本选项劫持
        var (exit, stdout, stderr) = F.Run("exec", "/bin/echo", "-f", "x-{{db.user}}");
        Assert.Equal(0, exit);
        Assert.Equal("-f x-root\n", stdout);
        Assert.DoesNotContain("脚本不存在", stderr);
    }

    [Fact]
    public void Exec_HomeNotHijackedInsideCommand()
    {
        if (!Unix) return;
        // pwhide exec -- /bin/echo --home X：命令自己的 --home 不得被全局扫描剥离
        var (exit, stdout, _) = F.Run("exec", "--", "/bin/echo", "--home", "GPGHOME");
        Assert.Equal(0, exit);
        Assert.Equal("--home GPGHOME\n", stdout);
    }

    [Fact]
    public void Exec_EnvInjectionActivatingRedaction_WithEcho_ProbeRefused()
    {
        if (!Unix) return;
        // --env 激活脱敏规则 + echo 候选 = 字典探测 oracle（第 2 轮评审发现的绕过），必须拒绝
        var (exit, _, stderr) = F.Run("exec", "--env", "db:PWHIDE_PROBE_V", "--", "/bin/echo", "swordfish");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("--allow-echo", stderr);
        // 放行后：候选≠密码则原样输出（等值 oracle 的输出面由 --allow-echo 交给人工确认）
        var (exit2, stdout2, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--env", "db:PWHIDE_PROBE_V", "--", "/bin/echo", "swordfish");
        Assert.Equal(0, exit2);
        Assert.Equal("swordfish\n", stdout2);
    }

    [Fact]
    public void WriteCommand_SymlinkedLock_Refused_NoPrivilegedChown()
    {
        if (!Unix) return;
        var home = Path.Combine(Path.GetTempPath(), "pwhide-it-symlock-" + Guid.NewGuid().ToString("N"));
        var target = Path.Combine(Path.GetTempPath(), "pwhide-symtarget-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
            Assert.Equal(0, F.RunIn(home, null, "init", "--no-harden").Exit);
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);
            File.WriteAllText(target, "critical-content");

            // 恶意进程把 run/lock 换成指向敏感文件的符号链接：任何写命令必须干净拒绝，
            // 绝不能让（潜在的 root）属主归还落在链接上（O_NOFOLLOW + lchown 双防）
            var lockPath = Path.Combine(home, "run", "lock");
            File.Delete(lockPath);
            File.CreateSymbolicLink(lockPath, target);

            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
            var (exit, _, stderr) = F.RunIn(home, "Sym-Pass-91", "set", "x", "--password-stdin");
            Assert.Equal(ExitCodes.Vault, exit);
            Assert.Contains("符号链接", stderr);
            Assert.Equal("critical-content", File.ReadAllText(target));   // 目标内容/状态未被波及
        }
        finally
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);
            try { File.Delete(Path.Combine(home, "run", "lock")); } catch { }
            Hardening.ClearImmutable(Path.Combine(home, "vault.json"));
            Hardening.ClearImmutable(Path.Combine(home, "master.key"));
            try { Directory.Delete(home, true); } catch { }
            File.Delete(target);
        }
    }

    [Fact]
    public void Exec_EnvReservedVariable_Rejected()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.Run("exec", "--env", "db:PWHIDE_PASSPHRASE", "--", "/bin/echo", "x");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("保留变量", stderr);
    }

    [Fact]
    public void Exec_UnknownOptionBeforeCommand_Rejected()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.Run("exec", "--tmeout", "5", "--", "/bin/echo", "x");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("未知的 pwhide 选项", stderr);
    }

    [Fact]
    public void Doctor_ReportsInterruptedRootInstallResidue()
    {
        if (!Unix) return;
        var home = Path.Combine(Path.GetTempPath(), "pwhide-it-orig-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
            Assert.Equal(0, F.RunIn(home, null, "init", "--no-harden").Exit);
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);
            File.WriteAllText(Path.Combine(home, "vault.json.pwhide-orig-abc"), "old-vault-bytes");
            var (exit, stdout, _) = F.RunIn(home, null, "doctor");
            Assert.Equal(0, exit);
            Assert.Contains("安装残留", stdout);
            Assert.Contains("pwhide-orig-abc", stdout);
            Assert.True(File.Exists(Path.Combine(home, "vault.json.pwhide-orig-abc")), "orig 是旧库唯一副本，doctor 不得删除");
        }
        finally
        {
            Hardening.ClearImmutable(Path.Combine(home, "vault.json"));
            Hardening.ClearImmutable(Path.Combine(home, "master.key"));
            try { Directory.Delete(home, true); } catch { }
        }
    }

    [Fact]
    public void Exec_MissingCommand_FailsFast_BeforePassphrase()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.Run("exec");   // 无口令环境：用法错误应先于口令需求
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("缺少要执行的命令", stderr);
    }

    [Fact]
    public void Exec_ScriptAndCommand_MutuallyExclusive()
    {
        if (!Unix) return;
        var script = Path.Combine(Path.GetTempPath(), "pwhide-mx-" + Guid.NewGuid().ToString("N") + ".sh");
        File.WriteAllText(script, "echo ok\n");
        try
        {
            var (exit, _, stderr) = F.Run("exec", "-f", script, "--", "/bin/echo", "extra");
            Assert.Equal(ExitCodes.Usage, exit);
            Assert.Contains("不能同时", stderr);
        }
        finally { File.Delete(script); }
    }

    [Fact]
    public void Exec_EnvVarNameValidated()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.Run("exec", "--env", "db:A=B", "--", "/bin/echo", "x");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("环境变量名非法", stderr);
    }

    [Fact]
    public void Exec_LargeTimeout_NoOverflow()
    {
        if (!Unix) return;
        var (exit, stdout, _) = F.Run("exec", "--timeout", "2147484", "--", "/bin/echo", "ok-{{db.user}}");
        Assert.Equal(0, exit);
        Assert.Equal("ok-root\n", stdout);
    }

    [Fact]
    public void Exec_StartFailure_FixedMessage_NoSecretLeak()
    {
        if (!Unix) return;
        // none 模式把密文解析为命令名：启动失败消息不得携带密文（I5）
        var (exit, _, stderr) = F.RunAs("init-pass-123", "exec", "--shell", "none", "--", "{{db}}");
        Assert.Equal(ExitCodes.Usage, exit);
        Assert.Contains("无法启动子进程", stderr);
        Assert.DoesNotContain(CliFixture.DbPassword, stderr);
    }

    [Fact]
    public void Set_EmptyPasswordAndFieldValue_Rejected()
    {
        if (!Unix) return;
        var (exit, _, stderr) = F.RunAsWithInput("init-pass-123", "", "set", "empty1", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit);
        // 空密码经 --password-stdin 会被"未读到密码"校验先拦（同为用法错误）；-f note= 的空值走"不能为空"
        Assert.True(stderr.Contains("不能为空") || stderr.Contains("未从 stdin 读到密码"), $"实际: {stderr}");
        var (exit2, _, _) = F.RunAsWithInput("init-pass-123", "Str0ng-Pass-9x", "set", "empty2", "-f", "note=", "--password-stdin");
        Assert.Equal(ExitCodes.Usage, exit2);
    }

    [Fact]
    public void Rotate_CreatesRecoveryBackup()
    {
        if (!Unix) return;
        var vaultPath = Path.Combine(F.Home, "vault.json");
        var keyPath = Path.Combine(F.Home, "master.key");
        var vaultBefore = File.ReadAllText(vaultPath);
        var keyBefore = File.ReadAllText(keyPath);
        try
        {
            Assert.Equal(0, F.RunAs("init-pass-123", "rotate").Exit);
            Assert.True(File.Exists(Path.Combine(F.Home, "run", "rotate-backup.vault.json")), "rotate 前必须备份 vault.json");
            Assert.True(File.Exists(Path.Combine(F.Home, "run", "rotate-backup.master.key")), "rotate 前必须备份 master.key");
            var (execExit, stdout, _) = F.RunAs("init-pass-123", "exec", "--allow-echo", "--", "/bin/echo", "{{db}}");
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
    public void PassphraseFile_LoosePermissions_Warned()
    {
        if (!Unix) return;
        var home = Path.Combine(Path.GetTempPath(), "pwhide-it-loose-" + Guid.NewGuid().ToString("N"));
        var pwFile = Path.Combine(Path.GetTempPath(), "pwhide-pw-" + Guid.NewGuid().ToString("N"));
        try
        {
            File.WriteAllText(pwFile, "loose-pass-123\n");
            File.SetUnixFileMode(pwFile, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE_FILE", pwFile);
            var (exit, _, stderr) = F.RunIn(home, null, "init", "--no-harden");
            Assert.Equal(0, exit);
            Assert.Contains("可读", stderr);
            Assert.Contains("chmod 600", stderr);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE_FILE", null);
            File.Delete(pwFile);
            try { Directory.Delete(home, true); } catch { }
        }
    }

    [Fact]
    public void Exec_ChildEnv_HasNoPassphrase()
    {
        if (!Unix) return;
        // 主口令不得透传给子进程（printenv/env 即可泄露，且口令不在脱敏规则内）
        var (exit, stdout, _) = F.RunAs("init-pass-123", "exec", "--",
            "/bin/sh", "-c", "echo \"[$PWHIDE_PASSPHRASE][$PWHIDE_PASSPHRASE_FILE]\"");
        Assert.Equal(0, exit);
        Assert.Equal("[][]\n", stdout);
    }

    [Fact]
    public void InstallStagedCmd_RejectsSymlinks()
    {
        if (!Unix) return;
        var home = Path.Combine(Path.GetTempPath(), "pwhide-it-symlink-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", "init-pass-123");
            Assert.Equal(0, F.RunIn(home, null, "init", "--no-harden").Exit);
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);

            var vaultPath = Path.Combine(home, "vault.json");
            var sentinel = Path.Combine(Path.GetTempPath(), "pwhide-sentinel-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(sentinel, "sentinel-content");

            var stagingDir = Path.Combine(home, "run", "staging");
            Directory.CreateDirectory(stagingDir);

            // 1) 目标是符号链接（指向外部文件）：拒绝，外部文件不得被 root 操作波及
            var backup = File.ReadAllBytes(vaultPath);
            File.Delete(vaultPath);
            File.CreateSymbolicLink(vaultPath, sentinel);
            var staged = Path.Combine(stagingDir, "vault.json.x1");
            File.WriteAllBytes(staged, "{}"u8.ToArray());
            var (exit1, _, err1) = F.RunIn(home, null, "_install-staged", staged, vaultPath);
            Assert.Equal(ExitCodes.Vault, exit1);
            Assert.Contains("符号链接", err1);
            Assert.Equal("sentinel-content", File.ReadAllText(sentinel));
            File.Delete(vaultPath);
            File.WriteAllBytes(vaultPath, backup);

            // 2) 暂存是符号链接：拒绝
            var outside = Path.Combine(Path.GetTempPath(), "pwhide-outside-" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(outside, "{}");
            var stagedLink = Path.Combine(stagingDir, "vault.json.x2");
            File.CreateSymbolicLink(stagedLink, outside);
            var (exit2, _, err2) = F.RunIn(home, null, "_install-staged", stagedLink, vaultPath);
            Assert.Equal(ExitCodes.Vault, exit2);
            Assert.Contains("符号链接", err2);
            Assert.Equal("{}", File.ReadAllText(outside));

            // 3) 正常安装不受影响（回归）
            var good = Path.Combine(stagingDir, "vault.json.x3");
            File.WriteAllBytes(good, "{}"u8.ToArray());
            Assert.Equal(0, F.RunIn(home, null, "_install-staged", good, vaultPath).Exit);
            File.Delete(vaultPath);
            File.WriteAllBytes(vaultPath, backup);
            File.Delete(outside);
            File.Delete(sentinel);
        }
        finally
        {
            Hardening.ClearImmutable(Path.Combine(home, "vault.json"));
            try { Directory.Delete(home, true); } catch { }
        }
    }

    [Fact]
    public void Init_PassphraseTooLong_Rejected()
    {
        if (!Unix) return;
        var home = Path.Combine(Path.GetTempPath(), "pwhide-it-longpw-" + Guid.NewGuid().ToString("N"));
        try
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", new string('x', 2000));
            var (exit, _, stderr) = F.RunIn(home, null, "init", "--no-harden");
            Assert.Equal(ExitCodes.Vault, exit);
            Assert.Contains("过长", stderr);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PWHIDE_PASSPHRASE", null);
            try { Directory.Delete(home, true); } catch { }
        }
    }

    [Fact]
    public void AuditOutputs_NoSecretInAnyCommandOutput()
    {
        // 全命令输出面审计（I1/I5）：正常输出与错误输出均不得包含密码与字段值
        var secrets = new[] { CliFixture.DbPassword, "ssh-pw-77", "ak-9" };
        var outputs = new (int Exit, string Stdout, string Stderr)[]
        {
            F.Run("version"),
            F.Run("list"),
            F.Run("list", "--json"),
            F.Run("inspect", "db"),
            F.Run("doctor"),
            F.RunAs("wrong-pass-99", "exec", "--", "/bin/echo", "{{db}}"),        // 口令错误路径
            F.Run("exec", "--", "/bin/echo", "{{ghost}}"),                          // 未知占位符路径
            F.RunAsWithInput("init-pass-123", "password", "set", "weakx", "--password-stdin"), // 弱密码拒绝路径
        };
        foreach (var (exit, stdout, stderr) in outputs)
        {
            foreach (var secret in secrets)
            {
                Assert.DoesNotContain(secret, stdout);
                Assert.DoesNotContain(secret, stderr);
            }
        }
    }
}
