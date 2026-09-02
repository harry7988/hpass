using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PwHide.Core;

/// <summary>
/// vault 目录布局：vault.json（条目库，元数据明文+密文）、master.key（口令加密的 RSA 私钥）、
/// config.json、run/（锁与运行期产物）。写入一律走 SecureFile 原子替换。
/// </summary>
public sealed class Vault : IDisposable
{
    public string Dir { get; }
    public string VaultPath => Path.Combine(Dir, "vault.json");
    public string MasterKeyPath => Path.Combine(Dir, "master.key");
    public string ConfigPath => Path.Combine(Dir, "config.json");
    public string RunDir => Path.Combine(Dir, "run");
    public string StagingDir => Path.Combine(RunDir, "staging");

    public VaultFile Data { get; private set; } = new();
    public PwHideConfig Config { get; private set; } = new();

    private RSA? _privateKey;
    private byte[]? _dek;

    private Vault(string dir)
    {
        Dir = dir;
    }

    public void Dispose()
    {
        _dek?.AsSpan().Clear();
        _dek = null;
        _privateKey?.Dispose();
        _privateKey = null;
    }

    public static string DefaultHome()
    {
        var env = Environment.GetEnvironmentVariable("PWHIDE_HOME");
        if (!string.IsNullOrEmpty(env)) return env;
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(profile, ".pwhide");
    }

    public static bool Exists(string dir) =>
        File.Exists(Path.Combine(dir, "vault.json")) && File.Exists(Path.Combine(dir, "master.key"));

    public static Vault Create(string dir, string passphrase)
    {
        Directory.CreateDirectory(Path.Combine(dir, "run"));
        ApplyDirectoryPermissions(dir);
        ApplyDirectoryPermissions(Path.Combine(dir, "run"));

        var vault = new Vault(dir);
        var dek = Crypto.RandomBytes(Crypto.DekSize);
        using var rsa = Crypto.GenerateIdentity();

        vault.Data = new VaultFile
        {
            Identity = new VaultIdentity { PublicKey = Convert.ToBase64String(Crypto.ExportPublicKey(rsa)) },
            WrappedDek = new WrappedKey { Ct = Convert.ToBase64String(Crypto.WrapDek(rsa, dek)) },
        };
        vault._dek = dek;
        var pk = Crypto.ExportPrivateKey(rsa);
        vault._privateKey = Crypto.ImportPrivateKey(pk);
        pk.AsSpan().Clear();
        vault.SaveMasterKey(passphrase);
        vault.Save();
        vault.SaveConfig(new PwHideConfig());
        return vault;
    }

    public static Vault Open(string dir)
    {
        if (!Exists(dir))
            throw new VaultException($"未找到 vault（{Path.Combine(dir, "vault.json")}）。请先运行 pwhide init");
        var vault = new Vault(dir);
        vault.Data = LoadJson<VaultFile>(vault.VaultPath) ?? throw new VaultException("vault.json 解析失败，文件可能损坏");
        vault.Config = LoadJson<PwHideConfig>(vault.ConfigPath) ?? new PwHideConfig();
        vault.Config.TimeoutSeconds = Math.Clamp(vault.Config.TimeoutSeconds, 1, 86_400);
        // config.json 用户可写：DefaultShell 必须白名单化，否则同 UID 攻击者可写入任意可执行路径，
        // 使下一次 exec 把解密后的密码交给它。任意路径只能经用户亲自输入的 --shell 指定。
        if (vault.Config.DefaultShell is not ("auto" or "bash" or "sh" or "pwsh" or "cmd" or "none"))
            vault.Config.DefaultShell = "auto";
        return vault;
    }

    /// <summary>加载口令、解密私钥、解包裹 DEK。list/inspect 等纯元数据操作无需调用。</summary>
    public void Unlock(string passphrase)
    {
        var master = LoadJson<MasterKeyFile>(MasterKeyPath) ?? throw new VaultException("master.key 解析失败，文件可能损坏");
        var key = Crypto.DeriveKey(passphrase, Convert.FromBase64String(master.Kdf.Salt), master.Kdf.Iterations);
        try
        {
            var privBytes = Crypto.Unseal(key, new SealedBox(master.Nonce, master.Ct), Encoding.UTF8.GetBytes("pwhide/master.key"));
            _dek?.AsSpan().Clear();
            _privateKey?.Dispose();
            _privateKey = Crypto.ImportPrivateKey(privBytes);
            privBytes.AsSpan().Clear();
        }
        finally
        {
            key.AsSpan().Clear();   // 异常路径也必须清除派生密钥
        }
        try
        {
            _dek = Crypto.UnwrapDek(_privateKey, Convert.FromBase64String(Data.WrappedDek.Ct));
        }
        catch (VaultException e)
        {
            throw new VaultException(e.Message + "；若刚执行过被中断的 rotate（master.key 与 vault.json 失配），可用 run/rotate-backup.* 恢复原配对后重试");
        }
    }

    public bool Unlocked => _dek is not null;

    public void EnsureUnlocked()
    {
        if (!Unlocked) throw new VaultException("需要主口令解锁 vault（交互输入，或设置 PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE）");
    }

    public VaultEntry? Find(string name) =>
        Data.Entries.FirstOrDefault(e => string.Equals(e.Name, name, StringComparison.Ordinal));

    public VaultEntry GetOrAdd(string name, string? type, string? username, string? tenant)
    {
        ValidateName(name, "条目名");
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        var e = Find(name);
        if (e is null)
        {
            e = new VaultEntry { Name = name, CreatedAt = now };
            Data.Entries.Add(e);
        }
        if (type is not null) e.Type = type;
        if (username is not null) e.Username = username;
        if (tenant is not null) e.Tenant = tenant;
        e.UpdatedAt = now;
        return e;
    }

    public bool Delete(string name)
    {
        var e = Find(name);
        return e is not null && Data.Entries.Remove(e);
    }

    /// <summary>rename 后 AAD 变化，密码与字段需在旧名下解密、新名下重加密。</summary>
    public void Rename(string oldName, string newName)
    {
        ValidateName(newName, "条目名");
        var e = Find(oldName) ?? throw new VaultException($"条目不存在：{oldName}");
        EnsureUnlocked();
        var password = DecryptPassword(e);
        var fields = e.Fields.Select(f => (f.Name, Value: DecryptField(e, f.Name))).ToList();
        e.Name = newName;
        e.UpdatedAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        e.Nonce = ""; e.Ct = "";
        e.Fields = [];
        SetPassword(e, password);
        foreach (var (n, v) in fields) SetField(e, n, v);
    }

    /// <summary>
    /// 更换身份密钥对：重生成 RSA，同一口令重新保存私钥，只重包裹 DEK。
    /// vault.json 与 master.key 是两次独立安装（跨文件无原子性）——安装前先把当前配对备份到
    /// run/rotate-backup.*（用户可写），中断导致新旧失配时可据此恢复（doctor/Unlock 失败时会提示）。
    /// </summary>
    public void Rotate(string passphrase)
    {
        EnsureUnlocked();
        Directory.CreateDirectory(RunDir);
        ApplyDirectoryPermissions(RunDir);
        var backupVault = Path.Combine(RunDir, "rotate-backup.vault.json");
        var backupKey = Path.Combine(RunDir, "rotate-backup.master.key");
        // 原子写：备份中途崩溃不能损坏"当前配对副本"（它是中断恢复的唯一依靠）
        SecureFile.WriteAtomic(backupVault, File.ReadAllBytes(VaultPath));
        SecureFile.WriteAtomic(backupKey, File.ReadAllBytes(MasterKeyPath));
        var dek = _dek!;
        using var rsa = Crypto.GenerateIdentity();
        Data.Identity = new VaultIdentity { PublicKey = Convert.ToBase64String(Crypto.ExportPublicKey(rsa)) };
        Data.WrappedDek = new WrappedKey { Ct = Convert.ToBase64String(Crypto.WrapDek(rsa, dek)) };
        _privateKey?.Dispose();
        var pk = Crypto.ExportPrivateKey(rsa);
        _privateKey = Crypto.ImportPrivateKey(pk);
        pk.AsSpan().Clear();
        SaveMasterKey(passphrase);
        Save();
    }

    public void SetPassword(VaultEntry entry, string password)
    {
        EnsureUnlocked();
        var bytes = Encoding.UTF8.GetBytes(password);
        var box = Crypto.Seal(_dek!, bytes, Aad(entry.Name, PasswordPath));
        bytes.AsSpan().Clear();
        entry.Nonce = box.Nonce;
        entry.Ct = box.Ct;
    }

    public string DecryptPassword(VaultEntry entry)
    {
        EnsureUnlocked();
        if (entry.Nonce.Length == 0 || entry.Ct.Length == 0)
            throw new VaultException($"条目 {entry.Name} 尚未设置密码");
        var pt = Crypto.Unseal(_dek!, new SealedBox(entry.Nonce, entry.Ct), Aad(entry.Name, PasswordPath));
        var result = Encoding.UTF8.GetString(pt);
        pt.AsSpan().Clear();
        return result;
    }

    public void SetField(VaultEntry entry, string fieldName, string value)
    {
        ValidateName(fieldName, "字段名");
        if (fieldName is "user" or "tenant")
            throw new UsageException($"字段名 {fieldName} 为保留字，不能用作自定义字段");
        EnsureUnlocked();
        entry.PlainFields.Remove(fieldName);   // 同名互斥：改为加密存储时移出明文区
        var bytes = Encoding.UTF8.GetBytes(value);
        var box = Crypto.Seal(_dek!, bytes, Aad(entry.Name, FieldPath(fieldName)));
        bytes.AsSpan().Clear();
        var f = entry.Fields.FirstOrDefault(x => x.Name == fieldName);
        if (f is null) { f = new EncryptedField { Name = fieldName }; entry.Fields.Add(f); }
        f.Nonce = box.Nonce;
        f.Ct = box.Ct;
    }

    /// <summary>明文字段：非敏感配置（IP/协议/端口等）。不经加密，list --json 元数据可见，exec 填充无需解锁。</summary>
    public void SetPlainField(VaultEntry entry, string fieldName, string value)
    {
        ValidateName(fieldName, "字段名");
        if (fieldName is "user" or "tenant")
            throw new UsageException($"字段名 {fieldName} 为保留字，不能用作自定义字段");
        entry.Fields.RemoveAll(f => f.Name == fieldName);   // 同名互斥：改为明文时移出加密区
        entry.PlainFields[fieldName] = value;
        entry.UpdatedAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
    }

    public string DecryptField(VaultEntry entry, string fieldName)
    {
        var f = entry.Fields.FirstOrDefault(x => x.Name == fieldName)
            ?? throw new PlaceholderException(Token(entry.Name, fieldName), entry.Name,
                $"条目 {entry.Name} 不存在字段 {fieldName}");
        EnsureUnlocked();
        var pt = Crypto.Unseal(_dek!, new SealedBox(f.Nonce, f.Ct), Aad(entry.Name, FieldPath(fieldName)));
        var result = Encoding.UTF8.GetString(pt);
        pt.AsSpan().Clear();
        return result;
    }

    public const string PasswordPath = "\x01password";
    private static string FieldPath(string field) => "f:" + field;
    private static byte[] Aad(string entry, string path) => Encoding.UTF8.GetBytes($"{entry}|{path}");
    public static string Token(string entry, string? field) =>
        field is null ? $"{{{{{entry}}}}}" : $"{{{{{entry}.{field}}}}}";

    public static void ValidateName(string name, string what)
    {
        if (name.Length == 0 || name.Length > 64 ||
            !char.IsAsciiLetterOrDigit(name[0]) && name[0] != '_' ||
            name.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '_' and not '-'))
            throw new UsageException($"{what} {name} 非法：仅允许字母/数字/下划线/连字符，以字母或数字开头，长度 1-64（'.' 为占位符分隔符，不允许出现在名字中）");
    }

    /// <summary>
    /// 两段式写入（I6）：先在用户可写的 run/staging 落盘密文，再经 SecureFile.InstallStaged
    /// 完成"清保护 → 原子覆盖 → 重新加保护"（需要时自动 sudo 搬运，跨进程只移动密文）。
    /// </summary>
    public void Save()
    {
        EnsureDirectory();
        StageAndInstall("vault.json", VaultPath,
            JsonSerializer.SerializeToUtf8Bytes(Data, PwHideJsonContext.Default.VaultFile));
    }

    private void StageAndInstall(string name, string finalPath, byte[] data)
    {
        Directory.CreateDirectory(StagingDir);
        ApplyDirectoryPermissions(StagingDir);   // 700：默认 umask 下可能 775（组可写）
        var staging = Path.Combine(StagingDir, name + "." + Guid.NewGuid().ToString("N"));
        File.WriteAllBytes(staging, data);
        SecureFile.Restrict(staging);
        SecureFile.InstallStaged(staging, finalPath, Dir);
    }

    public void SaveConfig(PwHideConfig config)
    {
        Config = config;
        SecureFile.WriteAtomic(ConfigPath, JsonSerializer.SerializeToUtf8Bytes(config, PwHideJsonContext.Default.PwHideConfig));
    }

    private void SaveMasterKey(string passphrase)
    {
        if (_privateKey is null) throw new VaultException("内部错误：私钥未加载");
        var salt = Crypto.RandomBytes(Crypto.SaltSize);
        var key = Crypto.DeriveKey(passphrase, salt, Crypto.Pbkdf2Iterations);
        var priv = Crypto.ExportPrivateKey(_privateKey);
        var box = Crypto.Seal(key, priv, Encoding.UTF8.GetBytes("pwhide/master.key"));
        priv.AsSpan().Clear();
        key.AsSpan().Clear();
        var master = new MasterKeyFile { Nonce = box.Nonce, Ct = box.Ct, Kdf = new KdfParams { Salt = Convert.ToBase64String(salt), Iterations = Crypto.Pbkdf2Iterations } };
        StageAndInstall("master.key", MasterKeyPath,
            JsonSerializer.SerializeToUtf8Bytes(master, PwHideJsonContext.Default.MasterKeyFile));
    }

    private void EnsureDirectory()
    {
        Directory.CreateDirectory(Dir);
        Directory.CreateDirectory(RunDir);
        Directory.CreateDirectory(StagingDir);
        ApplyDirectoryPermissions(Dir);
        ApplyDirectoryPermissions(RunDir);
        ApplyDirectoryPermissions(StagingDir);
    }

    private static void ApplyDirectoryPermissions(string dir)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) return;
        // 符号链接拒绝：root 运行（rotate/EnsureDirectory 等）时 chmod 会跟随链接作用于任意目录
        // （Docker 实证可把 /etc 等改成 700）；用户态同样是异常状态，fail-closed
        if (Hardening.IsSymbolicLink(dir))
            throw new VaultException($"目录是符号链接（可能的攻击或残留），拒绝操作：{dir}");
        try
        {
            File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch { /* 非 fatal：doctor 会报告 */ }
    }

    private static T? LoadJson<T>(string path) where T : class
    {
        if (!File.Exists(path)) return null;
        var bytes = File.ReadAllBytes(path);
        if (typeof(T) == typeof(VaultFile)) return JsonSerializer.Deserialize(bytes, PwHideJsonContext.Default.VaultFile) as T;
        if (typeof(T) == typeof(MasterKeyFile)) return JsonSerializer.Deserialize(bytes, PwHideJsonContext.Default.MasterKeyFile) as T;
        if (typeof(T) == typeof(PwHideConfig)) return JsonSerializer.Deserialize(bytes, PwHideJsonContext.Default.PwHideConfig) as T;
        throw new UsageException($"不支持的配置类型 {typeof(T).Name}");
    }

    /// <summary>写操作的进程内互斥锁（跨进程用文件锁文件 run/lock）。</summary>
    public sealed class FileLock : IDisposable
    {
        private readonly FileStream? _fs;
        private readonly Microsoft.Win32.SafeHandles.SafeFileHandle? _handle;
        internal FileLock(FileStream? fs, Microsoft.Win32.SafeHandles.SafeFileHandle? handle)
        { _fs = fs; _handle = handle; }
        public static FileLock Acquire(string dir)
        {
            Directory.CreateDirectory(Path.Combine(dir, "run"));
            var path = Path.Combine(dir, "run", "lock");
            if (Hardening.Unix)
            {
                // Unix：绕开 .NET 的 FileShare/FileAccess→fcntl 锁模拟（两个写者在 open 即冲突、无等待语义）。
                // 裸 open() + 手工限时 flock：互斥完全由 flock 提供，并发写排队而非立即失败。
                var handle = Hardening.OpenLockFile(path);
                try
                {
                    if (!Hardening.FlockExclusive(handle))
                        throw new IOException("lock-wait-timeout");
                    // sudo 运行会把 lock 留在 root 名下——立即归还调用用户，避免后续用户态命令永久 EACCES
                    if (Hardening.IsRoot())
                    {
                        // -h（lchown）：即使窗口内被换成符号链接也只作用于链接本体，绝不转移任意文件属主；
                        // O_NOFOLLOW 已保证我们锁定的不是链接，此处为纵深防御
                        var sudoUser = Hardening.RealSudoUser();
                        if (sudoUser is not null)
                            _ = Hardening.Sh($"chown -h {Hardening.Q(sudoUser)} {Hardening.Q(path)} 2>/dev/null || true");
                    }
                    return new FileLock(null, handle);
                }
                catch (IOException e) when (e.Message == "lock-wait-timeout")
                {
                    handle.Dispose();
                    throw new VaultException("另一个 pwhide 写操作长时间未完成（等待 60s 未能获得锁），请稍后重试");
                }
                catch
                {
                    handle.Dispose();
                    throw;
                }
            }
            // Windows：FileShare.None 即互斥
            FileStream fs;
            try
            {
                fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException)
            {
                throw new VaultException("另一个 pwhide 写操作正在进行（run/lock 被占用）");
            }
            catch (UnauthorizedAccessException)
            {
                throw new VaultException($"run/lock 无法访问（属主异常，多为 sudo 运行遗留）：可删除 {path} 后重试，或再运行一次 sudo 命令由其自动归还属主");
            }
            return new FileLock(fs, null);
        }
        public void Dispose()
        {
            _fs?.Dispose();
            _handle?.Dispose();
        }
    }
}
