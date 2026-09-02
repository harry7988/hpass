using System.Text.Json.Serialization;

namespace PwHide.Core;

public sealed class KdfParams
{
    public string Algo { get; set; } = "PBKDF2-SHA512";
    public int Iterations { get; set; } = 600_000;
    public string Salt { get; set; } = "";
}

public sealed class VaultIdentity
{
    public string Alg { get; set; } = "RSA-OAEP-SHA256";
    public string PublicKey { get; set; } = "";
}

public sealed class WrappedKey
{
    public string Alg { get; set; } = "RSA-OAEP-SHA256";
    public string Ct { get; set; } = "";
}

public sealed class EncryptedField
{
    public string Name { get; set; } = "";
    public string Nonce { get; set; } = "";
    public string Ct { get; set; } = "";
}

public sealed class VaultEntry
{
    public string Name { get; set; } = "";
    public string? Type { get; set; }
    public string? Username { get; set; }
    public string? Tenant { get; set; }
    public List<EncryptedField> Fields { get; set; } = [];
    /// <summary>明文字段（set 时用户自选非敏感信息：IP、协议、端口等）。值在 list --json 元数据中可见，AI 查询/填充均无需解锁。</summary>
    public Dictionary<string, string> PlainFields { get; set; } = [];
    public string CreatedAt { get; set; } = "";
    public string UpdatedAt { get; set; } = "";
    /// <summary>主密码密文（AES-256-GCM，AAD 绑定条目名）。</summary>
    public string Nonce { get; set; } = "";
    public string Ct { get; set; } = "";
}

public sealed class VaultFile
{
    public int Version { get; set; } = 1;
    public VaultIdentity Identity { get; set; } = new();
    public WrappedKey WrappedDek { get; set; } = new();
    public List<VaultEntry> Entries { get; set; } = [];
}

/// <summary>master.key：RSA 私钥经口令派生密钥 AES-256-GCM 加密。</summary>
public sealed class MasterKeyFile
{
    public KdfParams Kdf { get; set; } = new();
    public string Alg { get; set; } = "AES-256-GCM";
    public string Nonce { get; set; } = "";
    public string Ct { get; set; } = "";
}

public sealed class PwHideConfig
{
    public string DefaultShell { get; set; } = "auto";
    public int TimeoutSeconds { get; set; } = 120;
}

/// <summary>list --json / inspect --json 的条目元数据（不含任何密文值；明文字段值按设计可见）。</summary>
public sealed class EntryMeta
{
    public string Name { get; set; } = "";
    public string? Type { get; set; }
    public string? Username { get; set; }
    public string? Tenant { get; set; }
    public bool HasPassword { get; set; }
    public List<string> Fields { get; set; } = [];
    /// <summary>明文字段名→值（用户录入时自选非敏感信息；AI 可直接读取组装命令）。</summary>
    public Dictionary<string, string> PlainFields { get; set; } = [];
    public List<string> Placeholders { get; set; } = [];
    public string UpdatedAt { get; set; } = "";
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(VaultFile))]
[JsonSerializable(typeof(MasterKeyFile))]
[JsonSerializable(typeof(PwHideConfig))]
[JsonSerializable(typeof(List<EntryMeta>))]
[JsonSerializable(typeof(EntryMeta))]
public sealed partial class PwHideJsonContext : JsonSerializerContext { }
