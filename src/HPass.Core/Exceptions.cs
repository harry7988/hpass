namespace HPass.Core;

/// <summary>用法错误（退出码 2）。</summary>
public sealed class UsageException : Exception
{
    public UsageException(string message) : base(message) { }
}

/// <summary>vault / 密钥 / 口令错误（退出码 3）。</summary>
public sealed class VaultException : Exception
{
    public VaultException(string message) : base(message) { }
}

/// <summary>未知条目或字段（退出码 4）。消息中只允许出现条目名，绝不含密文。</summary>
public sealed class PlaceholderException : Exception
{
    public string EntryName { get; }
    public string Token { get; }

    public PlaceholderException(string token, string entryName, string message)
        : base(message)
    {
        Token = token;
        EntryName = entryName;
    }
}

public static class ExitCodes
{
    public const int Ok = 0;
    public const int Usage = 2;
    public const int Vault = 3;
    public const int UnknownPlaceholder = 4;
    public const int Timeout = 124;
}
