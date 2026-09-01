namespace PwHide.Core;

/// <summary>用法错误（退出码 2）。</summary>
public sealed class UsageException : Exception
{
    public UsageException(string message) : base(message) { }
}

/// <summary>vault / 密钥 / 口令错误（退出码 3）。</summary>
public class VaultException : Exception
{
    public VaultException(string message) : base(message) { }
}

/// <summary>
/// 目标文件处于管理员写保护（root 属主 + schg/+i），用户态无法完成安装（I6）。
/// 暂存文件只含密文，可安全交给 sudo 搬运。
/// </summary>
public sealed class NeedsElevationException : VaultException
{
    public string StagingPath { get; }
    public string FinalPath { get; }

    public NeedsElevationException(string stagingPath, string finalPath, string message)
        : base(message)
    {
        StagingPath = stagingPath;
        FinalPath = finalPath;
    }
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
