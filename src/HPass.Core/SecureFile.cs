using System.Text;

namespace HPass.Core;

/// <summary>
/// 原子安全写入：临时文件 → fsync → rename 覆盖 → 收紧权限。
/// 不变式 I6：vault 变更只走整体覆盖路径，永不就地修改。
/// </summary>
public static class SecureFile
{
    public static void WriteAtomic(string path, byte[] data)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
        var tmp = Path.Combine(dir, "." + Path.GetFileName(path) + ".tmp-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(data);
                fs.Flush(flushToDisk: true);
            }
            Restrict(tmp);
            File.Move(tmp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    /// <summary>Unix 0600 / Windows 仅当前用户 ACL（通过目录继承实现，额外显式收紧文件 DACL）。</summary>
    public static void Restrict(string path)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch { }
        }
    }
}
