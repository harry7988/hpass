using System.Text;
using PwHide.Core;

namespace PwHide.Cli;

/// <summary>
/// 输出边界的本地化写入器：en 模式下把 pwhide 自身消息按行翻译为英文（Loc.Tr：精确表 → 通配模板 → 原样）。
/// zh 模式或无 CJK 时零开销直通。子进程输出不经此类（exec 字节流直挂原始 Stream，永不翻译用户程序输出）。
/// 多行文本按行拆分翻译（usage 块逐行命中表项）。
/// </summary>
public sealed class LocalizingWriter(TextWriter inner) : TextWriter
{
    public override Encoding Encoding => inner.Encoding;

    public override void Write(char value) => inner.Write(Loc.Tr(value.ToString()));

    public override void Write(string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        WriteLines(value);
    }

    public override void Write(char[] buffer, int index, int count) =>
        WriteLines(new string(buffer, index, count));

    public override void WriteLine(string? value)
    {
        if (string.IsNullOrEmpty(value)) { inner.WriteLine(); return; }
        WriteLines(value, newline: true);
    }

    private void WriteLines(string s, bool newline = false)
    {
        var parts = s.Split('\n');
        for (var i = 0; i < parts.Length; i++)
        {
            if (i > 0) inner.Write('\n');
            // 只裁属于 \r\n 拆分产生的 \r；行内容自身的 \r（如 --verify 显示的秘密尾字符）原样保留
            var line = parts[i];
            var stripCr = i < parts.Length - 1 && line.EndsWith('\r');
            inner.Write(Loc.Tr(stripCr ? line[..^1] : line));
        }
        if (newline) inner.Write(NewLine);
    }

    public override void Flush() => inner.Flush();
}
