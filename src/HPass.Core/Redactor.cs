using System.Text;

namespace HPass.Core;

/// <summary>
/// 流式脱敏器（不变式 I3，最终防线）：把输出流中出现的本次使用的密文替换回占位符 token。
/// 处理跨缓冲区边界：每次保留可能被截断的尾部字节（maxSecretLen-1）到下一块。
/// </summary>
public sealed class StreamRedactor
{
    private readonly (byte[] Secret, byte[] Token)[] _rules;
    private readonly int _maxSecretLen;
    private byte[] _carry = [];
    private readonly int[] _counts;

    public StreamRedactor(IReadOnlyDictionary<string, string> secretToToken)
    {
        // 空 secret 必须过滤：IndexOf 对空 needle 恒命中 0，会让 Process 死循环并无限写 token（OOM）
        _rules = secretToToken
            .Where(kv => kv.Key.Length > 0)
            .Select(kv => (Encoding.UTF8.GetBytes(kv.Key), Encoding.UTF8.GetBytes(kv.Value)))
            .OrderByDescending(r => r.Item1.Length)
            .ToArray();
        _counts = new int[_rules.Length];
        _maxSecretLen = _rules.Length == 0 ? 0 : _rules.Max(r => r.Secret.Length);
    }

    public bool HasRules => _rules.Length > 0;

    /// <summary>各占位符的累计替换次数（用于高频碰撞检测）。</summary>
    public IReadOnlyDictionary<string, int> ReplacementCounts
    {
        get
        {
            var d = new Dictionary<string, int>();
            for (var i = 0; i < _rules.Length; i++)
                d[Encoding.UTF8.GetString(_rules[i].Token)] = _counts[i];
            return d;
        }
    }

    /// <summary>处理一块数据，返回可安全外发的字节。</summary>
    public byte[] Process(ReadOnlySpan<byte> chunk)
    {
        if (!HasRules) return chunk.ToArray();

        var buf = new byte[_carry.Length + chunk.Length];
        _carry.AsSpan().CopyTo(buf);
        chunk.CopyTo(buf.AsSpan(_carry.Length));

        var emitted = new MemoryStream(buf.Length);
        int pos = 0;
        while (pos < buf.Length)
        {
            int bestIdx = -1, bestRule = -1;
            for (var i = 0; i < _rules.Length; i++)
            {
                var idx = buf.AsSpan(pos).IndexOf(_rules[i].Secret);
                if (idx < 0) continue;
                if (bestIdx < 0 || pos + idx < bestIdx || (pos + idx == bestIdx && _rules[i].Secret.Length > _rules[bestRule].Secret.Length))
                {
                    bestIdx = pos + idx;
                    bestRule = i;
                }
            }
            if (bestRule < 0) break;
            var rule = _rules[bestRule];
            emitted.Write(buf.AsSpan(pos, bestIdx - pos));
            emitted.Write(rule.Token);
            _counts[bestRule]++;
            pos = bestIdx + rule.Secret.Length;
        }

        var keep = Math.Min(Math.Max(_maxSecretLen - 1, 0), buf.Length - pos);
        emitted.Write(buf.AsSpan(pos, buf.Length - pos - keep));
        _carry = buf.AsSpan(buf.Length - keep).ToArray();
        return emitted.ToArray();
    }

    /// <summary>流结束：冲掉残余 carry（不再可能构成完整 secret）。</summary>
    public byte[] Flush()
    {
        var rest = _carry;
        _carry = [];
        return rest;
    }
}
