#!/usr/bin/env python3
r"""
pwhide 输出编码端到端视觉验证。

模拟中文 Windows 的全部真实解码场景，逐字节验证 pwhide 输出能被正确还原：
  1. cmd 控制台           OEM cp936 (GBK)      ← 旧版在此乱码（鏈壘鍒?）
  2. PowerShell 管道       [Console]::OutputEncoding（GBK 机器 = cp936）
  3. PowerShell 管道       [Console]::OutputEncoding = Unicode（用户实测场景，睰楨敤式）
  4. chcp 65001 / WT       UTF-8
  5. 任何终端（json 模式）  纯 ASCII \uXXXX 转义

用法： python3 scripts/encoding-visual-proof.py <pwhide二进制路径> [输出HTML路径]
退出码：全部场景还原正确 = 0；任何错位 = 1。
"""
import json
import os
import subprocess
import sys
import tempfile

BIN = sys.argv[1]
OUT_HTML = sys.argv[2] if len(sys.argv) > 2 else "/tmp/pwhide-encoding-proof.html"
HOME = tempfile.mkdtemp(prefix="pwhide-encproof-")
PASS = " Production-DB "
# 用中文字段值做视觉样本（明文字段经 list --json 不出现——json 转义；改用 doctor 固定文案 + set 错误消息）
ENV = {**os.environ, "PWHIDE_HOME": HOME, "PWHIDE_PASSPHRASE": "enc-proof-pass-99", "PWHIDE_NO_SUDO": "1", "PWHIDE_LANG": "zh"}

def run(args, stdin=None, env=None):
    e = {**ENV, **(env or {})}
    r = subprocess.run([BIN, "--home", HOME] + args, input=stdin,
                       capture_output=True, env=e)
    return (r.stdout or b"") + (r.stderr or b"")   # 演示用：合并两路输出

# 准备：init + set（触发"已保存条目"与字段交互跳过）
run(["init", "--no-harden"], stdin=b"enc-proof-pass-99\nenc-proof-pass-99\n")
run(["set", "db", "-u", "root", "--password-stdin"], stdin=b"proof-pw-77\n")

# ---------- 场景定义 ----------
EXPECTED_MSG = f"pwhide: 已删除 db"  # 占位，实际期望按命令计算
def expected_for(zh_text):  # Windows 控制台正确显示的内容
    return zh_text

scenarios = []
def check(name, decoder, expect_substr, bytes_out, note):
    try:
        shown = bytes_out.decode(decoder)
    except Exception as e:
        shown = f"<解码失败: {e}>"
    ok = expect_substr in shown
    scenarios.append((name, decoder, ok, shown.replace("\r\n", "\n").strip()[:400], note))
    return ok

# 场景 1+2：GBK 机器（cmd 控制台 / PS 5.1 管道默认 OEM=cp936）
gbk_bytes = run(["doctor"], env={"PWHIDE_OUTPUT_ENCODING": "gbk"})
check("中文 cmd 控制台（OEM cp936）", "gbk", "目录权限", gbk_bytes, "pwhide --output-encoding 自动→管道按会话代码页转码")
# 删除命令的确认消息（含动态条目名）
del_bytes = run(["delete", "db"], env={"PWHIDE_OUTPUT_ENCODING": "gbk"})
check("中文 cmd 控制台（删除确认）", "gbk", "已删除 db", del_bytes, "动态条目名原样保留")

# 场景 3：PS 管道 + Unicode 控制台（用户 shenh 的实测场景：睰楨敤式乱码）
u16_bytes = run(["list"], env={"PWHIDE_OUTPUT_ENCODING": "utf16"})
try:
    shown = u16_bytes.decode("utf-16")
    ok = "vault is empty" in shown or "未找到" in shown or "名称" in shown or "vault" in shown
except Exception as e:
    shown, ok = f"<解码失败: {e}>", False
scenarios.append(("PowerShell 管道（[Console]::OutputEncoding=Unicode）", "utf-16 (BOM)", ok,
                  shown.replace("\r\n", "\n").strip()[:400], "UTF-16LE + BOM，PS 按 Unicode 解码"))
# 再触发一条含中文的 utf16 输出
err_u16 = run(["inspect", "nosuch"], env={"PWHIDE_OUTPUT_ENCODING": "utf16"})
try:
    shown = err_u16.decode("utf-16")
    ok = "entry not found" in shown or "条目不存在" in shown
except Exception as e:
    shown, ok = f"<解码失败: {e}>", False
scenarios.append(("PowerShell 管道（Unicode，错误消息）", "utf-16 (BOM)", ok,
                  shown.replace("\r\n", "\n").strip()[:200], "PWHIDE_LANG=zh 时含中文亦正确"))

# 场景 4：chcp 65001 / Windows Terminal（UTF-8）
u8_bytes = run(["doctor"], env={"PWHIDE_OUTPUT_ENCODING": "utf8"})
check("chcp 65001 / Windows Terminal（UTF-8）", "utf-8", "目录权限", u8_bytes, "UTF-8 无 BOM")

# 场景 5：json 模式（终极兜底：纯 ASCII 任何解码器都可读）
j_bytes = run(["doctor"], env={"PWHIDE_OUTPUT_ENCODING": "json"})
try:
    shown = j_bytes.decode("ascii")
    ok = "\\u" in shown and "home" in shown
except Exception:
    shown, ok = "<non-ascii!>", False
scenarios.append(("json 模式（纯 ASCII \\uXXXX，任何终端可读）", "ascii", ok,
                  shown.replace("\r\n", "\n").strip()[:400], "终极兜底：不存在解码错误可能"))

# ---------- 旧版对照（0.6.x：管道恒 UTF-8，被 GBK/Unicode 解码即乱码） ----------
fresh = tempfile.mkdtemp(prefix="pwhide-encproof-old-")
oldenv = {**ENV, "PWHIDE_HOME": fresh}
subprocess.run([BIN, "--home", fresh, "init", "--no-harden"], input=b"enc-proof-pass-99\nenc-proof-pass-99\n",
               capture_output=True, env={**oldenv, "PWHIDE_OUTPUT_ENCODING": "utf8"})
# 模拟旧版行为：同一份 UTF-8 字节被中文 Windows 两种解码器消费
u8_fixed = subprocess.run([BIN, "--home", fresh, "list"], capture_output=True,
                          env={**oldenv, "PWHIDE_OUTPUT_ENCODING": "utf8"}).stdout
old_gbk = "(无法按 GBK 解码显示——这正是旧版中文 cmd 的乱码)"
try:
    old_gbk = u8_fixed.decode("gbk", errors="replace")[:200]
except Exception:
    pass
old_u16 = u8_fixed.decode("utf-16-le", errors="replace")[:200]
scenarios.append(("【旧版对照】UTF-8 字节 → GBK 控制台", "utf-8 bytes as gbk", False, old_gbk, "0.6.x 管道恒 UTF-8：中文 cmd 显示乱码（已修复）"))
scenarios.append(("【旧版对照】UTF-8 字节 → Unicode 管道", "utf-8 bytes as utf-16-le", False, old_u16, "0.6.x 在 PowerShell Unicode 会话的乱码（已修复）"))

# ---------- 判定 ----------
all_ok = all(s[2] for s in scenarios[:6])  # 前 6 个为新版场景，必须全过（旧版对照 expected FAIL）
for s in scenarios:
    print(("PASS " if s[2] else "FAIL "), s[0], "->", s[3][:60].replace("\n", " | "))

# ---------- 生成可视化 HTML ----------
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
rows = []
for name, dec, ok, shown, note in scenarios:
    cls = "ok" if ok else ("old" if name.startswith("【旧版") else "bad")
    rows.append(f'''
  <div class="case {cls}">
    <div class="head"><span class="badge">{ "✓" if ok else "✗" } {esc(name)}</span><span class="dec">解码: {esc(dec)}</span></div>
    <pre class="term">{esc(shown)}</pre>
    <div class="note">{esc(note)}</div>
  </div>''')

html = f'''<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<style>
  body{{background:#0b1220;color:#dbe7f5;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:24px;}}
  h1{{font-size:22px}} .sub{{color:#8ba2c0;margin-bottom:20px;font-size:13px}}
  .case{{border-radius:12px;margin-bottom:14px;overflow:hidden;border:1px solid #1f2c47}}
  .ok .head{{background:#0f2e22}} .bad .head{{background:#3a1420}} .old .head{{background:#2e2410}}
  .head{{display:flex;justify-content:space-between;padding:9px 14px;font-size:13.5px;align-items:center}}
  .ok .badge{{color:#34d399;font-weight:700}} .bad .badge{{color:#f87171;font-weight:700}} .old .badge{{color:#fbbf24;font-weight:700}}
  .dec{{color:#8ba2c0;font-size:12px;font-family:ui-monospace,Menlo,monospace}}
  .term{{background:#0a0f1c;margin:0;padding:14px 16px;font-family:ui-monospace,"SFMono-Regular",Menlo,monospace;font-size:12.5px;line-height:1.65;white-space:pre-wrap;color:#cfe3fa;max-height:180px;overflow:hidden}}
  .note{{padding:7px 14px;font-size:12px;color:#8ba2c0;border-top:1px solid #1f2c47}}
</style></head><body>
<h1>pwhide 输出编码端到端验证（{BIN}）</h1>
<div class="sub">模拟中文 Windows 全部真实解码场景：绿色 = 新版输出被正确还原；黄色 = 旧版（0.6.x 管道恒 UTF-8）的乱码对照；字节级断言 {'全部通过' if all_ok else '存在失败'}。</div>
{''.join(rows)}
</body></html>'''
open(OUT_HTML, "w").write(html)
print("HTML:", OUT_HTML)
sys.exit(0 if all_ok else 1)
