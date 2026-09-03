#!/usr/bin/env python3
"""pty 回归测试：验证口令隐藏输入不再回显（.NET 10 行编辑器绕过 + /dev/tty termios 方案）。
用法：python3 scripts/verify-hidden-input.py <pwhide二进制或dll>
退出码 0 = 全部通过。"""
import os, pty, select, time, tempfile, subprocess, shutil, sys

if len(sys.argv) < 2:
    print("usage: verify-hidden-input.py <pwhide-binary>"); sys.exit(2)
BIN = sys.argv[1]
HOME = tempfile.mkdtemp(prefix="pwhide-hiddenin-")
ok = True

def exited(pid):
    try:
        wpid, _ = os.waitpid(pid, os.WNOHANG)
        return wpid == pid
    except ChildProcessError:
        return True

def wrote_ok(b): return (b"saved" in b) or ("已保存".encode() in b)

try:
    subprocess.run(["dotnet", BIN, "--home", HOME, "init", "--no-harden"], input=b"x-pass-99\nx-pass-99\n",
                   capture_output=True, env={**os.environ, "PWHIDE_HOME": HOME, "PWHIDE_PASSPHRASE": "x-pass-99"})
    pid, master = pty.fork()
    if pid == 0:
        env = {**os.environ, "PWHIDE_HOME": HOME, "PWHIDE_PASSPHRASE": "x-pass-99"}
        os.execvpe("dotnet", ["dotnet", BIN, "--home", HOME, "set", "svc"], env)
        os._exit(127)
    out = b""
    deadline = time.time() + 25
    prompted = False
    while time.time() < deadline and not exited(pid):
        r, _, _ = select.select([master], [], [], 0.3)
        if r:
            try:
                d = os.read(master, 4096)
                if not d: break
                out += d
            except OSError: break
        if not prompted and (b"password" in out.lower() or "密码".encode() in out):
            prompted = True
            time.sleep(0.05)   # 快手输入：原回显竞态场景
            os.write(master, b"my-secret-pw-77\n")
            time.sleep(0.2)
            os.write(master, b"my-secret-pw-77\n")
        if prompted and wrote_ok(out):
            break
    while not exited(pid) and time.time() < deadline + 3:
        r, _, _ = select.select([master], [], [], 0.3)
        if r:
            try:
                d = os.read(master, 4096)
                if not d: break
                out += d
            except OSError: break
        else: break
    os.close(master)
    text = out.decode(errors="replace")
    leak = "my-secret-pw-77" in text
    saved = wrote_ok(out)
    stars = "*" in text
    print("1. 口令回显泄漏:", leak, "(应 False)")
    print("2. set 成功:", saved, "(应 True)")
    print("3. 星号回显:", stars, "(应 True)")
    ok = ok and (not leak) and saved and stars
    r = subprocess.run(["dotnet", BIN, "--home", HOME, "exec", "--allow-echo", "--", "/bin/echo", "{{svc}}"],
                       capture_output=True, env={**os.environ, "PWHIDE_HOME": HOME, "PWHIDE_PASSPHRASE": "x-pass-99"})  # exec 用主口令解锁，条目密码由 pwhide 注入
    usable = "{{svc}}" in r.stdout.decode()
    print("4. 条目密码真实可用:", usable, "(应 True)")
    ok = ok and usable
finally:
    shutil.rmtree(HOME, ignore_errors=True)
sys.exit(0 if ok else 1)
