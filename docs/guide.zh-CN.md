> 中文指南 | English: [guide.en.md](guide.en.md)

> **提示**：pwhide 界面默认英文。跟着本中文指南操作前，建议先执行 `pwhide language zh`（或 `export PWHIDE_LANG=zh`），命令提示就是中文了。
# pwhide 图文指南：从零到 AI 日常使用

## 它解决什么问题

让 AI（Claude Code / Cursor / 任何 Agent）执行带密码的命令时，密码不再进入对话、日志或历史记录。

![工作原理](images/workflow.png)

三步之后，AI 的世界里只剩 `{{占位符}}` 和脱敏后的输出。密码本身被 AES-256-GCM + RSA-3072 信封加密存在本地 `~/.pwhide/`，主口令可以存进系统钥匙串。

## 五分钟上手

![快速上手会话](images/quickstart.png)

| 步骤 | 命令 | 说明 |
|---|---|---|
| ① 初始化 | `pwhide init` → `pwhide harden` | 设置主口令；harden 后 vault 只能整体覆盖 |
| ② 免交互（推荐） | `pwhide keychain set` | 主口令存系统钥匙串，之后所有命令零交互 |
| ③ 录入凭据 | `pwhide set prod-db -t database -u root` | 密码隐藏输入；字段逐个询问是否加密（IP/协议选明文 n，api_key 选 y） |
| ④ AI 使用 | `pwhide list --json` + `pwhide exec -- 命令…` | AI 查元数据组装命令，写 `{{prod-db}}` 占位 |

**AI 侧配置**（一次即可）：把 `pwhide list --json` 的可见性契约和占位符规则写进项目的 `AGENTS.md`，或安装仓库内置 Skill：`skills/pwhide/install.sh`。

## 三种执行模式（安全性递增）

1. **脚本 stdin（推荐）**：`pwhide exec -f deploy.sh` —— 脚本里写占位符，替换只在内存发生，密码不进 argv 也不进环境变量；
2. **环境变量注入**：`pwhide exec --env prod-db:MYSQL_PWD -- mysql …` —— argv 干净（Linux 上祖先进程可读 /proc）；
3. **args 内联**：`pwhide exec -- mysql -p{{prod-db}}` —— 最直观，但 `ps` 短暂可见。

## 人工核验：确认存的密码是对的

![verify 人工核验通道](images/verify-channel.png)

`pwhide verify 条目` 强制你在终端手输主口令（钥匙串/环境变量统统无效），然后解密显示供你本人核对。`pwhide exec --verify` 在执行前展示解密后的注入值和完整命令，确认后才运行。该通道**只在真实交互终端可用**——被重定向或被 AI 调用时直接拒绝，这是防止密文进入 AI 上下文的硬性设计。

## Windows 编码：为什么会乱码，现在怎么解决

![Windows 编码修复前后](images/windows-encoding.png)

**为什么一直出问题**：Windows 控制台的编码是"多层历史叠加"——

1. **cmd 的代码页是 DOS 时代的 OEM**（简体中文 = cp936/GBK），不是 UTF-8；
2. **一台机器上有三套解码器**：cmd 用 OEM、PowerShell 5.1 管道用 `[Console]::OutputEncoding`（默认也是 OEM）、PowerShell 7 默认 UTF-8；
3. **输出一旦被管道/重定向，规则全变**：子进程的原始字节直接交给消费者，用哪个解码器取决于调用方——同一个程序，在 cmd 里好、到 PowerShell 管道里就乱；
4. 旧版 pwhide 管道恒定输出 UTF-8：被 GBK 逐字节误读就成了 `鏈?鎵惧埌 vault锛圕:...`，被 PowerShell 的 Unicode 会话按 UTF-16 两两成对误读就成了 `pwhide: 睰楨敤›鳦...`（下面对比图里的乱码均由真实二进制输出反算）。

**0.7+ 的自动适配**：真控制台 → `WriteConsoleW` 直写（与代码页无关）；管道 → 按会话控制台代码页转码；文件重定向 → UTF-8。

**兜底**（自动检测仍不对时，全局手工指定一次即可）：

```powershell
pwhide doctor                        # 先看诊断：当前通道/代码页/覆盖来源
pwhide doctor --output-encoding gbk  # 或 utf8 / utf16 / json（纯 ASCII 永不乱码）
# 环境变量方式：$env:PWHIDE_OUTPUT_ENCODING = "gbk"
```

下图为字节级验证报告：全部场景由真实二进制产出、按 Windows 各解码器精确还原。

![编码验证报告](images/encoding-proof.png)

验证脚本随仓库提供：`python3 scripts/encoding-visual-proof.py <pwhide二进制>`（退出码 0 = 全场景字节级还原正确）。

## 速查

- 未知占位符（退出码 4）：`pwhide list` 核对条目名；不存在就本人 `pwhide set`；
- 口令相关（退出码 3）：`pwhide keychain set` 或 `PWHIDE_PASSPHRASE_FILE`；
- 与 Helm/Jinja 模板冲突：`exec --ph '#'`，占位符写 `#db#`；
- 回显探测口径：echo/printf 与密文占位符（或 `--env` 注入）共现即拦截，`--allow-echo` 放行；
- 超时 124：加 `--timeout`；
- 环境自检：`pwhide doctor`。
