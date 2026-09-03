# pwhide AI 部署与使用指南

> English edition: [ai-deploy-guide.en.md](ai-deploy-guide.en.md)

本文档面向 AI 编程工具（Claude Code、Cursor 及其他 Agent）。你的任务分两类：

1. **部署**：按 §1 的 runbook 为用户安装、初始化并验证 pwhide；
2. **日常使用**：通过查询接口（§3）了解可用凭据，通过执行接口（§4）代理执行含密码的命令 —— 全程不接触任何真实密码。

> 注意：pwhide 处于开发中，本指南描述的是 v1 目标行为（见 [PLAN.md](../PLAN.md)）。若命令不存在或行为不符，请提示用户当前版本尚未实现该里程碑，不要臆造替代方案。

---

## 0. 铁律（先读）

1. **永远不要**向用户索要、记录、输出或以任何形式处理真实密码。录入密码是用户本人的交互（`pwhide set` 隐藏输入），你不要旁观、代输或要求用户粘贴到对话里。
2. 密码与自定义字段值**没有任何查询接口**。`pwhide list` / `pwhide inspect` 只返回元数据（类型、账号、租户、字段名）。
3. 命令中需要密文的位置一律写**占位符**：`{{条目名}}`（密码）、`{{条目名.user}}`、`{{条目名.tenant}}`、`{{条目名.<字段名>}}`。
4. 执行结果中出现的 `{{条目名}}` 是 pwhide 的**脱敏标记**（原位置是真实密码），属正常现象，不要尝试"还原"它。
5. 优先使用更安全的模式：**脚本 stdin > 环境变量注入 > args 内联**（Linux 上祖先进程可经 /proc/<pid>/environ 读到
   注入的环境密文，脚本 stdin 是唯一同时避开 argv 与 environ 的模式；见 §4 与 threat-model）。
6. **不要构造回显占位符的命令**（`echo {{名}}` 等会被拒绝——回显密码没有正常用途，且可被用于推测密码）；不要尝试以任何方式推测密码内容。
7. 录入时弱密码（常见口令/常见语句）会被拒绝，引导用户设置强密码（长度 ≥8、混合字符、非常见语句）。

---

## 1. 部署 runbook

### 1.1 识别平台

```bash
uname -s && uname -m      # Darwin arm64 → osx-arm64；Linux x86_64 → linux-x64 …
```

Windows 下用 `pwsh`：`$env:PROCESSOR_ARCHITECTURE` 判断 x64/arm64。

### 1.2 获取二进制

**方式 A：GitHub Release（推荐，发布后可用）**

```bash
# 1) 下载对应 RID 的压缩包（版本 v 为最新 release）
curl -LO https://github.com/harry7988/pwhide/releases/latest/download/pwhide-<rid>.tar.gz
# 2) 校验（必须）
curl -LO https://github.com/harry7988/pwhide/releases/latest/download/SHA256SUMS
shasum -a 256 --check SHA256SUMS --ignore-missing
# 3) 解压
tar xzf pwhide-<rid>.tar.gz
```

**方式 B：源码构建（需 .NET 10 SDK）**

```bash
git clone git@github.com:harry7988/pwhide.git && cd pwhide
dotnet publish src/PwHide.Cli -c Release -r <rid> /p:PublishAot=true -o publish
# 产物为 publish/pwhide（Windows 为 pwhide.exe）
```

### 1.3 安装到 PATH

- Unix：`/usr/local/bin/pwhide`（需 sudo）或 `~/.local/bin/pwhide`（确认在 PATH 内）。
- Windows：`%LOCALAPPDATA%\Programs\pwhide\pwhide.exe` 并将该目录加入用户 PATH。

验证：`pwhide version`。

### 1.4 初始化

引导用户**本人**执行（你来运行命令、用户来输密码）：

```
pwhide init
```

- 会让用户设置并确认**主口令**（用于加密私钥）。提醒用户：口令丢失则所有密码不可恢复，没有后门。
- init 生成基础模式（目录 700 / 文件 600）；管理员级写保护需另行执行 `pwhide harden`（请求 sudo/UAC，属正常且建议执行）。

### 1.5 验证

```
pwhide doctor
```

确认输出中：shell 探测正常、vault 权限/加固状态正常、无中断待恢复项。

### 1.6 录入首批凭据

由用户本人运行（主密码为隐藏输入；非敏感配置字段用 `-f 字段=值` 传入，**敏感字段值**（api_key/token 等）请用交互隐藏输入 `-f 字段名`——命令行传值会进 shell history，pwhide 也会告警）：

```bash
pwhide set db-local -t database -u root -T prod -f host=127.0.0.1 -f port=3306
```

录入后你可以用 `pwhide inspect db-local` 向用户展示元数据确认无误。

### 1.7 冒烟测试

用无害命令验证占位符填充与脱敏链路：

```bash
# 注意：直接回显占位符属探测行为，默认被拒绝；人工验证脱敏需显式 --allow-echo
pwhide exec --allow-echo -- echo "password is {{db-local}}"
# 期望输出：password is {{db-local}}   ← 已被脱敏
```

---

## 2. 条目数据模型

| 字段 | 可见性 | 说明 |
|---|---|---|
| `name` | 明文 | 条目名，占位符引用的主键 |
| `type` | 明文 | 账号类型：database / ssh / api / cloud / 任意自定义字符串 |
| `username` | 明文 | 账号 |
| `tenant` | 明文 | 租户 / 环境标识（如 prod、tenant-a） |
| password | **加密** | 密码，占位符 `{{name}}` |
| `fields` | 名明文、**值加密** | 自定义字段（host、api_key、token…），占位符 `{{name.<字段名>}}` |

设计意图：类型/账号/租户/字段名这类**组装命令所需的非敏感信息**可查；密码与字段值这类**敏感信息**只能经占位符注入子进程。

## 3. 查询接口

```bash
pwhide list            # 人类可读表格
pwhide list --json     # 机器可读（推荐 AI 使用）
pwhide inspect <name>  # 单条目详情 + 可用占位符清单
```

`pwhide list --json` 输出示例：

```json
[
  {
    "name": "db-local",
    "type": "database",
    "username": "root",
    "tenant": "prod",
    "hasPassword": true,
    "fields": ["host", "api_key"],
    "placeholders": ["{{db-local}}", "{{db-local.user}}", "{{db-local.tenant}}", "{{db-local.host}}", "{{db-local.api_key}}"],
    "updatedAt": "2026-09-01T00:00:00Z"
  }
]
```

## 4. 执行接口

按安全性从高到低（与 threat-model §5.9 一致：脚本 stdin 唯一同时避开 argv 与 /proc/<pid>/environ）：

```bash
# ① 脚本 stdin 模式（推荐：唯一同时避开 argv 与 /proc/<pid>/environ 的模式）
pwhide exec -f deploy.sh --shell auto

# ② 环境变量注入（密码不进 argv；注意 Linux 祖先进程可经 /proc/<pid>/environ 读到注入的环境密文）
pwhide exec --env db-local:MYSQL_PWD -- mysql -u {{db-local.user}} -e "SELECT 1"

# ③ args 内联（兼容性最好；子进程运行期间 ps 可短暂见到密码）
pwhide exec -- mysql -u {{db-local.user}} -p{{db-local}} -e "SELECT 1"
```

常用选项：`--shell auto|bash|sh|pwsh|cmd|none`、`--env NAME:VAR`（可重复）、`--timeout 秒`（默认 120）。

退出码：`0` 成功（透传子进程码）｜`2` 用法错误｜`3` vault/口令错误｜`4` 未知占位符｜`124` 超时。

## 5. 错误处理

| 现象 | 含义 | 你的动作 |
|---|---|---|
| 退出码 4（未知占位符） | 条目或字段不存在 | `pwhide list` 核对名称；不存在则请用户本人 `pwhide set` 录入 |
| 退出码 3（口令/密钥错误） | 主口令未解锁或错误 | 提示用户配置 `PWHIDE_PASSPHRASE_FILE` 或交互输入；不要尝试猜测 |
| 退出码 124 | 子进程超时被杀 | 检查命令是否需要交互/挂起，必要时加 `--timeout` |
| 输出含 `{{…}}` | 正常脱敏标记 | 直接转述结果即可 |
| `pwhide exec` 触发 sudo/UAC | 异常（读路径永不提权） | 运行 `pwhide doctor` 检查 vault 状态并反馈用户 |

## 6. 粘贴到项目 AGENTS.md / CLAUDE.md 的契约

```
当需要执行包含密码的命令时：
1. 永远不要向用户索要真实密码，用 {{条目名}} 占位；
2. 不确定有哪些凭据可用时，先 `pwhide list --json` 查询（可见：账号类型、账号、租户、自定义字段名、明文字段值（-pf 录入的非敏感信息如 host/proto）；不可见：密码与加密字段值）；
3. 通过 `pwhide exec -- <命令>` 执行，pwhide 会自动填充并返回结果；
4. 报"未知条目"（退出码 4）时，若无该条目则请用户本人运行 `pwhide set <名字>` 录入；
5. 输出中出现的 {{条目名}} 即为被脱敏的密码，属正常现象。
```
