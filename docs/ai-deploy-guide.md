# hpass AI 部署与使用指南

本文档面向 AI 编程工具（Claude Code、Cursor 及其他 Agent）。你的任务分两类：

1. **部署**：按 §1 的 runbook 为用户安装、初始化并验证 hpass；
2. **日常使用**：通过查询接口（§3）了解可用凭据，通过执行接口（§4）代理执行含密码的命令 —— 全程不接触任何真实密码。

> 注意：hpass 处于开发中，本指南描述的是 v1 目标行为（见 [PLAN.md](../PLAN.md)）。若命令不存在或行为不符，请提示用户当前版本尚未实现该里程碑，不要臆造替代方案。

---

## 0. 铁律（先读）

1. **永远不要**向用户索要、记录、输出或以任何形式处理真实密码。录入密码是用户本人的交互（`hpass set` 隐藏输入），你不要旁观、代输或要求用户粘贴到对话里。
2. 密码与自定义字段值**没有任何查询接口**。`hpass list` / `hpass inspect` 只返回元数据（类型、账号、租户、字段名）。
3. 命令中需要密文的位置一律写**占位符**：`{{条目名}}`（密码）、`{{条目名.user}}`、`{{条目名.tenant}}`、`{{条目名.<字段名>}}`。
4. 执行结果中出现的 `{{条目名}}` 是 hpass 的**脱敏标记**（原位置是真实密码），属正常现象，不要尝试"还原"它。
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
curl -LO https://github.com/harry7988/hpass/releases/latest/download/hpass-<rid>.tar.gz
# 2) 校验（必须）
curl -LO https://github.com/harry7988/hpass/releases/latest/download/SHA256SUMS
shasum -a 256 --check SHA256SUMS --ignore-missing
# 3) 解压
tar xzf hpass-<rid>.tar.gz
```

**方式 B：源码构建（需 .NET 10 SDK）**

```bash
git clone git@github.com:harry7988/hpass.git && cd hpass
dotnet publish src/HPass.Cli -c Release -r <rid> /p:PublishAot=true -o publish
# 产物为 publish/hpass（Windows 为 hpass.exe）
```

### 1.3 安装到 PATH

- Unix：`/usr/local/bin/hpass`（需 sudo）或 `~/.local/bin/hpass`（确认在 PATH 内）。
- Windows：`%LOCALAPPDATA%\Programs\hpass\hpass.exe` 并将该目录加入用户 PATH。

验证：`hpass version`。

### 1.4 初始化

引导用户**本人**执行（你来运行命令、用户来输密码）：

```
hpass init
```

- 会让用户设置并确认**主口令**（用于加密私钥）。提醒用户：口令丢失则所有密码不可恢复，没有后门。
- 默认启用特权加固：请求 sudo/UAC 将 vault 文件设为管理员写保护，属正常且建议允许；环境不支持会自动询问降级。

### 1.5 验证

```
hpass doctor
```

确认输出中：shell 探测正常、vault 权限/加固状态正常、无中断待恢复项。

### 1.6 录入首批凭据

由用户本人运行（每个敏感值都是隐藏输入；`-f` 敏感字段值可从环境变量读取避免明文出现在命令行）：

```bash
hpass set db-local -t database -u root -T prod -f host=127.0.0.1 -f port=3306
```

录入后你可以用 `hpass inspect db-local` 向用户展示元数据确认无误。

### 1.7 冒烟测试

用无害命令验证占位符填充与脱敏链路：

```bash
# 注意：直接回显占位符属探测行为，默认被拒绝；人工验证脱敏需显式 --allow-echo
hpass exec --allow-echo -- echo "password is {{db-local}}"
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
hpass list            # 人类可读表格
hpass list --json     # 机器可读（推荐 AI 使用）
hpass inspect <name>  # 单条目详情 + 可用占位符清单
```

`hpass list --json` 输出示例：

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

按安全性从高到低：

```bash
# ① 环境变量注入（推荐：密码不进 argv，ps 不可见）
hpass exec --env db-local:MYSQL_PWD -- mysql -u {{db-local.user}} -e "SELECT 1"

# ② 脚本 stdin 模式（脚本文件内写占位符；替换在内存完成，不落盘）
hpass exec -f deploy.sh --shell auto

# ③ args 内联（兼容性最好；子进程运行期间 ps 可短暂见到密码）
hpass exec -- mysql -u {{db-local.user}} -p{{db-local}} -e "SELECT 1"
```

常用选项：`--shell auto|bash|sh|pwsh|cmd|none`、`--env NAME:VAR`（可重复）、`--timeout 秒`（默认 120）。

退出码：`0` 成功（透传子进程码）｜`2` 用法错误｜`3` vault/口令错误｜`4` 未知占位符｜`124` 超时。

## 5. 错误处理

| 现象 | 含义 | 你的动作 |
|---|---|---|
| 退出码 4（未知占位符） | 条目或字段不存在 | `hpass list` 核对名称；不存在则请用户本人 `hpass set` 录入 |
| 退出码 3（口令/密钥错误） | 主口令未解锁或错误 | 提示用户配置 `HPASS_PASSPHRASE_FILE` 或交互输入；不要尝试猜测 |
| 退出码 124 | 子进程超时被杀 | 检查命令是否需要交互/挂起，必要时加 `--timeout` |
| 输出含 `{{…}}` | 正常脱敏标记 | 直接转述结果即可 |
| `hpass exec` 触发 sudo/UAC | 异常（读路径永不提权） | 运行 `hpass doctor` 检查 vault 状态并反馈用户 |

## 6. 粘贴到项目 AGENTS.md / CLAUDE.md 的契约

```
当需要执行包含密码的命令时：
1. 永远不要向用户索要真实密码，用 {{条目名}} 占位；
2. 不确定有哪些凭据可用时，先 `hpass list --json` 查询（可见：账号类型、账号、租户、自定义字段名；不可见：密码与字段值）；
3. 通过 `hpass exec -- <命令>` 执行，hpass 会自动填充并返回结果；
4. 报"未知条目"（退出码 4）时，若无该条目则请用户本人运行 `hpass set <名字>` 录入；
5. 输出中出现的 {{条目名}} 即为被脱敏的密码，属正常现象。
```
