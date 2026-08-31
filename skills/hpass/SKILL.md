---
name: hpass
description: 通过 hpass 代理执行需要密码或凭据的命令（数据库连接、SSH、API 密钥、云 CLI 等）。当用户要求运行含账号/密码的命令、提到 hpass、或 hpass exec 返回退出码 4（未知条目）时使用。核心约束：密码永不进入对话上下文，一律用 {{条目名}} 占位。
---

# hpass — 本地密码代填执行器

hpass 把凭据加密存在本地，你（AI）只用占位符写命令，由 hpass 解密填充、执行、并把输出中的密码脱敏后返回。

## 何时使用

- 任何需要密码 / 凭据 / token 的命令：`mysql`、`psql`、`ssh`、`scp`、云 CLI、带 api key 的 `curl` 等；
- 用户提到 hpass，或之前的 `hpass exec` 报"未知条目"。

## 安全红线（必须遵守）

1. **永远不要**向用户索要、记录、输出真实密码。录入由用户本人在 `hpass set` 的隐藏输入中完成，你不要代输、旁观或要求用户粘贴到对话。
2. 密码与自定义字段值**没有任何查询接口**；`hpass list` / `hpass inspect` 只返回元数据。
3. 密文位置一律写占位符：`{{名}}`（密码）、`{{名.user}}`（账号）、`{{名.tenant}}`（租户）、`{{名.<字段名>}}`（自定义字段值）。
4. 执行输出中出现的 `{{名}}` 是 hpass 的**脱敏标记**（原位置是真实密码），不要尝试还原或绕过。
5. 执行模式优先级：**环境变量注入 > 脚本 stdin > args 内联**（越靠后密码越可能在 `ps` 中短暂可见）。

## 第一步：确认可用

```bash
command -v hpass && hpass version
```

- 未安装 → 按文末"部署"处理；
- 已安装但不确定有哪些凭据 → 先查询。

## 查询可用凭据（只返回元数据，无任何密文值）

```bash
hpass list --json       # 全部条目
hpass inspect <name>    # 单条目 + 可用占位符清单
```

可见：条目名、账号类型（type）、账号（username）、租户（tenant）、自定义字段名、`hasPassword`。不可见：密码与字段值。

## 执行命令

```bash
# ① 环境变量注入（推荐：密码不进 argv，ps 不可见）
hpass exec --env db-local:MYSQL_PWD -- mysql -u {{db-local.user}} -e "SELECT 1"

# ② 脚本 stdin 模式（脚本文件内写占位符；替换在内存完成，不落盘）
hpass exec -f deploy.sh --shell auto

# ③ args 内联（兼容性最好；子进程运行期间 ps 可短暂见到密码）
hpass exec -- mysql -u {{db-local.user}} -p{{db-local}} -e "SELECT 1"
```

常用选项：`--shell auto|bash|sh|pwsh|cmd|none`、`--env NAME:VAR`（可重复）、`--timeout 秒`（默认 120）。

## 凭据不存在时（退出码 4）

请用户**本人**运行录入命令，密码由隐藏输入提供：

```bash
hpass set <条目名> -t <类型:database|ssh|api|cloud|自定义> -u <账号> -T <租户> -f <字段名=值>
```

录入后用 `hpass inspect <条目名>` 向用户展示元数据确认。

## 错误处理

| 现象 | 含义 | 你的动作 |
|---|---|---|
| 退出码 4 | 未知条目/字段 | `hpass list` 核对；不存在则请用户本人 `hpass set` |
| 退出码 3 | 主口令未解锁/错误 | 提示用户配置 `HPASS_PASSPHRASE_FILE` 或交互输入；不要猜测 |
| 退出码 124 | 子进程超时被杀 | 检查命令是否挂起，必要时加 `--timeout` |
| 输出含 `{{…}}` | 正常脱敏标记 | 直接转述结果 |
| `hpass exec` 触发 sudo/UAC | 异常（读路径永不提权） | 运行 `hpass doctor` 并反馈用户 |

## 部署（未安装时）

按仓库 `docs/ai-deploy-guide.md` 的 runbook 执行：

1. 识别平台（`uname -s`/`uname -m`）；
2. 从 GitHub Release 下载对应 RID 二进制并校验 sha256（未发布则源码构建：.NET 10 SDK，`dotnet publish -r <rid> -c Release /p:PublishAot=true`）；
3. 放入 PATH，`hpass version` 验证；
4. `hpass init` —— 主口令由用户本人输入；默认请求 sudo/UAC 做文件加固，属正常；
5. `hpass doctor` 验证；引导用户录入首批凭据；用 `hpass exec -- echo {{条目名}}` 冒烟验证脱敏。

> 注：hpass 处于开发中，本 skill 描述 v1 目标行为。若命令不存在或行为不符，提示用户当前里程碑尚未实现，**不要臆造替代方案**（尤其不要退回到"把密码贴进对话"）。
