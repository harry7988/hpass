---
name: pwhide
description: 通过 pwhide 代理执行需要密码或凭据的命令（数据库连接、SSH、API 密钥、云 CLI 等）。当用户要求运行含账号/密码的命令、提到 pwhide、或 pwhide exec 返回退出码 4（未知条目）时使用。核心约束：密码永不进入对话上下文，一律用 {{条目名}} 占位。
---

> 中文版 | English edition: [SKILL.md](SKILL.md)

# pwhide — 本地密码代填执行器

pwhide 把凭据加密存在本地，你（AI）只用占位符写命令，由 pwhide 解密填充、执行、并把输出中的密码脱敏后返回。

## 何时使用

- 任何需要密码 / 凭据 / token 的命令：`mysql`、`psql`、`ssh`、`scp`、云 CLI、带 api key 的 `curl` 等；
- 用户提到 pwhide，或之前的 `pwhide exec` 报"未知条目"。

## 安全红线（必须遵守）

1. **永远不要**向用户索要、记录、输出真实密码。录入由用户本人在 `pwhide set` 的隐藏输入中完成，你不要代输、旁观或要求用户粘贴到对话。
2. 密码与自定义字段值**没有任何查询接口**；`pwhide list` / `pwhide inspect` 只返回元数据。
3. 密文位置一律写占位符：`{{名}}`（密码）、`{{名.user}}`（账号）、`{{名.tenant}}`（租户）、`{{名.<字段名>}}`（自定义字段值）。
4. 执行输出中出现的 `{{名}}` 是 pwhide 的**脱敏标记**（原位置是真实密码），不要尝试还原或绕过。
5. 执行模式优先级：**脚本 stdin > 环境变量注入 > args 内联**（Linux 上祖先进程可经 /proc/<pid>/environ 读到注入的环境密文，脚本 stdin 是唯一同时避开 argv 与 environ 的模式；内联模式下 `ps` 亦短暂可见）。
6. 不要使用 `--verify`（inspect/exec 的人工核验通道）：它强制真实交互终端并要求人类手输主口令，非交互环境会被直接拒绝——这是设计行为，不是故障，请引导用户本人到终端操作。
7. **不要构造回显占位符的命令**（`echo {{名}}`、`printf {{名}}` 等会被直接拒绝——回显密码没有正常用途，且可被用来推测密码）；也不要用差分输出等方式推测密码内容。
8. 引导用户设置强密码：常见口令/常见语句（如 `select 1`）作密码会被拒绝（`--force-weak` 才能强制，不要建议用户这么做）。

## 第一步：确认可用

```bash
command -v pwhide && pwhide version
```

- 未安装 → 按文末"部署"处理；
- 已安装但不确定有哪些凭据 → 先查询。

## 查询可用凭据（只返回元数据，无任何密文值）

```bash
pwhide list --json       # 全部条目
pwhide inspect <name>    # 单条目 + 可用占位符清单
```

可见：条目名、账号类型（type）、账号（username）、租户（tenant）、自定义字段名、明文字段值（plainFields，-pf 录入的 host/proto 等非敏感信息）、`hasPassword`。不可见：密码与加密字段值。

## 执行命令

```bash
# ① 脚本 stdin 模式（推荐：唯一同时避开 argv 与 /proc/<pid>/environ 的模式）
pwhide exec -f deploy.sh --shell auto

# ② 环境变量注入（密码不进 argv；注意 Linux 祖先进程可经 /proc/<pid>/environ 读到注入的环境密文）
pwhide exec --env db-local:MYSQL_PWD -- mysql -u {{db-local.user}} -e "SELECT 1"

# ③ args 内联（兼容性最好；子进程运行期间 ps 可短暂见到密码）
pwhide exec -- mysql -u {{db-local.user}} -p{{db-local}} -e "SELECT 1"
```

常用选项：`--shell auto|bash|sh|pwsh|cmd|none`、`--env NAME:VAR`（可重复）、`--timeout 秒`（默认 120）。

### 与模板语法冲突时：切换占位符定界符

要编辑/执行的文件本身使用 `{{ }}` 模板语法（Helm、Jinja2、Go text/template、Ansible 等）时，给 exec 加 `--ph`，占位符改写为 `#条目名#`（或 `@条目名@`）：

```bash
pwhide exec --ph '#' -- envsubst < helm-values.yaml   # 此时 {{db}} 是模板字面量，#db# 才是凭据占位符
pwhide exec --ph '@' -f deploy.sh --shell auto         # 脚本内注释密集时用 @（# 与注释行易混淆）
```

规则：`--ph` 生效时**只**识别当前定界符（`{{db}}` 是字面量，反之亦然）；脱敏输出与错误信息也按当前定界符渲染（如输出中的 `#db#` 即脱敏标记）。字段语法不变：`#条目名.user#`、`@条目名.字段名@`。

## 凭据不存在时（退出码 4）

请用户**本人**运行录入命令，密码由隐藏输入提供：

```bash
pwhide set <条目名> -t <类型:database|ssh|api|cloud|自定义> -u <账号> -T <租户> -f <字段名=值>
```

录入后用 `pwhide inspect <条目名>` 向用户展示元数据确认。

## 错误处理

| 现象 | 含义 | 你的动作 |
|---|---|---|
| 退出码 4 | 未知条目/字段 | `pwhide list` 核对；不存在则请用户本人 `pwhide set` |
| 退出码 3 | 主口令未解锁/错误 | 提示用户运行 `pwhide keychain set`（一次配置，之后零交互）或配置 `PWHIDE_PASSPHRASE_FILE`；不要猜测、不要向用户索要口令 |
| 退出码 124 | 子进程超时被杀 | 检查命令是否挂起，必要时加 `--timeout` |
| 输出含 `{{…}}` | 正常脱敏标记 | 直接转述结果 |
| `pwhide exec` 触发 sudo/UAC | 异常（读路径永不提权） | 运行 `pwhide doctor` 并反馈用户 |

## 部署（未安装时）

按仓库 `docs/ai-deploy-guide.md` 的 runbook 执行：

1. 识别平台（`uname -s`/`uname -m`）；
2. 从 GitHub Release 下载对应 RID 二进制并校验 sha256（未发布则源码构建：.NET 10 SDK，`dotnet publish -r <rid> -c Release /p:PublishAot=true`）；
3. 放入 PATH，`pwhide version` 验证；
4. `pwhide init` —— 主口令由用户本人输入（基础模式 700/600）；随后建议执行 `pwhide harden` 启用管理员级写保护（sudo/UAC 属正常）；
5. `pwhide doctor` 验证；引导用户录入首批凭据；如需人工验证脱敏：`pwhide exec --allow-echo -- echo {{条目名}}`（直接回显占位符会被拒绝）。
