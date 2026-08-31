# hpass

> 面向 AI 编程工具的本地密码代填 CLI —— AI 只看到占位符和执行结果，密码永远不进入对话上下文。

**状态：v0.1.0 已实现** —— 100 个测试全部通过（60 单元 + 40 集成），CI 三平台（macOS / Ubuntu / Windows）构建测试 + Native AOT 冒烟（含真实 sudo 的管理员级加固流程）全绿；威胁模型见 [docs/threat-model.md](docs/threat-model.md)，里程碑状态见 [PLAN.md](PLAN.md)。

## 为什么需要 hpass

让 AI（Claude Code、Cursor、其他 Agent）执行需要密码的命令时，传统做法只有两种：把密码贴进对话（进入上下文、日志，且被长期记住），或者人类每次手动代跑（打断自动化）。

hpass 提供第三条路：**密码预先录入本地加密库，AI 用占位符写命令，hpass 解密填充、执行、并把输出里的密码脱敏后返回。**

```
AI 生成：hpass exec -- mysql -u {{db.user}} -p{{db}} -e "SELECT 1"
AI 收到：mysql: [输出] ...（若输出中出现密码，已被替换为 {{db}}）
密码全程未出现在：对话、shell history、进程日志
```

## 核心特性

- **零上下文泄露**：没有任何查看密码的命令；子进程输出流式脱敏后才返回。
- **三种执行模式**：args 内联（兼容）、环境变量注入（推荐，`ps` 不可见）、脚本 stdin（脚本内占位符，不落盘不进 argv）。
- **包装四种 shell**：bash / sh / pwsh / cmd，跨平台自动探测或显式指定。
- **扩展条目模型**：账号类型、账号、租户、自定义字段 —— 元数据可查（AI 组装命令用），密码与字段值不可查。
- **信封加密**：口令 → PBKDF2 → 加密 RSA-3072 私钥 → OAEP 包裹 AES-256 数据密钥 → 每条 AEAD 加密（AAD 防密文互换）。
- **特权加固**：vault 变更唯一入口是"staged 安装"（清保护 → 原子覆盖 → 重新加保护）。`hpass harden` 一键加固——root 属主 + 不可变标志（`schg`/`chattr +i`，macOS 普通用户可用 `uchg` 用户级保护）；管理员写保护下 `set` 等命令自动经 sudo 搬运**密文**完成安装（`_install-staged`，带路径白名单）；`doctor` 检测并恢复中断的加固/残留暂存；`exec` 读路径永不提权。
- **C# Native AOT 单文件二进制**：macOS / Linux / Windows 六个 RID，零运行时依赖。

## 安装

**方式 A：Release 二进制（推荐）**——从 [Releases](https://github.com/harry7988/hpass/releases) 下载对应平台的压缩包并校验：

```bash
curl -LO https://github.com/harry7988/hpass/releases/latest/download/hpass-osx-arm64.tar.gz
curl -LO https://github.com/harry7988/hpass/releases/latest/download/SHA256SUMS
shasum -a 256 --check SHA256SUMS --ignore-missing
tar xzf hpass-osx-arm64.tar.gz && sudo mv hpass /usr/local/bin/
```

**方式 B：源码构建**（需 .NET 10 SDK）：

```bash
git clone git@github.com:harry7988/hpass.git
cd hpass
dotnet publish src/HPass.Cli -c Release -r osx-arm64 /p:PublishAot=true -o publish
# RID 可选：osx-arm64 | osx-x64 | linux-x64 | linux-arm64 | win-x64 | win-arm64
```

让 AI 工具帮你部署：见 [docs/ai-deploy-guide.md](docs/ai-deploy-guide.md)。

## 快速上手

```bash
# 1. 初始化（设置主口令；默认请求 sudo/UAC 做文件加固，属正常）
hpass init

# 2. 录入凭据（人类操作；密码为隐藏输入，AI 不参与）
hpass set db-local -t database -u root -T prod -f host=127.0.0.1

# 3. 查询可用凭据（元数据，无任何密文值）
hpass list --json

# 4. AI 代理执行
hpass exec -- mysql -u {{db-local.user}} -p{{db-local}} -e "SELECT 1"
hpass exec --env db-local:MYSQL_PWD -- mysql -u {{db-local.user}} -e "SELECT 1"   # 更安全
hpass exec -f deploy.sh          # 脚本内写 {{db-local}}，替换后经 stdin 执行
```

## 条目模型

| 字段 | 可见性 | 说明 | 占位符 |
|---|---|---|---|
| name | 明文 | 条目名（主键） | — |
| type | 明文 | 账号类型：database / ssh / api / cloud / 自定义 | — |
| username | 明文 | 账号 | `{{name.user}}` |
| tenant | 明文 | 租户 / 环境标识 | `{{name.tenant}}` |
| password | **加密** | 密码 | `{{name}}` |
| fields | 字段名明文、**值加密** | 自定义字段（host、api_key…） | `{{name.<字段名>}}` |

`hpass list --json` 示例（AI 的主查询接口）：

```json
[
  {
    "name": "db-local",
    "type": "database",
    "username": "root",
    "tenant": "prod",
    "hasPassword": true,
    "fields": ["host", "api_key"],
    "updatedAt": "2026-09-01T00:00:00Z"
  }
]
```

## AI 工具集成

将以下契约粘贴进项目的 `AGENTS.md` / `CLAUDE.md`：

```
当需要执行包含密码的命令时：
1. 永远不要向用户索要真实密码，用 {{条目名}} 占位；
2. 不确定有哪些凭据可用时，先 `hpass list --json` 查询（可见：账号类型、账号、租户、自定义字段名；不可见：密码与字段值）；
3. 通过 `hpass exec -- <命令>` 执行，hpass 会自动填充并返回结果；
4. 报"未知条目"（退出码 4）时，若无该条目则请用户本人运行 `hpass set <名字>` 录入；
5. 输出中出现的 {{条目名}} 即为被脱敏的密码，属正常现象。
```

完整部署 runbook 与故障排查：[docs/ai-deploy-guide.md](docs/ai-deploy-guide.md)。

### 安装 AI Skill（推荐）

仓库内置面向 Agent 的 [skills/hpass](skills/hpass/)（含 `SKILL.md` 与安装脚本），安装后 AI 会自动遵循占位符与脱敏规则，无需手动粘贴契约：

```bash
git clone git@github.com:harry7988/hpass.git && cd hpass
./skills/hpass/install.sh                    # 自动探测 ~/.claude/skills > ~/.zcode/skills > ~/.agents/skills
# 或指定目录：./skills/hpass/install.sh ~/.claude/skills
```

手动安装：将 `skills/hpass/` 整个目录复制到对应工具的 skills 目录 —— Claude Code `~/.claude/skills/`、ZCode `~/.zcode/skills/`、通用 `~/.agents/skills/`；项目级放 `<项目>/.claude/skills/`。Windows 直接复制文件夹即可。

## 安全设计摘要

六条安全不变量约束所有实现（全文见 [PLAN.md](PLAN.md) §1）：

1. 密码只进进程、不出终端（无 `get`/`show` 类命令）
2. 未知占位符绝不执行
3. 输出流式脱敏（最终防线）
4. 私钥不出本机，vault 单独泄露不可解
5. 日志/错误永不回显已解析命令
6. vault 变更仅经特权原子覆盖，`exec` 永不提权

**如实声明的边界**：防密码意外进入上下文/日志/备份，不防已提权的恶意软件与恶意 Agent 主动编码外传；内联模式下密码在子进程运行期间可通过 `ps` 短暂可见（用 env 注入/脚本 stdin 模式规避）。完整威胁模型：[docs/threat-model.md](docs/threat-model.md)。

## 平台支持

| 平台 | RID | 状态 |
|---|---|---|
| macOS (Apple Silicon / Intel) | osx-arm64 / osx-x64 | ✅ arm64 本地实测 + CI 绿 |
| Linux (x64 / arm64) | linux-x64 / linux-arm64 | ✅ x64 CI 绿（bash/sh/pwsh） |
| Windows (x64 / arm64) | win-x64 / win-arm64 | ✅ x64 CI 绿（pwsh 实测，cmd 按 §7.1 规则实现） |

## 开发

里程碑 M0 底座 → M1 保险库 → M2 执行引擎 → M3 特权加固 → M4 发布 → M5 增强，详见 [PLAN.md](PLAN.md)。

```bash
dotnet build
dotnet test          # 100 个测试：单元（加密/vault/占位符/脱敏/执行引擎/加固）+ 集成（CLI 全链路）
dotnet publish src/HPass.Cli -c Release -r osx-arm64 /p:PublishAot=true -o publish
```

## 许可证

[MIT](LICENSE)
