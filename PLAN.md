# h-password (hpass) 完整开发计划

> 一个面向 AI 编程工具的本地密码代填 CLI：AI 只看到占位符和执行结果，密码永远不进入对话上下文。
> 技术形态：C# Native AOT 单文件二进制，跨 macOS / Linux / Windows。

---

## 0. 目标与定位

| # | 需求 | 对应设计 |
|---|------|----------|
| 1 | 包装 pwsh/cmd/bash/sh 脚本 | 执行引擎支持 shell 自动探测与显式指定（§7） |
| 2 | 代理执行含用户名密码的命令 | `hpass exec`：占位符填充 → 执行 → 结果返回（§6/§7） |
| 3 | 跨平台 AI TOOL 密码填充工具 | .NET AOT 六个 RID 产物（§8），附带"AI 使用契约"（§3.1） |
| 4 | 预先录入、加密本地存放、不进上下文 | 非对称混合加密 vault，无任何明文输出命令（§4/§5） |
| 5 | 调用便捷 | 一条命令完成填充+执行+脱敏返回（§6） |
| 6 | C# AOT 二进制分发 + 非对称加密 | RSA-OAEP 混合加密 + Native AOT 发布（§4/§8） |

**非目标（v1）**：网络同步、团队共享、密码生成器、浏览器填充。

---

## 1. 核心安全不变量（Invariants）

整个开发过程中，以下 5 条不变量优先于一切功能需求，任何 PR 不得违反：

- **I1 密码只进进程、不出终端**：不提供任何把明文密码打印到 stdout/stderr/文件的命令（没有 `get`/`show`/`cat`）。
- **I2 未解析的占位符绝不执行**：命令中任何 `{{name}}` 在 vault 中找不到条目 → 直接失败退出（exit 4），绝不带着占位符或空值降级执行。
- **I3 输出脱敏**：子进程 stdout/stderr 中若出现本次使用的密码，流式替换回 `{{name}}` 后再输出 —— 这是"密码不进上下文"的最终防线。
- **I4 私钥不出本机**：vault 文件单独被拷贝/误提交不可解密。
- **I5 不回显已解析命令**：错误信息、verbose 日志中只出现占位符版本，永不出现填充后的命令行。
- **I6 变更仅经特权原子覆盖**：vault/master.key 的写入只允许"提权 → 原子替换整个文件 → 重新加保护"这一条路径，永不就地修改；`exec` 读取路径永不提权（AI 调用不触发任何系统权限提示）。

---

## 2. 威胁模型（如实声明）

**防护目标**：
- 密码进入 AI 对话上下文、终端回显、日志、shell history（命令由 hpass 直接 spawn，history 只记录占位符版本）。
- vault 文件被拷贝、同步网盘、误提交到 git 后泄露（没有私钥不可解）。
- 用户态进程（含 AI 起的子进程）对 vault/master.key 的修改、替换、删除 —— 加固模式（§5.1）下任何写动作都触发 OS 提权确认（sudo/UAC），人在环。

**明确不防护**：
- 恶意 Agent 主动构造变换（如 `echo {{db}} | base64`）绕过脱敏外传 —— 这属于恶意软件范畴，工具定位是"防意外泄露"；M5 可加 risky-pattern lint 缓解。
- 持有 root/Administrator 的攻击者（平台保护标志可被其清除）：现有条目的局部篡改会被 AEAD 认证必然发现，整体重造 vault 可经 `hpass list` 察觉条目异常，但不做进一步对抗。
- 内存 dump、ptrace 调试。
- 内联参数模式下，密码在子进程运行期间可通过 `ps` 短暂可见 —— 通过 env 注入 / 脚本 stdin 两种更安全模式缓解并文档明示。

---

## 3. 总体架构

```
AI 工具 (Claude Code / Cursor / …)                 人（一次性录入）
        │                                                 │
        │ hpass exec -- mysql -u {{db.user}} …            │ hpass set db
        ▼                                                 ▼
┌────────────────────── hpass（单文件 AOT 二进制）──────────────────────┐
│  参数/脚本 → 占位符解析 → vault 解密(仅内存) → 命令组装 → spawn 子进程  │
│                                   ▲                                   │
│              输出流式脱敏 ←────────┴── stdin/stdout/stderr 转发        │
└───────────────────────────────────────────────────────────────────────┘
```

### 3.1 三种填充/执行模式（安全性递增）

1. **args 内联模式**：`hpass exec -- mysql -u {{db.user}} -p{{db}} -e "…"`
   兼容性最好；缺点：密码进入子进程 argv，`ps` 短暂可见。
2. **环境变量注入模式（推荐）**：`hpass exec --env db:MYSQL_PWD -- mysql -u root -e "…"`
   密码只进 child 环境变量，argv 与 `ps` 不可见。预置常见工具约定（MYSQL_PWD、PGPASSWORD 等）文档。
3. **脚本 stdin 模式（脚本包装的主推方式）**：`hpass exec -f deploy.sh --shell auto`
   脚本文件里写 `{{db}}`，hpass 读文件 → 内存中替换 → 通过 stdin 交给 `bash -s` / `pwsh -Command -`。
   密码不落盘、不进 argv，ps 不可见。

### 3.2 AI 工具使用契约（交付物之一，写入 README，可粘贴进 AGENTS.md/CLAUDE.md）

```
当需要执行包含密码的命令时：
1. 永远不要向用户索要真实密码，用 {{条目名}} 占位；
2. 不确定有哪些凭据可用时，先 `hpass list --json` 查询（可见：账号类型、账号、租户、自定义字段名；不可见：密码与字段值）；
3. 通过 `hpass exec -- <命令>` 执行，hpass 会自动填充并返回结果；
4. 报"未知条目"（退出码 4）时，若无该条目则请用户本人运行 `hpass set <名字>` 录入；
5. 输出中出现的 {{条目名}} 即为被脱敏的密码，属正常现象。
```

---

## 4. 密钥与加密设计

### 4.1 密钥层次（信封加密）

```
口令 (passphrase)
  └─(PBKDF2-HMAC-SHA512, ≥210k 迭代, 16B 随机盐)→ KEK
       └─(AES-256-GCM) 加密 master.key 中的 RSA-3072 私钥
             └─(RSA-OAEP-SHA256) 包裹 vault 级 DEK（随机 AES-256 key）
                   └─(AES-256-GCM, AAD=条目名+vault版本) 加密每条密码
```

- **身份密钥对：RSA-3072 / OAEP-SHA256**。理由：Windows CNG 不支持 X25519 ECDH，而 RSA 在 .NET 内置加密库里三平台行为完全一致且 AOT 安全。X25519/Ed25519 列为后续优化项（验证 Windows 兼容后可切换，格式字段 `alg` 预留）。
- **每条目**：独立 nonce（12B），AAD 绑定条目名 + vault 版本号，防"条目密文互换"攻击。
- **为什么本地工具也用非对称**（对应需求 6）：
  1. `set` 录入只需公钥 —— 可在 CI 或其他机器上向 vault 写入"写入方自己也读不出"的密码；
  2. 密钥轮换只重包裹 DEK，不需重加密全部条目；
  3. 为将来多设备同步留出架构空间。
- **口令（私钥解锁）来源优先级**：交互隐藏输入 > `HPASS_PASSPHRASE_FILE`（文件权限 600）> `HPASS_PASSPHRASE` 环境变量（自动化/AI 非交互场景）。M5 增加 OS keychain 与 agent 常驻解锁。
- **内存卫生**：解密结果停留在 `byte[]`，用后 `Array.Clear`； unavoidable 的 string 使用后尽快脱离引用（.NET string 不可清零，文档如实说明残余风险）。

### 4.2 密码学原语清单（全部 .NET 内置，零第三方依赖）

| 用途 | 算法 | API |
|---|---|---|
| 对称加密 | AES-256-GCM | `AesGcm` |
| 密钥包裹 | RSA-3072 OAEP-SHA256 | `RSA.Encrypt/Decrypt` |
| 口令派生 | PBKDF2-HMAC-SHA512 | `Rfc2898DeriveBytes` |
| 随机数 | CSPRNG | `RandomNumberGenerator` |

（M5 评估 Argon2id 替换 PBKDF2，需先验证第三方库的 AOT 兼容性。）

---

## 5. Vault 存储设计

**目录布局 — 基础模式**（Unix：`~/.hpass/`；Windows：`%USERPROFILE%\.hpass\`；目录 0700，文件 0600，Windows 设置 ACL 仅当前用户）：

```
~/.hpass/
├── vault.json     # 条目库（可安全被同步/备份，无私钥不可解）
├── master.key     # RSA 私钥（口令加密后的密文）
├── config.json    # 默认 shell、超时等
└── run/           # 用户可写：lock（flock / LockFileEx）、会话产物
```

**vault.json 格式**（与 v0.1.0 实现一致；KDF 参数在 master.key 中，vault.json 不含）：

```json
{
  "version": 1,
  "identity": { "alg": "RSA-OAEP-SHA256", "publicKey": "b64(SPKI)" },
  "wrappedDek": { "alg": "RSA-OAEP-SHA256", "ct": "b64" },
  "entries": [
    {
      "name": "db-local",
      "type": "database",
      "username": "root",
      "tenant": "prod",
      "fields": [
        { "name": "host", "nonce": "b64", "ct": "b64(AES-GCM(value), AAD=name|f:host)" },
        { "name": "api_key", "nonce": "b64", "ct": "b64" }
      ],
      "createdAt": "2026-09-01T00:00:00Z",
      "updatedAt": "2026-09-01T00:00:00Z",
      "nonce": "b64(12B)",
      "ct": "b64(AES-GCM(password), AAD=name|\x01password)"
    }
  ]
}
```

**master.key 格式**（RSA 私钥经口令派生密钥加密）：

```json
{
  "kdf": { "algo": "PBKDF2-SHA512", "iterations": 210000, "salt": "b64(16B)" },
  "alg": "AES-256-GCM",
  "nonce": "b64(12B)",
  "ct": "b64(PKCS8(RSA-3072), AAD=\"hpass/master.key\")"
}
```

- **明文字段（AI 可查询，用于组装命令的非敏感部分）**：条目名、账号类型（type）、账号（username）、租户（tenant）、自定义字段**名**。
- **加密字段（无任何查询接口，只能经占位符注入子进程）**：密码、全部自定义字段**值**（字段值可能含 API key 等，统一加密最简且安全）。
- 每个自定义字段值独立 AEAD，AAD 绑定"条目名+字段名"，防字段间密文互换；`user`、`tenant` 为保留字段名。

- **并发**：set/delete/rename 持独占锁；exec 只读，读到不一致（GCM 校验失败）时报错而非半执行。
- **条目名**：字符集 `[A-Za-z0-9_.-]`，不区分大小写存储、区分大小写匹配（`hpass list` 展示原名）。

### 5.1 特权加固模式（hardened）—— 管理员权限写保护

目标：**密码文件只能整体覆盖，不能被直接修改/篡改**。用户态进程对 vault/master.key 的一切写动作都会触发 OS 级提权确认，人在环。

| 平台 | 所有权与权限 | 写保护机制 | 解除保护 |
|---|---|---|---|
| macOS | root:用户组 0440，目录 root 0750 | `chflags schg`（系统不可变标志） | 需 root |
| Linux | root:用户组 0440，目录 root 0750 | `chattr +i`（不可变属性） | 需 root |
| Windows | Administrators/SYSTEM 完全控制，当前用户只读 | ACL 拒写（不可变标志的平台等价物） | 需 UAC |

注：Linux 上文件系统不支持 `chattr +i`（WSL、容器 overlayfs、网络盘）时自动降级为"仅 root 属主 + 权限"，`doctor` 明示当前实际保护等级。`run/` 保持用户可写，保证 `exec` 读路径完全无需提权。

**写入流程（统一原则：提权子进程只碰密文，明文永不出用户态进程）**：
1. 父进程（用户态）完成全部加密，产出完整的新 vault/master.key 密文，先写入用户可写的暂存文件；
2. 提权仅做文件操作：Unix 以 `sudo` 重拉自身执行搬运；Windows 经 UAC 拉起提权"搬运"子进程；执行"清保护 → 原子 rename 覆盖 → 恢复属主/权限 → 重新加保护"；
3. 机密永不经 argv/环境变量跨进程传递 —— 跨进程移动的只有密文，无泄露面；
4. 中断恢复：清保护与再加保护之间被打断时，文件处于"未保护但完整"状态，`doctor` 与下次 `set` 检测并自动补加保护。

---

## 6. CLI 命令规格

| 命令 | 作用 | 关键点 |
|---|---|---|
| `hpass init [--no-harden]` | 生成密钥对 + 空 vault | 默认启用特权加固（§5.1），创建时请求 sudo/UAC；`--no-harden` 降级基础模式；口令两次确认；RSA keygen 约 1-2 秒属正常 |
| `hpass set <name> [-t <类型>] [-u <账号>] [-T <租户>] [-f <字段=值>…]` | 录入/更新条目 | 密码走隐藏输入（termios/SetConsoleMode P/Invoke）；**禁止**命令行明文传密码（防 history），自定义字段敏感值同样走隐藏输入/`-f` 读环境变量；支持 `-` 从 stdin 读；加固模式下为特权操作（自动请求提权，仅密文移动） |
| `hpass list [--json]` | 列出全部条目 | 输出明文元数据：条目名/类型/账号/租户/字段名列表 + 更新时间；**永不显示密码与字段值** —— 这是 AI 的主查询接口 |
| `hpass inspect <name> [--json]` | 查看单个条目元数据 | 同上，粒度到单条目；含 `hasPassword` 标记与可用占位符清单 |
| `hpass delete <name>` / `hpass rename <old> <new>` | 管理 | rename 后需重加密（AAD 变化）；特权操作（自动请求提权） |
| `hpass exec [options] -- <cmd...>` | **核心**：填充+执行+脱敏 | 见下 |
| `hpass exec -f <script> [options]` | 脚本 stdin 模式 | 脚本内占位符替换后经 stdin 执行 |
| `hpass rotate` | 更换密钥对 | 只重包裹 DEK；特权操作 |
| `hpass doctor` | 环境自检 | shell 探测、加固状态与中断恢复检查、平台信息 |
| `hpass version` | 版本 | — |

**`exec` 选项**：

- `--shell auto|bash|sh|pwsh|cmd|none`（默认 auto：Unix 下 `$SHELL`→bash→sh；Windows 下 pwsh→powershell→cmd；`none` 表示不经 shell 直接 spawn，最安全）
- `--env NAME:ENVVAR`（可重复，如 `--env db:MYSQL_PWD`）
- `--timeout <秒>`（默认 120）
- `--no-redact`（人类调试用，输出警告，文档不做重点宣传）

**占位符语法**：`{{name}}` = 密码；`{{name.user}}` = 账号；`{{name.tenant}}` = 租户；`{{name.<字段名>}}` = 自定义字段值（解密后填充）。`user`/`tenant` 为保留字段名。解析规则：名内字符集外的内容不匹配，避免误伤模板字符串。

**退出码**：`0` 成功（透传子进程退出码）；`2` 用法错误；`3` vault/密钥/口令错误；`4` 未知占位符；`124` 超时。

---

## 7. 执行引擎（重点）

> `exec` 全程只读 vault、以普通用户权限运行 —— AI 调用路径永远不触发 sudo/UAC（I6）。

### 7.1 spawn 策略

| 模式 | Unix | Windows |
|---|---|---|
| args 内联（有 shell 特性时） | `bash -c "<填充后命令>"` | `pwsh -Command "<…>"` 或 `cmd /c "<…>"` |
| args + `--shell none` | 直接 exec，argv 数组传递 | 直接 CreateProcess，ArgumentList 传递 |
| env 注入 | child 环境变量，argv 干净 | 同左 |
| 脚本 stdin | `bash -s`，脚本内容走 stdin | `pwsh -Command -`；cmd 无等价物 → 提示改用 pwsh 或降级临时文件（受 ACL 保护 + 立即删除，文档标注风险） |

- **Windows cmd 引号转义**是已知深坑（cmd 规则与 MSVCRT 不同，.NET ArgumentList 的自动引号在 cmd 下不正确）：实现自研 cmd 转义器 + 专用测试矩阵；文档推荐 Windows 用户优先 pwsh。
- **stdin**：默认转发（支持管道输入）；检测 tty 时直接继承。

### 7.2 输出脱敏（I3，最终防线）

- 对**本次解密使用的**每个 secret（最小知识原则，不做全库扫描）在 stdout/stderr 流中做流式替换 → `{{name}}`。
- **跨缓冲区边界处理**：替换器保留上一块尾部 `maxSecretLen-1` 字节拼接匹配，配 fuzz 测试（secret 被任意切分）。
- 密码本身包含 `{{` 等特殊字符不影响脱敏（按精确字节匹配）。

### 7.3 超时与进程树

- Unix：`setpgid` 后 `kill(-pgid, SIGKILL)` 杀整组；Windows：`taskkill /T /F`。
- 超时退出码 124，stderr 提示（不含 secret）。

### 7.4 错误输出规范

所有错误信息只包含：条目名、错误类别、（exec 失败时）占位符版本的命令。任何路径都不得拼接 secret。

---

## 8. 技术选型

| 项 | 选择 | 理由 |
|---|---|---|
| 运行时 | .NET 10（LTS，支持到 2028-11） | 当前 LTS；如企业限制可降 .NET 8 |
| 发布 | `PublishAot=true` + `PublishSingleFile` | 单文件原生二进制，无运行时依赖，启动快 |
| RID 矩阵 | osx-arm64, osx-x64, linux-x64, linux-arm64, win-x64, win-arm64（linux-musl-x64 可选） | 覆盖主流平台 |
| 序列化 | System.Text.Json + source generator | AOT 安全 |
| 参数解析 | 手写（约 200 行） | 命令面小；规避 System.CommandLine 的 AOT/trim 风险 |
| 隐藏输入 | P/Invoke：Unix termios / Win SetConsoleMode（约 100 行） | 零依赖 |
| 第三方依赖 | **v1 零依赖** | AOT/trim 零惊喜；发布物可信面最小 |

**发布**：`dotnet publish -r <rid> -c Release` per 平台 → GitHub Release 附 `SHA256SUMS`；代码签名/公证（macOS）与 Authenticode（Windows）放 M5。

---

## 9. 仓库结构

```
h-password/
├── src/
│   ├── HPass.Core/            # Vault、Crypto、PlaceholderParser、Redactor、ShellLauncher
│   └── HPass.Cli/             # Program.cs、命令分发、隐藏输入 P/Invoke
├── tests/
│   ├── HPass.Core.Tests/      # 单元测试
│   └── HPass.IntegrationTests/ # 真实 shell 矩阵测试（按 OS 条件编译启用）
├── docs/
│   ├── ai-deploy-guide.md     # AI 部署/使用指南（含条目模型与查询接口）✅ 已建
│   ├── threat-model.md        # 威胁模型（防什么/不防什么/加固语义/密码学参数）✅ 已建
│   └── usage.md               # 面向人的使用说明
├── skills/hpass/               # AI Skill（SKILL.md + install.sh），README 有安装说明 ✅ 已建
├── .github/workflows/          # ci.yml（三平台测试+AOT 冒烟）、release.yml
├── LICENSE（MIT）/ README.md   # ✅ 已建
└── PLAN.md
```

---

## 10. 测试与 CI

**单元测试（纯逻辑，跨平台跑）**：
- 占位符解析：空名、未知名、一行多个、嵌套花括号、unicode、`{{`出现在普通文本、字段级占位符（user/tenant/自定义字段、保留字冲突）。
- 脱敏器：secret 任意切分位置的跨块替换（fuzz）、stderr 流、无 secret 时零开销路径。
- 加密：roundtrip、错误口令失败、vault 字段篡改 → GCM 认证失败、条目互换（AAD）失败、KDF 已知向量。

**集成测试（真实 shell，按 OS 启用）**：
- 矩阵：macOS{bash,sh} × Linux{bash,sh,dash} × Windows{pwsh,cmd}。
- 场景：三模式 × 各 shell；argv 干净（env 模式下密码不进 argv；注意 Linux 上 /proc/<pid>/environ 对祖先进程可读，故推荐优先级为脚本 stdin > env > 内联——见 threat-model）；超时杀进程树；退出码透传；`echo {{db}}` 类命令的输出必须已脱敏。
- 加固：用户态进程写 vault 必被拒；提权覆盖流程成功；中断后自动恢复保护；无 sudo / 不支持 `chattr` 的文件系统优雅降级。

**安全回归用例（CI 必须常绿）**：未知占位符拒跑（I2）、输出脱敏（I3）、错误信息无 secret（I5）、vault 拷贝到无钥环境不可解（I4）、用户态写 vault 被拒且不产生半写状态（I6）、list/inspect 输出不含密码与字段值（I1）。

**CI**：GitHub Actions matrix `[macos-latest, ubuntu-latest, windows-latest]`：单测 + `PublishAot` 产物运行 `hpass version` 冒烟。托管 runner 自带 passwordless sudo / 管理员权限，可完整覆盖加固流程测试。

---

## 11. 里程碑（单人开发估算）

| 里程碑 | 内容 | 验收标准 | 状态（2026-09-01） |
|---|---|---|---|
| **M0** 工程底座（1-2 天） | solution、双项目、CI 三平台、AOT 发布管线骨架 | 三平台 AOT 产物可运行 `hpass version` | ✅ 完成（CI 六任务全绿：三平台构建测试 + 三平台 AOT 冒烟） |
| **M1** 保险库（3-5 天） | init/set/inspect/list/delete/rename + 扩展条目模型（类型/账号/租户/自定义字段）+ 全套加密 + 单测（基础权限模式，加固在 M3） | roundtrip 通过；错误口令拒绝；文件权限正确；篡改检测；list/inspect 无密文值泄露 | ✅ 完成（单测 + 集成覆盖，三平台 CI 通过） |
| **M2** 执行引擎（4-6 天） | exec 三模式、shell 矩阵、流式脱敏、env 注入、超时、退出码 | 集成测试矩阵全绿；`echo {{db}}` 输出已脱敏；env 模式 ps 不可见 | ✅ 完成（bash/sh/pwsh 实测 + Windows auto→pwsh 实测修复 .exe 探测 bug；env 注入 argv 干净） |
| **M3** 特权加固（2-4 天） | §5.1 全平台：root/Admin 属主、不可变标志 / ACL、提权原子覆盖、中断恢复、doctor 检测与降级 | 用户态写 vault 必被拒；提权覆盖与恢复流程通过；WSL / 无 sudo 环境优雅降级 | ✅ 完成（vault 唯一写入口 = staged 安装：清保护→原子覆盖→重加保护；用户级 uchg 本地全链路测试；root 属主 + schg/+i 由 CI AOT 冒烟以真实 sudo 验证（自动 `-n` 优先、交互兜底、`_install-staged` 仅搬运密文且有路径白名单）；doctor 清理 staging 残留 + 中断保护自动补齐；提权失败无半写、暂存仅密文；Windows icacls 指引） |
| **M4** 发布与文档（2-3 天） | README/AI 指引随开发完善、threat-model、release workflow（README、LICENSE、AI 部署指南已前置完成） | 三平台二进制 + 校验和发布；新机器 5 分钟上手 | ✅ 完成（ci.yml 三平台全绿含 root 加固流程；threat-model.md 已写；release.yml 于 v* tag 触发，六 RID 产物 + SHA256SUMS 创建 GitHub Release） |
| **M5** 增强（按需） | OS keychain 解锁、agent 常驻、rotate、export/import、MCP server（`hpass mcp` 暴露 `credentialed_exec` 工具）、Argon2id、risky-pattern lint | 按特性单独验收 | ⬜ 按需（rotate 已提前实现并有测试） |

---

## 12. 风险清单

| 风险 | 影响 | 缓解 |
|---|---|---|
| cmd.exe 引号规则 | 高（命令执行错误/注入） | 自研转义器 + 测试矩阵；文档推荐 pwsh |
| 内联模式 ps 可见 | 中 | 主推 env / 脚本 stdin 模式；文档明示 |
| 脱敏被编码变换绕过 | 中 | 威胁模型如实声明"防意外不防恶意"；M4 lint |
| AOT/trim 不兼容 | 低 | v1 零第三方依赖 |
| RSA keygen 慢（低端机） | 低 | 仅 init 一次性，提示 UI |
| 并发写 vault 损坏 | 低 | 独占文件锁 |
| macOS Gatekeeper 拦截 | 中 | M5 签名+公证 / Homebrew 分发 |
| .NET string 残留内存 | 低 | byte[] 优先 + 文档声明 |
| `chattr +i` 文件系统不支持（WSL、容器 overlayfs、网络盘） | 中 | 检测失败自动降级为"仅 root 属主 + 权限"，`doctor` 明示保护等级 |
| Windows UAC 提权子进程交互（新控制台窗口、输出无法直通） | 中 | 提权子进程仅做"密文搬运"，经退出码 + 结果文件回传状态，无需终端交互 |
| sudo 不可用 / 用户无 sudo 权限 | 低 | 优雅降级基础模式并警告；`--no-harden` 显式选择 |

---

## 13. 待确认决策点（默认值已给出，可推翻）

1. CLI 二进制名：**`hpass`**（可换）。
2. 占位符语法：**`{{name}}` / `{{name.user}}`**（备选 `$HPASS_name`）。
3. v1 解锁方式：口令（交互 / 文件 / 环境变量），OS keychain 放 M5 —— 是否需要提前？
4. 是否需要面向人类的取密途径（如 `hpass clip` 复制到剪贴板）？v1 默认**不做**以收紧攻击面。
5. MCP server（`hpass mcp`）是否进 M5 范围？
6. 目标框架：.NET 10（默认）还是 .NET 8（企业约束）？
7. 特权加固默认开启？（推荐 `init` 默认请求提权加固，环境不支持时询问降级；`--no-harden` 显式选择基础模式）

---

## 14. 路线图（M5 之后）

多设备同步（公钥加密天然支持）、条目级授权策略（哪些条目允许被 exec 引用）、审计日志（谁在何时用了哪个条目，不含 secret）、密码轮换提醒、brew/winget/scoop 分发渠道。
