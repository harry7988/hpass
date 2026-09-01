# hpass 威胁模型

> 本文如实声明 hpass 防什么、不防什么。目标是"防密码意外进入 AI 上下文 / 日志 / 备份"，不是对抗已提权的恶意软件。
> 与实现同步维护；行为变化须先改这里。总体设计见 [PLAN.md](../PLAN.md)。

## 1. 资产

| 资产 | 位置 | 保护 |
|---|---|---|
| 密码与自定义字段值（明文） | 仅 hpass 进程内存（byte[]，用后清除） | 生存期最短化；不存在明文落盘路径 |
| vault.json（密文+元数据） | `~/.hpass/vault.json` | AES-256-GCM（AAD 防密文互换）；文件保护（见 §3） |
| master.key（口令加密的 RSA 私钥） | `~/.hpass/master.key` | PBKDF2-SHA512(600k) + AES-256-GCM；600 |
| 主口令 | 用户记忆 / `HPASS_PASSPHRASE[_FILE]` | 不落 vault；文件方式要求权限 600 |
| 脱敏后的命令输出 | stdout/stderr | 即 AI 可见面 |

## 2. 攻击者模型

### A1 意外泄露（主要目标，全防）

密码进入 AI 对话、终端回显、shell history、日志、误提交的文件。

缓解（全部有测试对应）：
- **无明文输出命令**（I1）：不存在 `get/show` 类命令；`list`/`inspect` 只返回元数据（类型/账号/租户/字段名）。
- **未知占位符拒跑**（I2）：预校验条目/字段存在（只查元数据、无需口令），任一未知 → 退出码 4，子进程不启动。
- **输出流式脱敏**（I3）：子进程 stdout/stderr 中出现本次使用的密文 → 跨缓冲区安全地替换回 `{{名}}`。
- **不回显已解析命令**（I5）：错误信息/超时信息只含占位符版本。
- **shell history 只含占位符**：命令由 hpass 直接 spawn；`set` 密码走隐藏输入，禁止 argv 明文。

### A2 静态窃取（全防）

拿到 vault 文件副本（网盘同步、误提交 git、备份泄露）。

- 私钥口令加密存放，vault 单独泄露不可解（I4）。
- 每条 AEAD + AAD 绑定条目名/字段路径 → 局部篡改与条目/字段互换必然认证失败。
- `ps` 短暂可见：仅 args 内联模式存在（密码进子进程 argv）；缓解为主推 env 注入与脚本 stdin 模式（argv 干净）。

### A3 用户态恶意进程（部分防）

与用户同权限的恶意软件/AI 子进程想改 vault。

- **文件保护**（I6）：管理员级 = root 属主 + schg/`chattr +i`；用户级（macOS）= uchg。变更只走
  "清保护 → 原子 rename 覆盖 → 重新加保护"，任何绕过该路径的写入直接失败（EPERM/EACCES）。
- 用户态进程**读**仍可行（密文，无用）；真正机密性仍由口令+私钥保证。
- 读取密码仍需口令 → 恶意进程拿不到私钥（除非口令也在环境里）。

### A4 恶意 AI Agent（部分防，如实声明）

- 被动面：与 A1 相同，全部覆盖（Agent 看到的只有占位符与脱敏输出）。
- **主动绕过**：Agent 构造 `hpass exec -- sh -c 'echo {{db}} | base64'` 之类变换外传 —— 输出脱敏按字节精确匹配，
  编码后即不再匹配，**不防**。这属于恶意软件范畴（Agent 若有网络权，还能直接外传数据）。定位是"防意外，不防恶意"。
- **回显探测（字典攻击）**：Agent 换各种候选语句跑 `echo`，观察哪个被替换成占位符即可确认密码 —— 
  即"替换位置本身是泄露面"。缓解：`exec` 采用**全文共现语义**——同一次调用中"回显原语（echo/printf/Write-Output/puts…）"
  与"密文占位符"共现即拒绝（早期"同语句"规则可被 `x={{db}}; echo cand` 语序绕过）；`--allow-echo` 显式放行。
  代价：`echo 进度 && mysql -p{{db}} …` 这类组合也会被拦，需 --allow-echo。配合 A7 弱密码拦截，使可探测的弱答案无法录入。
- Agent 诱发提权：`_install-staged` 有路径白名单（暂存必须位于 `run/staging` 之下、最终只能是三个 vault 文件），
  不能被当作任意 root 文件搬运工；sudo 密码由用户输入，Agent 无法从 hpass 获取。

### A7 弱密码 = 常见语句（录入源头拦截）

若密码本身是高频文本（如 `select 1`、`connection refused`、`password`），会造成双重危害：
1. 正常输出（日志、SQL 结果）会被大面积误替换成占位符，破坏输出可用性；
2. **被替换的位置直接暴露密码内容** —— 看到日志里哪句变成了 `{{db}}$，就猜到密码是那句。

缓解（分层）：
- **录入拒绝**：`set` 对密码做弱检测（常见口令/常见语句字典整串匹配、长度 <8、纯数字、字符种类 <4、全小写短串），
  命中即拒绝，`--force-weak` 显式覆盖（风险自担）。字段值（如 host=127.0.0.1 这类常见配置）不阻断、仅警告。
- **运行时警告**：exec 统计各密文在输出中的替换次数，单次运行 >32 次时提示"疑似与常见文本碰撞，建议更换强密码"。
- **回显探测拦截**：见 A4。

### A5 root / 管理员（不防，如实声明）

- 可清除任何平台保护标志；拥有机器即拥有一切。AEAD 保证现有条目的局部篡改必然暴露；整体重造 vault 可通过 `hpass list` 察觉条目异常。

### A6 物理与旁路（不防）

- 内存 dump、ptrace、swap、冷启动、键盘记录。内存中解密的 byte[] 用后清除，但 .NET GC/字符串残留属已知残余风险（尽量停留在 byte 层）。

## 3. 特权加固语义（I6）

| 级别 | 触发 | 效果 | 变更路径 |
|---|---|---|---|
| 基础 | `init` 默认 | 目录 700 / 文件 600，原子覆盖写入 | `run/staging` 暂存 → 安装 |
| 用户级 | `harden`（macOS 普通用户） | 核心 vault 文件 uchg 不可变 | 自动：清 uchg → 覆盖 → 复加 uchg（用户态完成） |
| 管理员级 | `sudo hpass harden` | root 属主 440（组对齐 SUDO_USER）+ schg/`chattr +i`；目录 750 | 自动：sudo（先 `-n` 免密再交互）重拉自身执行 `_install-staged`，**只搬运密文**；Windows 走 icacls 指引 |

管理员级补充说明：
- macOS 所有本地用户主组均为共享的 staff，"组对齐"等价于全机本地用户可读密文配对（可离线穷举）；
  如需收窄请配合 FileVault/家目录权限，或等待后续 per-file ACL 支持。Linux 主组通常私有，不受影响。
- `_install-staged` 的 root 路径：暂存目录链（home/run/staging）符号链接拒绝 + 内容结构验证（合法 JSON ≤8MB）
  + 新内容经 O_EXCL 临时名写入后 rename 覆盖（rename 不跟随链接）+ 旧真身转移 `.hpass-orig-*` 复核、
  仅在成功后删除。中断残留的 `.hpass-orig-*` / `.hpass-new-*` 由 doctor 报告（不自动删除——orig 是旧库唯一副本）。
- `--env` 注入同样计入"密文引用"参与回显探测判定（第 2 轮评审堵住的绕过）。

- `exec` 读路径**永不提权**（AI 调用不触发任何系统权限提示）。
- 中断恢复：清保护与复加保护之间被打断 → 文件处于"未保护但完整"状态；`doctor` 检测（部分保护 = 中断态）并清理 `run/staging` 残留（仅密文）、补齐缺失保护。
- 失败不产生半写状态：安装失败时最终文件不变，暂存密文保留供 `sudo _install-staged` 手动搬运。

## 4. 密码学参数

| 项 | 值 |
|---|---|
| 身份密钥 | RSA-3072（OAEP-SHA256 包裹 DEK）——Windows CNG 不支持 X25519，故选全平台一致的 RSA |
| 数据密钥 DEK | 随机 AES-256，仅密文存于 vault |
| 条目加密 | AES-256-GCM，nonce 96bit，AAD=`条目名\|字段路径`（密码路径为 `\x01password`） |
| 口令派生 | PBKDF2-HMAC-SHA512，600,000 迭代（OWASP 现行推荐；旧 vault 按各自存储值解，兼容），16B 盐（Argon2id 列为后续项） |
| 随机数 | `RandomNumberGenerator`（CSPRNG） |

## 5. 已知残余风险清单

1. args 内联模式下密码在子进程运行期间 `ps` 可见（文档明示，主推 env/脚本模式）。
2. 编码变换可绕过输出脱敏（A4，定位外）。
3. root 管理员全权（A5）。
4. `HPASS_PASSPHRASE` 环境变量方式可被同用户进程读取（自动化便利与安全的折中；推荐 `HPASS_PASSPHRASE_FILE` 600 权限文件）。
5. .NET 运行时内存残留（byte[] 清除已做，string 场景最小化）。
6. cmd.exe 的引号语义特殊，路径复杂时建议 pwsh。
7. 回显探测拦截是**启发式**（全文共现正则）：不覆盖全部编程语言的输出原语，
   也无法阻止 Agent 通过其他方式差分输出（如把命令结果写文件再读）；弱密码字典不可能是完备的。
   两道防线叠加显著抬高门槛，但不做完备性承诺。
8. 非回显的原样外传（如 `tee`/重定向到文件后读取）仍会把密文行替换为占位符 —— 这是预期行为（脱敏始终生效）。
9. **env 注入与 /proc**：`--env db:MYSQL_PWD` 把密码放进子进程环境；Linux 上祖先进程（驱动 hpass 的 AI shell）
   可经 `/proc/<pid>/environ` 读到（yama ptrace_scope=1 不拦祖先）。argv 之外唯一同时避开 argv 与 environ 的模式是
   **脚本 stdin**——优先级应为：脚本 stdin > env 注入 > args 内联。
10. **孤儿进程逃逸**：超时杀进程采用"独立进程组 + kill(-pgid)"与 Kill(entireProcessTree) 双保险，但 double-fork /
    被 init 收养的后代仍可能逃逸并携带注入的环境密文继续运行。
11. **rotate 的跨文件原子性**：vault.json 与 master.key 是两次独立安装；rotate 前自动把当前配对备份到
    `run/rotate-backup.*`，中断导致新旧失配时可据此恢复（Unlock 失败的错误信息会提示）。
12. **Windows ACL**：hpass 在 Windows 上不做程序化 ACL 收紧（harden 输出 icacls 指引）；--home 指向宽松 ACL
    目录时元数据与密文可能对组/其他用户可读。
13. root 安装路径的防御为：暂存目录链 symlink 检查 + 内容结构验证（合法 JSON）+ O_EXCL 临时名 + rename 覆盖
    （不跟随链接）+ 操作后复核。同 UID 恶意进程仍可竞争覆写暂存（安装出"结构合法"的伪造库）——属已声明的
    同 UID DoS/伪造面，root 属主校验仅收窄跨用户伪造。
14b. 并发写互斥 = 裸 open + flock 限时排队（60s，超时报"稍后重试"）；.NET 的 FileShare/Access 在 Unix 上
     会被模拟为排他 fcntl（并发 open 即冲突、无等待），故锁文件不走托管 FileStream（Windows 除外）。
14c. root 直接运行（su / root-shell，SUDO_USER 缺失或为 root）时：目录与文件均不改变属主，仅收紧权限 + 不可变
     （找不到可对齐的真实用户；chown root:root 会把用户自己的库锁死）。此时文件为 444——密文对本地用户可读
     属既定回退（见 macOS staff 条目）。
14d. 不支持 chattr/chflags 的文件系统（overlayfs/tmpfs/NFS 等）上不可变标志自动降级（安装不阻断，
     保护等级由 doctor/GetLevel 如实报告）。
14. `config.json`（用户可写）中的 DefaultShell 已白名单化（仅 auto/bash/sh/pwsh/cmd/none），任意可执行路径只能经
    用户亲自输入的 `--shell` 指定。
15. 孙进程持有 stdout 管道时，正常退出路径最多再等 10s 后输出尾部可能被截断（数据丢失面，非泄露面）。
16. rotate 备份 `run/rotate-backup.*`（600）保留至下次 rotate 覆盖；与当前库同口令加密，泄露面等价于密文本身。
17. **shell 元字符变体**：密文含 `"`/`'`/`$`/反引号/`\` 且占位符经嵌套 shell（`sh -c "… {{db}} …"`）或脚本 stdin
    模式时，二级 shell 会把密文解析成去引号/分词/展开后的变体——字节精确脱敏对变体失配，变体或碎片可能进入输出。
    缓解：exec 检测到该组合时输出警告；**含元字符的密文应一律用 `--env` 注入**（值经环境传递、不经 shell 解析，免疫）。
18. **home 整体偷换**（Linux 已用 inode 快照复核关键操作；macOS 依赖 O_NOFOLLOW+前置校验）：多用户 + NOPASSWD +
    毫秒级竞态的组合场景下，root 安装/harden 的文件操作理论上仍可被重定向到他用户 vault（跨用户完整性破坏，无
    机密性收益）——属同 UID 竞争面在多用户环境的延伸。
