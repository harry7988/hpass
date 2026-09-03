namespace PwHide.Core;

/// <summary>
/// zh→en 消息表（Loc.Tr 使用）。条目格式 "zh||en"：zh 侧含 * 者为通配模板（* 数量两侧一致，动态段原样保留）。
/// 维护规则：新增用户可见中文消息时同步补一条；en 模式的"输出无 CJK"测试电池会抓漏。
/// </summary>
public static partial class Loc
{
    private static readonly string[] Raw =
    [
        // ---------- CliRunner / Program ----------
        "用法：pwhide <init|set|list|inspect|delete|rename|exec|verify|rotate|harden|doctor|language|version> [选项]||usage: pwhide <init|set|list|inspect|delete|rename|exec|verify|rotate|harden|doctor|language|version> [options]",
        "未知命令：*||unknown command: *",
        "*录入/更新条目（密码隐藏输入）||*create/update an entry (hidden password input)",

        // ---------- GetPassphrase / 口令 ----------
        "主口令: ||master passphrase: ",
        "主口令（--verify 手输）: ||master passphrase (--verify, type it): ",
        "再次确认: ||confirm again: ",
        "两次输入不一致||passphrases do not match",
        "口令至少需要 8 个字符||passphrase must be at least 8 characters",
        "口令至少需要 8 个字符（env/文件方式与交互输入执行同一标准）||passphrase must be at least 8 characters (same rule for env/file/interactive)",
        "口令过长（>1024 字符），拒绝使用||passphrase too long (>1024 chars), rejected",
        "需要主口令解锁 vault（交互输入，或设置 PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE）||vault locked: master passphrase required (interactive input, or set PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE)",
        "非交互环境需要解锁：请设置 PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE，或先运行 pwhide keychain set 存入系统钥匙串||non-interactive unlock required: set PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE, or run `pwhide keychain set` once to store it in the OS keychain",
        "pwhide: 警告：口令文件 * 对组/其他用户可读（主口令泄露=库可离线穷举），建议 chmod 600||pwhide: warning: passphrase file * is group/world-readable (a leaked passphrase allows offline brute force); chmod 600 recommended",

        // ---------- init / set ----------
        "vault 已存在（*）。如需重置请先手动删除该目录||vault already exists (*); delete the directory manually if you really want to reset",
        "已初始化：*||initialized: *",
        "文件保护：基础模式（目录 700 / 文件 600）。可随时运行 pwhide harden 升级为管理员写保护||file protection: basic mode (dir 700 / file 600). run `pwhide harden` anytime to upgrade to admin write-protection",
        "文件保护：基础模式（目录 700 / 文件 600）。可运行 pwhide harden 启用管理员写保护（仅整体覆盖）||file protection: basic mode (dir 700 / file 600). run `pwhide harden` for admin write-protection (whole-file overwrite only)",
        "-t 需要 <类型>||-t requires <type>",
        "-u 需要 <账号>||-u requires <username>",
        "-T 需要 <租户>||-T requires <tenant>",
        "-f 需要 <字段名=值> 或 <字段名>（隐藏输入）||-f requires <field=value> or <field> (hidden input)",
        "-pf 需要 <字段名=值>（明文字段必须显式给值）||-pf requires <field=value> (plain fields need an explicit value)",
        "-pf 需要 <字段名=值>（收到 *）||-pf requires <field=value> (got *)",
        "set：无法识别的参数 *||set: unrecognized argument *",
        "同一字段名不能重复指定（-f 与 -pf 同名也不行：加密/明文二选一）||duplicate field name (also across -f and -pf): encrypted/plain is mutually exclusive per field",
        "用法：pwhide set <名> [-t 类型] [-u 账号] [-T 租户] [-f 字段=值]… [-pf 明文字段=值]… [--password-stdin] [--force-weak]||usage: pwhide set <name> [-t type] [-u user] [-T tenant] [-f field=value]... [-pf plain=value]... [--password-stdin] [--force-weak]",
        "--password-stdin：未从 stdin 读到密码（或内容全是空白）||--password-stdin: no password read from stdin (or whitespace only)",
        "--password-stdin：未从 stdin 读到密码||--password-stdin: no password read from stdin",
        "密码（*）: ||password (*): ",
        "非交互环境请使用 --password-stdin 从 stdin 提供密码（禁止命令行明文传密码）||non-interactive: provide the password via --password-stdin (plaintext password on the command line is forbidden)",
        "密码不能为空||password cannot be empty",
        "拒绝保存弱密码：*。如确要使用请追加 --force-weak（风险自担：输出中的常见文本会被大面积误替换为占位符，并可被据此推测）||refusing weak password: *. append --force-weak to override at your own risk (common texts in output would be massively mis-redacted and could be inferred)",
        "字段 * 的值: ||value of field *: ",
        "非交互环境请用 -f *=<值> 提供字段值||non-interactive: provide the value as -f *=<value>",
        "字段 * 是否敏感、需要加密存储？[Y/n] ||is field * sensitive and should be encrypted? [Y/n] ",
        "字段 * 是否敏感、需要加密存储？[y/N] ||is field * sensitive and should be encrypted? [y/N] ",
        "字段 * 的值不能为空（首尾空白已清除后仍为空）||value of field * cannot be empty (still empty after trimming)",
        "字段 * 的值不能为空||value of field * cannot be empty",
        "pwhide: 警告：字段 * 形似敏感字段，命令行传值会进入 shell history——建议改用交互隐藏输入（pwhide set … -f *）||pwhide: warning: field * looks sensitive; passing it on the command line stores it in shell history - prefer hidden interactive input (pwhide set ... -f *)",
        "pwhide: 警告：字段 * 的值*；作为密文注入时可能与正常输出碰撞，请确认||pwhide: warning: value of field **; when injected as a secret it may collide with normal output, please double-check",
        "已保存条目 *（* 个条目）||saved entry * (* entries total)",
        "字段名 * 为保留字，不能用作自定义字段||field name * is reserved and cannot be used as a custom field",

        // ---------- list / inspect / verify 显示 ----------
        "（vault 为空，用 pwhide set <名> 录入）||(vault is empty; add entries with `pwhide set <name>`)",
        "名称||name", "类型||type", "账号||user", "租户||tenant",
        "--verify 与 --json 不能同时使用（--verify 为人类交互验证通道，输出为终端文本）||--verify and --json cannot be combined (--verify is the human interactive channel and prints terminal text)",
        "用法：pwhide inspect <名> [--json] [--verify（人工核验：需交互终端手输主口令，解密显示密码与字段）]||usage: pwhide inspect <name> [--json] [--verify (human check: interactive terminal, typed passphrase, decrypted display)]",
        "条目不存在：*||entry not found: *",
        "用法：pwhide verify <名>（人工核验：需交互终端手输主口令，解密显示密码与字段）||usage: pwhide verify <name> (human check: interactive terminal, typed passphrase, decrypted display)",
        "--verify 需要在真实交互终端运行并手动输入主口令（当前为非交互或 stdin/stdout 被重定向——这是防止密文进入 AI 上下文/日志/管道的硬性限制）||--verify requires a real interactive terminal and a hand-typed master passphrase (non-interactive, or stdin/stdout redirected - hard limit that keeps secrets out of AI context/logs/pipes)",
        "verify 需要在真实交互终端运行并手动输入主口令（当前为非交互或 stdin/stdout 被重定向——这是防止密文进入 AI 上下文/日志/管道的硬性限制）||verify requires a real interactive terminal and a hand-typed master passphrase (non-interactive, or stdin/stdout redirected - hard limit that keeps secrets out of AI context/logs/pipes)",
        "条目 *（类型 *）  [verify 解密显示，仅限本人终端，请勿截图/粘贴给 AI]||entry * (type *)  [verify decrypted display - your own terminal only; do not screenshot or paste to an AI]",
        "账号: *    租户: *||user: *    tenant: *",
        "密码: *||password: *",
        "密码: （未设置）||password: (not set)",
        "未设置||(not set)",
        "明文字段（非敏感，元数据可见）: ||plain fields (non-sensitive, visible in metadata): ",
        "明文字段 * = *||plain field * = *",
        "加密字段 * = *||encrypted field * = *",
        "可用占位符:||available placeholders:",
        "已删除 *||deleted *",
        "用法：pwhide delete <名>||usage: pwhide delete <name>",
        "已重命名 * → *||renamed * -> *",
        "用法：pwhide rename <旧名> <新名>||usage: pwhide rename <old> <new>",
        "已更换身份密钥对（DEK 未变，条目无需重加密）||identity key pair rotated (DEK unchanged; entries need no re-encryption)",
        "未找到 vault（*），请先 pwhide init||vault not found (*); run pwhide init first",
        "未找到 vault（*）。请先运行 pwhide init||vault not found (*); run pwhide init first",
        "vault.json 解析失败，文件可能损坏||vault.json failed to parse; file may be corrupted",
        "master.key 解析失败，文件可能损坏||master.key failed to parse; file may be corrupted",
        "；若刚执行过被中断的 rotate（master.key 与 vault.json 失配），可用 run/rotate-backup.* 恢复原配对后重试||; if a rotate was just interrupted (master.key/vault.json mismatch), restore run/rotate-backup.* and retry",

        // ---------- exec ----------
        "--shell 需要 shell 名||--shell requires a shell name",
        "--ph 需要 # 或 @||--ph requires # or @",
        "--timeout 需要正整数秒数||--timeout requires a positive number of seconds",
        "--env 需要 <条目名>:<环境变量名>||--env requires <entry>:<ENVVAR>",
        "--env 格式应为 条目名:环境变量名（收到 *）||--env format is entry:ENVVAR (got *)",
        "--env 环境变量名非法：*||--env invalid environment variable name: *",
        "--env 不能注入保留变量：*||--env cannot inject reserved variable: *",
        "--env 重复的环境变量（不区分大小写）：*||--env duplicate environment variable (case-insensitive): *",
        "-f 需要 <脚本路径>||-f requires <script path>",
        "脚本不存在：*||script not found: *",
        "未知的 pwhide 选项：*（命令自身的选项请放在 -- 之后）||unknown pwhide option: * (put the command's own options after --)",
        "缺少要执行的命令（pwhide exec [--] <命令…> 或 -f <脚本>）||missing command (pwhide exec [--] <cmd...> or -f <script>)",
        "缺少要执行的命令（pwhide exec [-- 参数…] 或 -f 脚本）||missing command (pwhide exec [-- args...] or -f script)",
        "不能同时指定 -f 脚本与命令参数（多余部分会被忽略，已拒绝）||cannot combine -f script with command arguments (extras would be silently ignored; rejected)",
        "--ph 仅支持 # 或 @（收到 *）；不指定时默认语法为 {{name}}||--ph supports only # or @ (got *); default syntax is {{name}}",
        "* 尚未设置密码||* has no password set",
        "* 未设置账号（user）||* has no username (user) set",
        "* 未设置租户（tenant）||* has no tenant set",
        "条目 * 不存在字段 *||entry * has no field *",
        "占位符未被预解析（内部错误）||placeholder was not pre-resolved (internal error)",
        "检测到回显命令与密文占位符（*）在同一次调用中共现。回显 + 已激活的脱敏规则可被逐候选探测出密码内容（输出被替换成占位符 ⟺ 候选即密码）。如确属正常用途（如回显进度同时使用密码），请追加 --allow-echo 确认放行。||an echo primitive and a secret placeholder (*) co-occur in one invocation. Echo plus active redaction rules enables candidate-by-candidate password probing (output replaced by the placeholder iff the candidate equals the password). For legitimate uses (echoing progress while using a password), add --allow-echo to allow it.",
        "pwhide: 警告：* 的值包含 shell 元字符（引号/美元/反引号/反斜杠），经 shell 解析可能产生变体绕过输出脱敏（cmd 还含 & | < > ^）——建议改用 --env 注入（值不经 shell 解析）||pwhide: warning: value of * contains shell metacharacters (quotes/dollar/backtick/backslash); shell parsing may produce variants that bypass output redaction (cmd also has & | < > ^) - prefer --env injection (value never parsed by the shell)",
        "--verify 执行前核对（已解密，仅限本人终端，请勿截图/粘贴给 AI）：||--verify pre-exec check (decrypted; your own terminal only; do not screenshot or paste to an AI):",
        "将执行：||will execute:",
        "涉及密文（将注入子进程；执行输出仍自动脱敏回占位符）：||secrets involved (injected into the child; execution output is still auto-redacted to placeholders):",
        "确认执行？||confirm execution?",
        "确认执行？ [y/N] ||confirm execution? [y/N] ",
        "已取消（未执行）||cancelled (nothing executed)",
        "pwhide: 执行超时（*s），已终止进程树||pwhide: timed out (*s); process tree killed",
        "pwhide: 警告：* 在输出中出现 * 次已被脱敏——该密码疑似与常见文本碰撞（既破坏输出，也可能被据此推测），建议更换强密码：pwhide set *||pwhide: warning: * was redacted * times in output - this password likely collides with common text (breaks output and can be inferred); consider a stronger one: pwhide set *",

        // ---------- ShellLauncher / 子进程 ----------
        "cmd 仅在 Windows 可用||cmd is only available on Windows",
        "找不到 shell：*（可用 --shell 指定 bash/sh/pwsh/cmd，或 --shell none 直连执行）||shell not found: * (set --shell bash/sh/pwsh/cmd, or --shell none to exec directly)",
        "未探测到可用 shell，请用 --shell 显式指定||no usable shell detected; set --shell explicitly",
        "脚本模式必须由调用方一次读入内容（ScriptText）；按路径二次读取会重新引入 TOCTOU||script mode requires the caller to read content once (ScriptText); re-reading by path reintroduces TOCTOU",
        "脚本模式需要 shell（--shell auto|bash|sh|pwsh）||script mode needs a shell (--shell auto|bash|sh|pwsh)",
        "cmd 不支持脚本 stdin 模式，请改用 pwsh（--shell pwsh）||cmd has no script-stdin mode; use pwsh (--shell pwsh)",
        "Windows PowerShell 5.1 的 stdin 按 OEM 代码页解码，会改写非 ASCII 密文导致脱敏失配——请安装 pwsh 7+（--shell pwsh）||Windows PowerShell 5.1 decodes stdin with the OEM code page and rewrites non-ASCII secrets, breaking redaction - install pwsh 7+ (--shell pwsh)",
        "命令未在 PATH 中找到（拒绝当前目录命中，防可执行文件种植）；命令可能不存在、未安装，或首参数不是命令名||command not found on PATH (CWD hits rejected to prevent executable planting); it may not exist, not be installed, or the first argument is not a command name",
        "无法启动子进程（命令不存在或不可执行）||failed to start child process (command missing or not executable)",
        "解密失败：数据被篡改，或口令/密钥不正确||decryption failed: data tampered, or wrong passphrase/key",
        "密文长度非法，数据可能已损坏||invalid ciphertext length; data may be corrupted",

        // ---------- WeakSecret ----------
        "长度不足 8 个字符||shorter than 8 characters",
        "纯数字||digits only",
        "字符种类过少（少于 4 种）||too few character classes (fewer than 4)",
        "全小写字母且过短||all lowercase and too short",
        "属于常见口令/常见语句（会与正常输出碰撞，且替换位置会暴露密码内容）||matches a common password/common phrase (collides with normal output and leaks content via redaction positions)",

        // ---------- doctor ----------
        "home     : *||home     : *",
        "platform : *||platform : *",
        "未知的 doctor 选项：*||unknown doctor option: *",
        "--output-encoding 需要 <auto|utf8|utf16|gbk|json>||--output-encoding requires <auto|utf8|utf16|gbk|json>",
        "无效的输出编码：*（可用 auto|utf8|utf16|gbk|json；json = 非 ASCII 转义为 \\uXXXX，任何终端可读）||invalid output encoding: * (allowed auto|utf8|utf16|gbk|json; json escapes non-ASCII to \\uXXXX, readable on any terminal)",
        "输出编码 : 已全局指定为 *（*，对所有 pwhide 命令生效；删除该文件或改回 auto 恢复自动检测）||output encoding : globally set to * (*; applies to every pwhide command; delete the file or set auto to restore detection)",
        "安装残留 : *（特权安装被中断的产物；orig 为旧库唯一副本，可用 sudo 手动改名恢复，切勿先 init 覆盖）||install leftover : * (from an interrupted privileged install; orig is the only copy of the old vault - restore it manually with sudo, never init over it)",
        "中断残留 : 已清理 * 个未安装的暂存文件（run/staging，仅密文）||interrupted leftovers : cleaned * uninstalled staging files (run/staging, ciphertext only)",
        "vault    : 正常（* 个条目，元数据可查）||vault    : ok (* entries, metadata readable)",
        "目录权限 : *（建议 700）||dir perms : * (700 recommended)",
        "目录权限 : 700（符合预期）||dir perms : 700 (as expected)",
        "目录权限 : Windows ACL（建议 Administrators/SYSTEM 完全控制、当前用户读写）||dir perms : Windows ACL (Administrators/SYSTEM full control, current user read/write recommended)",
        "vault    : 文件缺失，但存在 *.pwhide-orig-* 残留（旧库唯一副本）——请先恢复再考虑 init||vault    : file missing but *.pwhide-orig-* leftovers exist (only copy of the old vault) - restore before any init",
        "vault    : 未初始化（pwhide init）||vault    : not initialized (pwhide init)",
        "保护状态 : 已加固（*）：密码文件只可整体覆盖||protection : hardened (*); secret files can only be replaced wholesale",
        "保护状态 : 中断的加固（部分文件受保护）→ ||protection : interrupted hardening (some files protected) -> ",
        "已自动修复（管理员级）||auto-repaired (admin level)",
        "已自动补齐用户级不可变（uchg）；管理员级请 sudo pwhide harden||user-level immutable flag (uchg) auto-restored; run sudo pwhide harden for admin level",
        "保护状态 : 基础模式（700/600）。可运行 pwhide harden 启用不可变写保护||protection : basic mode (700/600). run `pwhide harden` to enable immutable write-protection",
        "shell    : auto → *||shell    : auto -> *",

        // ---------- 输出通道 / 编码 ----------
        "环境变量 *=* 无效（可用 auto|utf8|utf16|gbk|json），已忽略||environment variable *=* invalid (allowed auto|utf8|utf16|gbk|json), ignored",
        "环境变量 *=*||environment variable *=*",
        "配置文件 *：*||config file *: *",
        "配置文件 * 内容无效，已忽略||config file * invalid, ignored",
        "自动||auto",
        "输出编码 : *||output encoding : *",
        "输出通道 : 手工指定（*）||output channel : manual (*)",
        "输出通道 : UTF-8（非 Windows 恒 UTF-8）||output channel : UTF-8 (always UTF-8 outside Windows)",
        "控制台 → WriteConsoleW 直写（与代码页无关）||console -> WriteConsoleW direct (codepage-independent)",
        "管道 → 按控制台代码页 * 转码（PowerShell 按 [Console]::OutputEncoding 解码）||pipe -> transcoded by console codepage * (PowerShell decodes with [Console]::OutputEncoding)",
        "管道 → UTF-8（无控制台会话，无法取代码页）||pipe -> UTF-8 (no console session, codepage unavailable)",
        "文件重定向 → UTF-8||file redirect -> UTF-8",
        "输出通道 : *||output channel : *",

        // ---------- keychain ----------
        "平台支持 : *||platform support : *",
        "当前状态 : 已通过 PWHIDE_NO_KEYCHAIN=1 禁用钥匙串来源||status : keychain source disabled via PWHIDE_NO_KEYCHAIN=1",
        "当前状态 : 不可用（见上）||status : unavailable (see above)",
        "当前状态 : 已存储主口令（exec/set 自动取用，零交互）||status : master passphrase stored (exec/set pick it up automatically, zero interaction)",
        "当前状态 : 未存储。运行 pwhide keychain set 配置（配置后 exec 无需再输口令）||status : not stored. run `pwhide keychain set` once (afterwards exec needs no passphrase)",
        "未知的 keychain 子命令：*（可用 set / clear / status）||unknown keychain subcommand: * (set / clear / status)",
        "当前平台钥匙串不可用：*。替代方案：PWHIDE_PASSPHRASE_FILE（chmod 600）||keychain unavailable on this platform: *. alternative: PWHIDE_PASSPHRASE_FILE (chmod 600)",
        "vault 不存在（*）。请先 pwhide init，再 keychain set||vault not found (*); run pwhide init first, then keychain set",
        "非交互环境请用 PWHIDE_PASSPHRASE=<主口令> pwhide keychain set 完成一次配置||non-interactive: configure once with PWHIDE_PASSPHRASE=<master> pwhide keychain set",
        "已存入 *（槽位绑定 *）。之后 exec/set 等命令将自动取用，无需再输口令||stored in * (slot bound to *). exec/set and friends now pick it up automatically",
        "撤销：pwhide keychain clear；临时跳过：PWHIDE_NO_KEYCHAIN=1||undo: pwhide keychain clear; temporary bypass: PWHIDE_NO_KEYCHAIN=1",
        "已从钥匙串删除主口令||master passphrase removed from keychain",
        "钥匙串中没有已存储的主口令（无需清理）||no stored master passphrase in keychain (nothing to clean)",
        "macOS Keychain（/usr/bin/security）||macOS Keychain (/usr/bin/security)",
        "Windows 凭据管理器||Windows Credential Manager",
        "Linux Secret Service（secret-tool）||Linux Secret Service (secret-tool)",
        "当前平台不可用（Linux 需安装 secret-tool / libsecret）||unavailable on this platform (Linux needs secret-tool / libsecret)",
        "当前平台无钥匙串支持：Linux 需安装 secret-tool（libsecret-tools）；或改用 PWHIDE_PASSPHRASE_FILE（chmod 600）||no keychain support on this platform: Linux needs secret-tool (libsecret-tools); alternatively use PWHIDE_PASSPHRASE_FILE (chmod 600)",
        "写入钥匙串失败（exit *）：*。可改用 PWHIDE_PASSPHRASE_FILE（chmod 600）||keychain write failed (exit *): *. alternatively use PWHIDE_PASSPHRASE_FILE (chmod 600)",
        "写入 Windows 凭据管理器失败（Win32 *）||Windows Credential Manager write failed (Win32 *)",

        // ---------- 加固 / 特权 / SecureFile（高频路径） ----------
        "vault 处于管理员写保护。请手动执行：sudo pwhide --home * …||vault is admin write-protected. run manually: sudo pwhide --home * ...",
        "Windows：文件 ACL 拒写，请以管理员重新运行本命令（pwhide harden 输出含 icacls 指引）||Windows: file ACL denies writes; rerun this command as administrator (pwhide harden prints icacls guidance)",
        "已加固（管理员级）：root 属主 + 不可变标志（schg / chattr +i），密码文件只可整体覆盖。||hardened (admin): root-owned + immutable flag (schg / chattr +i); secret files can only be replaced wholesale.",
        "exec 读路径无需提权；后续 set/delete/rename/rotate 会自动经 sudo 搬运安装（也可手动：sudo pwhide --home * …）||exec needs no elevation; later set/delete/rename/rotate automatically install via sudo (or manually: sudo pwhide --home * ...)",
        "已加固（用户级 uchg 不可变）：文件只能整体覆盖（pwhide 内部自动清/复加）。||hardened (user-level uchg immutable): files can only be replaced wholesale (pwhide clears/reapplies internally).",
        "升级为管理员级（root 属主 + schg）：sudo pwhide --home * harden||upgrade to admin level (root-owned + schg): sudo pwhide --home * harden",
        "将以 sudo 重新执行加固（root 属主 + chattr +i）…||re-running harden with sudo (root-owned + chattr +i)...",
        "pwhide: 即将请求 sudo 密码执行加固（目标为上述 vault 目录）||pwhide: about to ask for the sudo password to harden (target: the vault directory above)",
        "加固已启用||hardening enabled",
        "已加固（管理员级，经 sudo -n）：root 属主 + 不可变标志，密码文件只可整体覆盖。||hardened (admin, via sudo -n): root-owned + immutable; secret files can only be replaced wholesale.",
        "pwhide: 非交互环境未能完成加固（Linux 普通用户无法 chattr 且 sudo -n 不可用）。请手动运行：sudo pwhide --home * harden||pwhide: could not finish hardening non-interactively (a normal Linux user cannot chattr and sudo -n unavailable). run manually: sudo pwhide --home * harden",
        "pwhide: 即将请求 sudo 密码以安装 vault 变更（仅搬运密文，目标为上述 vault 文件）||pwhide: about to ask for the sudo password to install vault changes (ciphertext relocation only; targets are the vault files above)",
        "（当前环境已禁用自动 sudo）||(auto sudo disabled in this environment)",
        "（无法定位 pwhide 可执行文件）||(cannot locate the pwhide executable)",
        "pwhide: 未找到 sudo（/usr/bin/sudo）。||pwhide: sudo not found (/usr/bin/sudo).",
        "pwhide: 未找到 sudo（/usr/bin/sudo）。请手动执行：sudo pwhide --home * harden||pwhide: sudo not found (/usr/bin/sudo). run manually: sudo pwhide --home * harden",
        "pwhide: 二进制位于不受信任路径（*，用户可写位置），不自动提权。请手动执行：sudo pwhide --home * harden（请亲眼核对 sudo 目标）||pwhide: binary is at an untrusted path (*, user-writable); not auto-elevating. run manually: sudo pwhide --home * harden (verify the sudo target yourself)",
        "Windows 平台：请以管理员运行以下命令设置 ACL（用户只读，Administrators/SYSTEM 完全控制）：||Windows: run the following as administrator to set the ACL (user read-only, Administrators/SYSTEM full control):",
        "无法关闭终端回显（/bin/stty 失败）。为防口令明文回显，拒绝在此终端读取口令：请改用 PWHIDE_PASSPHRASE_FILE（chmod 600）或在常规终端运行||cannot disable terminal echo (/bin/stty failed); refusing to read the passphrase here to avoid echoing it: use PWHIDE_PASSPHRASE_FILE (chmod 600) or a regular terminal",
        "另一个 pwhide 写操作长时间未完成（等待 60s 未能获得锁），请稍后重试||another pwhide write is taking too long (could not acquire the lock within 60s); retry later",
        "另一个 pwhide 写操作正在进行（run/lock 被占用）||another pwhide write is in progress (run/lock held)",
        "run/lock 无法访问（属主异常，多为 sudo 运行遗留）：可删除 * 后重试，或再运行一次 sudo 命令由其自动归还属主||run/lock inaccessible (odd owner, usually sudo leftovers): delete * and retry, or rerun a sudo command to hand ownership back",
        "* * 非法：仅允许字母/数字/下划线/连字符，以字母或数字开头，长度 1-64（'.' 为占位符分隔符，不允许出现在名字中）||invalid * *: only letters/digits/underscore/hyphen, starting with a letter or digit, length 1-64 ('.' is the placeholder separator and not allowed in names)",

        "*pwhide — 本地密码代填执行器（密码只进进程，不出终端）||*pwhide - local password proxy executor (secrets go into processes, never onto your terminal)",
        "*全局手工指定输出编码（乱码兜底）||*globally force the output encoding (mojibake fallback)",
        "*--ph #|@（占位符定界符，默认 {{name}}；脚本中 # 与注释冲突时用 @）||*--ph #|@ (placeholder delimiters, default {{name}}; prefer @ in scripts with # comments)",
        "*--verify（执行前人工核对：需交互终端手输主口令，展示解密值并确认）||*--verify (pre-exec human check: interactive terminal, typed passphrase, decrypted values shown)",
        "*pwhide init [--no-harden]                 初始化 vault（设置主口令）||*pwhide init [--no-harden]                 initialize the vault (set master passphrase)",
        "*pwhide set <名> [-t 类型] [-u 账号] [-T 租户] [-f 字段=值]… [-pf 明文字段=值]… [--password-stdin]||*pwhide set <name> [-t type] [-u user] [-T tenant] [-f field=value]... [-pf plain-field=value]... [--password-stdin]",
        "*pwhide list [--json]                      列出条目元数据（不含密文值）||*pwhide list [--json]                      list entry metadata (no secret values)",
        "*pwhide inspect <名> [--json] [--verify]    元数据与占位符；--verify 人工核验（解密显示）||*pwhide inspect <name> [--json] [--verify]  metadata and placeholders; --verify human check (decrypted display)",
        "*pwhide delete <名> / rename <旧> <新>     管理条目||*pwhide delete <name> / rename <old> <new>  manage entries",
        "*pwhide exec [选项] -- <命令…>             填充+执行+脱敏||*pwhide exec [options] -- <cmd...>         fill + execute + redact",
        "*pwhide exec [选项] -f <脚本>              脚本 stdin 模式（不落盘）||*pwhide exec [options] -f <script>         script-stdin mode (nothing written to disk)",
        "*pwhide rotate                             更换身份密钥对||*pwhide rotate                             rotate the identity key pair",
        "*pwhide verify <名>                        人工核验：解密显示密码/字段（需终端手输主口令）||*pwhide verify <name>                      human check: decrypted password/fields (terminal, typed passphrase)",
        "*pwhide keychain set|clear|status          主口令存入系统钥匙串（配置后 exec 零交互）||*pwhide keychain set|clear|status          store the passphrase in the OS keychain (exec then needs none)",
        "*pwhide language en|zh                      界面语言（默认英文；PWHIDE_LANG 可覆盖）||*pwhide language en|zh                      UI language (English default; PWHIDE_LANG overrides)",
        "*exec 选项：--shell auto|bash|sh|pwsh|cmd|none  --env 条目:环境变量(可重复)||*exec options: --shell auto|bash|sh|pwsh|cmd|none  --env entry:ENVVAR (repeatable)",
        "*--timeout 秒(默认120)  --allow-echo(放行回显探测拦截)  --home <目录>||*--timeout seconds (default 120)  --allow-echo (allow echo-probe)  --home <dir>",
        "*环境变量：PWHIDE_HOME / PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE / PWHIDE_OUTPUT_ENCODING / PWHIDE_NO_KEYCHAIN||*environment: PWHIDE_HOME / PWHIDE_PASSPHRASE / PWHIDE_PASSPHRASE_FILE / PWHIDE_OUTPUT_ENCODING / PWHIDE_NO_KEYCHAIN",
        "名称: *||name: *",
        "类型: *    账号: *    租户: *||type: *    user: *    tenant: *",
        "密码: 已设置（只能经 {{*}} 注入）||password: set (injected only via {{*}})",
        "明文字段（非敏感，元数据可见）: *||plain fields (non-sensitive, visible in metadata): *",
        // ---------- language 命令（自身消息在 Commands 内用 Loc.T 双语直出） ----------
    ];

    public static readonly Dictionary<string, string> Table;
    private static readonly List<(string Pattern, string En)> Wildcards;

    static Loc()
    {
        Table = [];
        Wildcards = [];
        foreach (var raw in Raw)
        {
            var i = raw.IndexOf("||", StringComparison.Ordinal);
            if (i < 0) continue;
            var zh = raw[..i];
            var en = raw[(i + 2)..];
            if (zh.Contains('*')) Wildcards.Add((zh, en));
            else Table[zh] = en;
        }
        // 通配模板按最长键优先，避免短前缀模板误吃长消息
        Wildcards.Sort((a, b) => b.Pattern.Length.CompareTo(a.Pattern.Length));
    }
}
