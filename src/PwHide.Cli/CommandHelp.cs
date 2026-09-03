using PwHide.Core;

namespace PwHide.Cli;

/// <summary>
/// 每命令帮助（-h / --help / pwhide help &lt;cmd&gt;）。文案用 Loc.T 双语直出（不进翻译表）。
/// 结构统一：用途一句话 → 用法 → 选项 → 示例 → 下一步。
/// </summary>
internal static class CommandHelp
{
    public static bool Has(string cmd) => Texts.ContainsKey(cmd);

    public static string Get(string cmd)
    {
        if (Texts.TryGetValue(cmd, out var t)) return t;
        throw new UsageException(Loc.T($"no help for command: {cmd}", $"该命令没有帮助：{cmd}"));
    }

    /// <summary>命令一句话摘要（供 pwhide help 列表与错误提示复用）。</summary>
    public static string Summary(string cmd) => cmd switch
    {
        "init" => Loc.T("initialize the vault (set master passphrase)", "初始化 vault（设置主口令）"),
        "set" => Loc.T("create/update an entry (hidden password input)", "录入/更新条目（密码隐藏输入）"),
        "list" => Loc.T("list entry metadata (no secret values)", "列出条目元数据（不含密文值）"),
        "inspect" => Loc.T("show one entry's metadata and placeholders", "查看单条目元数据与占位符"),
        "delete" => Loc.T("delete an entry", "删除条目"),
        "rename" => Loc.T("rename an entry (re-encrypts)", "重命名条目（会重加密）"),
        "exec" => Loc.T("fill placeholders, execute, redact output", "填充占位符并执行，输出自动脱敏"),
        "verify" => Loc.T("human check: decrypt and display an entry (terminal only)", "人工核验：解密显示条目（仅限终端）"),
        "rotate" => Loc.T("rotate the identity key pair", "更换身份密钥对"),
        "harden" => Loc.T("enable immutable write-protection", "启用不可变写保护"),
        "doctor" => Loc.T("environment self-check + encoding/keychain/language diagnostics", "环境自检 + 编码/钥匙串/语言诊断"),
        "keychain" => Loc.T("store/clear/check the master passphrase in the OS keychain", "主口令存取系统钥匙串"),
        "language" => Loc.T("switch UI language (en|zh)", "切换界面语言（en|zh）"),
        "version" => Loc.T("show version", "显示版本"),
        _ => "",
    };

    private static readonly Dictionary<string, string> Texts = new()
    {
        ["init"] = Loc.T(
            """
initialize the vault.

usage: pwhide init [--no-harden]

  Creates ~/.pwhide (or PWHIDE_HOME), generates the RSA identity and
  encrypted DEK, and asks for the master passphrase (twice).

options:
  --no-harden    skip the suggestion to run `pwhide harden` afterwards

next steps:
  pwhide keychain set    store the passphrase (zero interaction afterwards)
  pwhide set <name>      record your first credential
""",
            """
初始化 vault。

用法：pwhide init [--no-harden]

  创建 ~/.pwhide（或 PWHIDE_HOME），生成 RSA 身份密钥与加密 DEK，
  主口令需输入两次。

选项：
  --no-harden    跳过随后运行 pwhide harden 的建议

下一步：
  pwhide keychain set    主口令存钥匙串（之后全部命令零交互）
  pwhide set <名>        录入第一条凭据
"""),

        ["set"] = Loc.T(
            """
create or update an entry.

usage: pwhide set <name> [-t type] [-u username] [-T tenant]
                 [-f field=value | -f field]... [-pf plain-field=value]...
                 [--password-stdin] [--force-weak]

  The password is read hidden (interactive) or from stdin. Custom fields
  interactively ask whether to encrypt (sensitive-looking names default
  to encrypted). Plain fields (-pf) appear in `list --json` so the AI can
  use them without unlocking. Passwords and field values are trimmed.

options:
  -f <field=value>    encrypted custom field (or -f <field> for hidden input)
  -pf <field=value>   plain custom field (visible in metadata, AI-friendly)
  --password-stdin    read the password from stdin instead of hidden prompt
  --force-weak        override the weak-password rejection (risky)

examples:
  pwhide set db -t database -u root -T prod -f host
  pwhide set api -pf base=https://api.example.com --password-stdin < pw.txt

next steps:
  pwhide inspect db       check metadata and placeholders
  pwhide exec -- ...      use {{db}} / {{db.user}} / {{db.host}} in commands
""",
            """
创建或更新条目。

用法：pwhide set <名> [-t 类型] [-u 账号] [-T 租户]
                 [-f 字段=值 | -f 字段]... [-pf 明文字段=值]...
                 [--password-stdin] [--force-weak]

  密码经隐藏输入读取（或从 stdin）。自定义字段会逐个交互询问是否加密
  （形似敏感的字段名默认加密）。明文字段（-pf）会出现在 list --json
  元数据中，AI 免解锁即可用。密码与字段值会清除首尾空白。

选项：
  -f <字段=值>     加密自定义字段（或 -f <字段> 隐藏输入）
  -pf <字段=值>    明文自定义字段（元数据可见，AI 友好）
  --password-stdin    从 stdin 读密码（替代隐藏输入）
  --force-weak        强制保存弱密码（有风险）

示例：
  pwhide set db -t database -u root -T prod -f host
  pwhide set api -pf base=https://api.example.com --password-stdin < pw.txt

下一步：
  pwhide inspect db       查看元数据与可用占位符
  pwhide exec -- ...      在命令里用 {{db}} / {{db.user}} / {{db.host}}
"""),

        ["list"] = Loc.T(
            """
list entry metadata.

usage: pwhide list [--json]

  Shows name/type/username/tenant/plain-field values and whether a
  password is set. Never shows passwords or encrypted field values.
  `--json` is the AI's primary discovery interface.

next steps:
  pwhide inspect <name>    details and placeholders for one entry
""",
            """
列出条目元数据。

用法：pwhide list [--json]

  显示名称/类型/账号/租户/明文字段值/是否已设密码。绝不显示密码与
  加密字段值。--json 是 AI 的主查询接口。

下一步：
  pwhide inspect <名>    查看单条目详情与占位符
"""),

        ["inspect"] = Loc.T(
            """
show one entry's metadata and placeholders.

usage: pwhide inspect <name> [--json] [--verify]

options:
  --json     machine-readable (metadata only)
  --verify   human check: requires a real interactive terminal and a
             hand-typed master passphrase (keychain/env are ignored);
             decrypts and displays the password and fields for your own
             eyes. Refused when redirected or non-interactive.
""",
            """
查看单条目元数据与占位符。

用法：pwhide inspect <名> [--json] [--verify]

选项：
  --json     机器可读（仅元数据）
  --verify   人工核验：需真实交互终端并手输主口令（钥匙串/环境变量
             无效），解密显示密码与字段供本人核对；被重定向或非交互
             环境一律拒绝。
"""),

        ["delete"] = Loc.T(
            """
delete an entry.

usage: pwhide delete <name>

  Requires the master passphrase. If the vault is admin-hardened the
  change is installed via sudo automatically.
""",
            """
删除条目。

用法：pwhide delete <名>

  需要主口令。vault 处于管理员加固时，变更自动经 sudo 安装。
"""),

        ["rename"] = Loc.T(
            """
rename an entry.

usage: pwhide rename <old> <new>

  Encryption is bound to the entry name (AAD), so the password and all
  encrypted fields are re-encrypted under the new name. Requires the
  master passphrase; privileged install runs via sudo when hardened.
""",
            """
重命名条目。

用法：pwhide rename <旧名> <新名>

  加密与条目名绑定（AAD），密码与全部加密字段会在新名下重加密。
  需要主口令；加固状态下自动经 sudo 特权安装。
"""),

        ["exec"] = Loc.T(
            """
fill placeholders, execute a command, redact the output.

usage: pwhide exec [options] -- <command...>
       pwhide exec [options] -f <script>

  Placeholders: {{name}} password · {{name.user}} username ·
  {{name.tenant}} tenant · {{name.field}} custom field. Any unknown
  placeholder exits 4 without running the command (I2). Output is
  streamed through a byte-accurate redactor (I3): secrets are replaced
  back to placeholders before anything reaches stdout/stderr.

options:
  --shell auto|bash|sh|pwsh|cmd|none    shell to wrap with (default auto)
  --env <entry>:<ENVVAR>                inject the password as env var (repeatable)
  -f | --file <script>                  script-stdin mode (recommended; no argv/environ)
  --timeout <seconds>                   kill the process tree on timeout (default 120)
  --ph | --placeholder <#|@>            switch delimiters: #name# / @name@
  --allow-echo                          allow echo/printf co-occurring with secrets
  --verify                              pre-exec human check: interactive terminal,
                                        typed passphrase, decrypted preview, confirm y/N
  --home <dir>                          vault directory

notes:
  recommended: script-stdin (secrets in neither argv nor environ);
  env injection next; inline args are briefly visible to `ps`.
  template clash (Helm/Jinja {{ }})? use --ph '#' and write #name#.

examples:
  pwhide exec -- mysql -u {{db.user}} -p{{db}} -e "SELECT 1"
  pwhide exec --env db:MYSQL_PWD -- mysql -u root -e "SELECT 1"
  pwhide exec -f deploy.sh --shell auto
""",
            """
填充占位符并执行命令，输出自动脱敏。

用法：pwhide exec [选项] -- <命令…>
       pwhide exec [选项] -f <脚本>

  占位符：{{名}} 密码 · {{名.user}} 账号 · {{名.tenant}} 租户 ·
  {{名.字段}} 自定义字段。任一占位符未解析即退出码 4，子进程不启动
  （I2）。输出经字节级流式脱敏（I3）：密文在到达 stdout/stderr 前被
  替换回占位符。

选项：
  --shell auto|bash|sh|pwsh|cmd|none    包装的 shell（默认 auto）
  --env <条目>:<环境变量>                将密码注入环境变量（可重复）
  -f | --file <脚本>                      脚本 stdin 模式（推荐；不进 argv/environ）
  --timeout <秒>                         超时杀进程树（默认 120）
  --ph | --placeholder <#|@>             切换定界符：#名# / @名@
  --allow-echo                           放行 echo/printf 与密文共现
  --verify                               执行前人工核对：需交互终端手输主口令，
                                         展示解密值并确认 y/N
  --home <目录>                          vault 目录

说明：
  推荐：脚本 stdin（密码不进 argv 与 environ）；其次环境变量注入；
  args 内联会被 ps 短暂可见。与 Helm/Jinja 的 {{ }} 冲突？用 --ph '#'
  改写 #名#。

示例：
  pwhide exec -- mysql -u {{db.user}} -p{{db}} -e "SELECT 1"
  pwhide exec --env db:MYSQL_PWD -- mysql -u root -e "SELECT 1"
  pwhide exec -f deploy.sh --shell auto
"""),

        ["verify"] = Loc.T(
            """
human check: decrypt and display an entry (peer of exec).

usage: pwhide verify <name>

  Requires a real interactive terminal and a hand-typed master
  passphrase (keychain/env/file are ALL ignored) - the point is a human
  being present. Decrypts and displays the password and fields for your
  own eyes. Refused when stdin/stdout is redirected, and therefore
  unreachable by AI agents or scripts. Also available as
  `pwhide inspect <name> --verify`.
""",
            """
人工核验：解密并显示条目（与 exec 平级）。

用法：pwhide verify <名>

  需要真实交互终端并手输主口令（钥匙串/环境变量/口令文件统统无效）——
  设计上要求人在场。解密显示密码与字段供本人核对。stdin/stdout 被重
  定向时直接拒绝，因此 AI 与脚本不可达。等价形式：
  `pwhide inspect <名> --verify`。
"""),

        ["rotate"] = Loc.T(
            """
rotate the identity key pair.

usage: pwhide rotate

  Regenerates the RSA identity and re-wraps the DEK under the new
  public key. Entries need no re-encryption. Requires the master
  passphrase; privileged install runs via sudo when hardened.
""",
            """
更换身份密钥对。

用法：pwhide rotate

  重新生成 RSA 身份并用新公钥重包裹 DEK。条目无需重加密。需要主口令；
  加固状态下自动经 sudo 特权安装。
"""),

        ["harden"] = Loc.T(
            """
enable immutable write-protection.

usage: pwhide harden

  Root ownership + immutable flags (schg on macOS / chattr +i on Linux,
  ACL guidance on Windows): vault files can only be replaced wholesale -
  never edited in place. The exec read path never elevates; later
  set/delete/rename/rotate install their changes via sudo automatically.

next steps:
  pwhide doctor    verify protection state
""",
            """
启用不可变写保护。

用法：pwhide harden

  root 属主 + 不可变标志（macOS schg / Linux chattr +i，Windows 输出
  ACL 指引）：vault 文件只能整体覆盖、不能就地修改。exec 读路径永不
  提权；后续 set/delete/rename/rotate 自动经 sudo 安装变更。

下一步：
  pwhide doctor    核验保护状态
"""),

        ["doctor"] = Loc.T(
            """
environment self-check.

usage: pwhide doctor [--output-encoding <auto|utf8|utf16|gbk|json>]

  Reports home/platform, the output encoding channel (auto-detected by
  handle type; manual override source), vault state, leftover staging
  files (cleaned automatically), directory permissions, protection state
  (with auto-repair for interrupted hardening), and the resolved shell.

options:
  --output-encoding <mode>    globally force the output encoding; modes:
                              auto | utf8 | utf16 | gbk | json (pure ASCII)
""",
            """
环境自检。

用法：pwhide doctor [--output-encoding <auto|utf8|utf16|gbk|json>]

  报告 home/平台、输出编码通道（按句柄类型自动检测；含手工覆盖来源）、
  vault 状态、残留暂存文件（自动清理）、目录权限、保护状态（含中断
  加固的自动修复）与解析到的 shell。

选项：
  --output-encoding <模式>    全局强制输出编码；取值：
                              auto | utf8 | utf16 | gbk | json（纯 ASCII）
"""),

        ["keychain"] = Loc.T(
            """
store / clear / check the master passphrase in the OS keychain.

usage: pwhide keychain set | clear | status

  set     validates the passphrase against the vault first, then stores
          it (macOS Keychain / Windows Credential Manager / Linux Secret
          Service). Afterwards every command picks it up automatically -
          zero interaction for you and for AI calls.
  clear   remove the stored passphrase.
  status  platform support and current state.

notes:
  bypass once with PWHIDE_NO_KEYCHAIN=1. The slot is bound to the home
  path. Non-interactive setup: PWHIDE_PASSPHRASE=<master> pwhide keychain set
""",
            """
主口令存取系统钥匙串。

用法：pwhide keychain set | clear | status

  set     先用口令解锁 vault 验证，验证通过才存入（macOS 钥匙串 /
          Windows 凭据管理器 / Linux Secret Service）。之后所有命令
          自动取用——对你和 AI 调用都是零交互。
  clear   删除已存口令。
  status  平台支持与当前状态。

说明：
  临时跳过：PWHIDE_NO_KEYCHAIN=1。槽位与 home 路径绑定。非交互配置：
  PWHIDE_PASSPHRASE=<主口令> pwhide keychain set
"""),

        ["version"] = Loc.T(
            """
            show the pwhide version and platform.

            usage: pwhide version
            """,
            """
            显示 pwhide 版本与平台信息。

            用法：pwhide version
            """),

        ["language"] = Loc.T(
            """
switch the UI language.

usage: pwhide language en | zh
       pwhide language status

  Writes the choice to <home>/language; applies to every command.
  PWHIDE_LANG environment variable takes precedence.
""",
            """
切换界面语言。

用法：pwhide language en | zh
       pwhide language status

  写入 <home>/language，对所有命令生效。PWHIDE_LANG 环境变量优先。
"""),
    };
}
