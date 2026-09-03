> English guide | 中文：[guide.zh-CN.md](guide.zh-CN.md)

> **Note**: the CLI UI is English by default (matches this guide). To switch to Chinese: `pwhide language zh` or `export PWHIDE_LANG=zh`.
# pwhide Illustrated Guide: from zero to everyday AI usage

## The problem it solves

Let AI agents (Claude Code / Cursor / any agent) run password-bearing commands without the password ever entering the conversation, logs, or history.

![How it works](images/workflow.png)

After the three steps, the AI's world contains only `{{placeholders}}` and redacted output. Secrets themselves sit encrypted (AES-256-GCM + RSA-3072 envelope) in `~/.pwhide/`, with the master passphrase optionally in the OS keychain.

## Five-minute quick start

![Quick start session](images/quickstart.png)

| Step | Command | Notes |
|---|---|---|
| 1 init | `pwhide init` → `pwhide harden` | set master passphrase; after harden the vault is wholesale-replace only |
| 2 zero-interaction (recommended) | `pwhide keychain set` | store the passphrase in the OS keychain; every command afterwards is interaction-free |
| 3 record credential | `pwhide set prod-db -t database -u root` | hidden password input; each field interactively asked encrypt-or-plain (IP/protocol plain, api_key encrypted) |
| 4 hand it to the AI | `pwhide list --json` + `pwhide exec -- cmd...` | AI reads metadata, writes `{{prod-db}}` |

**AI-side setup** (once): put the visibility contract and placeholder rules into the project's `AGENTS.md`, or install the bundled skill: `skills/pwhide/install.sh`.

## Three execution modes (safest last)

1. **script-stdin (recommended)**: `pwhide exec -f deploy.sh` — placeholders in the script; substitution purely in memory; secrets in neither argv nor environ.
2. **env injection**: `pwhide exec --env prod-db:MYSQL_PWD -- mysql …` — clean argv (Linux ancestors can read /proc).
3. **inline args**: `pwhide exec -- mysql -p{{prod-db}}` — most intuitive, briefly visible to `ps`.

## Human verification: confirm what's stored is right

![verify channel](images/verify-channel.png)

`pwhide verify entry` forces you to type the master passphrase in a real terminal (keychain/env ignored) and decrypts the entry for your eyes only. `pwhide exec --verify` shows the decrypted injection values and the full command before running; declining cancels. The channel **only exists on a real interactive terminal** — redirection or AI invocation is refused by design.

## Windows encoding: why it kept breaking, and the fix

![Windows encoding before/after](images/windows-encoding.png)

**Why it kept breaking**: the Windows console stacks decades of encoding history —

1. cmd's code page is DOS-era OEM (Simplified Chinese = cp936/GBK), not UTF-8;
2. one machine has three decoders: cmd uses OEM, PowerShell 5.1 pipes decode with `[Console]::OutputEncoding` (OEM by default), PowerShell 7 defaults to UTF-8;
3. once output is piped or redirected the rules change entirely: raw bytes go to the consumer, and whoever reads them picks the decoder;
4. old pwhide always wrote UTF-8 into pipes: decoded as GBK it became `鏈?鎵惧埌 vault锛圕:...`; decoded as UTF-16LE it became `pwhide: 睰楨敤›鳦...` (the mojibake samples in the comparison image are computed from real binary output).

**0.7+ auto-adapts**: real console → `WriteConsoleW` (codepage-independent); pipe → transcoded by the session console code page; file redirect → UTF-8.

**Fallback** (if auto-detection is still wrong, set it once globally):

```powershell
pwhide doctor                        # diagnostics: current channel/codepage/source
pwhide doctor --output-encoding gbk  # or utf8 / utf16 / json (pure ASCII, cannot mojibake)
# env var: $env:PWHIDE_OUTPUT_ENCODING = "gbk"
```

The byte-level verification report below is produced by the real binary and decoded exactly as each Windows consumer would.

![encoding proof](images/encoding-proof.png)

Repeatable script: `python3 scripts/encoding-visual-proof.py <pwhide binary>` (exit 0 = every scenario round-trips byte-perfect).

## Cheat sheet

- unknown placeholder (exit 4): `pwhide list`; the user records with `pwhide set`;
- passphrase errors (exit 3): `pwhide keychain set` or `PWHIDE_PASSPHRASE_FILE`;
- Helm/Jinja template clash: `exec --ph '#'`, write `#db#`;
- timeout 124: add `--timeout`;
- environment self-check: `pwhide doctor`.
