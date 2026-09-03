> English edition | 中文版：[README.zh-CN.md](README.zh-CN.md)

# pwhide

> A password proxy CLI for AI coding tools — the AI only ever sees placeholders and redacted output; passwords never enter the conversation context.

[![CI](https://github.com/harry7988/pwhide/actions/workflows/ci.yml/badge.svg)](https://github.com/harry7988/pwhide/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-0.7.0-blue)](https://github.com/harry7988/pwhide/releases)
[![License: MIT](https://github.com/harry7988/pwhide/blob/main/LICENSE)](https://github.com/harry7988/pwhide/blob/main/LICENSE)

You hand AI agents real commands to run — database connections, deploys, cloud CLIs — and the password has to come from somewhere. Pasting it into the chat leaks it into logs, history, and context windows. `pwhide` offers a third path: **credentials are stored in a local encrypted vault; the AI writes commands with placeholders; pwhide decrypts, injects, executes, and redacts the password back out of any output before the AI sees it.**

```
AI writes:  pwhide exec -- mysql -u {{db.user}} -p{{db}} -e "SELECT 1"
AI receives: mysql: [output] ...  (any password in the output is replaced with {{db}})
```

**Status: v0.7.0** — 269 tests passing (140 unit + 129 integration), CI on three platforms (macOS / Ubuntu / Windows) with a Native AOT smoke test (including a real-sudo hardening flow) all green. Threat model: [docs/threat-model.en.md](docs/threat-model.en.md); milestones: [PLAN.md](PLAN.md). UI language defaults to **English**; `pwhide language zh` switches to Chinese.

## Highlights

- **Zero context leakage**: no command can display a password (the single exception is the `--verify` human channel below); child-process output is streamed through a byte-accurate redactor before it returns.
- **OS keychain, zero interaction**: `pwhide keychain set` stores the master passphrase in macOS Keychain / Windows Credential Manager / Linux Secret Service (validated against the vault before storing). Afterwards `exec` and friends never ask for it. `PWHIDE_NO_KEYCHAIN=1` bypasses.
- **Human verification channel**: `pwhide verify <name>` (peer of `exec`, equal to `inspect <name> --verify`) requires a real interactive terminal plus a hand-typed master passphrase — keychain/env are ignored — then decrypts and displays the entry for your eyes only. `exec --verify` shows the decrypted injection values and the full command, and asks for confirmation before running; declining means the child never starts.
- **Switchable placeholder delimiters**: default `{{name}}`; `exec --ph '#'` switches to `#name#` (`--ph '@'` → `@name@`) so `{{ }}` stops colliding with Helm / Jinja / Go templates. Parsing and redaction semantics are identical.
- **Plain fields**: `set` interactively asks per field whether to encrypt (sensitive-looking names default to encrypted; IPs/protocols default to plain). Plain-field values appear in `list --json` metadata so the AI can assemble commands without unlocking. `-pf name=value` opts in explicitly for scripts.
- **Weak-secret gates**: "password = common phrase" entries are rejected (redaction positions would leak them; `--force-weak` overrides); echo-probe commands (echo/printf co-occurring with a secret placeholder) are blocked (`--allow-echo` opts in); more than 32 redactions in one run warns.
- **Privileged hardening**: root ownership + immutable flags — the vault can only be replaced wholesale. Elevated installs move ciphertext only, guarded by symlink / ownership / inode checks; three real attack classes verified in adversarial Docker runs.
- **Three execution modes**: script-stdin (recommended: secrets touch neither argv nor environ) > env injection > inline args. Wraps bash / sh / pwsh / cmd.
- **Windows console encoding, fixed for real**: a genuine console handle writes via `WriteConsoleW` (any code page); a pipe transcodes using the session's console code page (which is exactly what PowerShell decodes with); file redirects stay UTF-8. Still garbled? `pwhide doctor --output-encoding <auto|utf8|utf16|gbk|json>` forces it globally (`json` escapes non-ASCII to `\uXXXX` and is readable on any terminal).
- **C# Native AOT single-file binaries**: six RIDs across macOS / Linux / Windows, zero runtime dependencies.

## Illustrated guide

A visual walkthrough (workflow diagram, terminal sessions, the Windows-encoding before/after, and the byte-level encoding verification report) lives at [docs/guide.en.md](docs/guide.en.md) and on the website: www.pwhide.com → **Guide**. 中文版：[docs/guide.zh-CN.md](docs/guide.zh-CN.md)。

## Quick start

```bash
# 1. Initialize (sets the master passphrase; basic mode: dir 700 / file 600)
pwhide init
# (recommended) admin-level write protection: whole-file replacement only
pwhide harden

# 2. Record a credential (a human does this; hidden password input)
pwhide set db -t database -u root -T prod -f host=127.0.0.1

# 3. List available credentials (metadata only, zero secrets)
pwhide list --json

# 4. Proxy-execute; the AI writes placeholders only
pwhide exec --env db:MYSQL_PWD -- mysql -u {{db.user}} -e "SELECT 1"
```

Optional, once: `pwhide keychain set` — afterwards no command ever asks for the passphrase.

## The AI contract

Paste this into your project's `AGENTS.md` / `CLAUDE.md` (or install the bundled skill below):

```
When a command needs a password:
1. Never ask the user for a real password - use a {{placeholder}}.
2. Unsure which credentials exist? Query `pwhide list --json` first (visible: type,
   username, tenant, field names, plain-field values; never visible: passwords
   and encrypted field values).
3. Execute via `pwhide exec -- <command>`; pwhide fills and returns the redacted result.
4. On "unknown entry" (exit code 4), ask the user to run `pwhide set <name>` themselves.
5. Do not build commands that echo placeholders (rejected), and do not try to infer secrets.
6. Do not use --verify (human-only channel; non-interactive calls are refused by design).
7. Weak passwords (common words/phrases) are rejected - guide users toward strong ones.
```

The repo ships an agent-facing skill at [skills/pwhide](skills/pwhide/) (`SKILL.md` + installer) so your AI follows the placeholder and redaction rules automatically.

## Security model

| Invariant | Meaning |
|---|---|
| I1 no plaintext output | No get/show commands; metadata queryable, secrets not (sole exception: `--verify` human channel — interactive terminal, typed passphrase, unreachable from pipes/scripts/AI) |
| I2 unknown = no run | Any unresolved placeholder exits 4; the child never starts |
| I3 output redaction | Byte-accurate replacement back to placeholders across buffer boundaries |
| I4 private key stays local | A leaked ciphertext alone is undecryptable |
| I5 never echo resolved commands | Errors and logs contain placeholder versions only |
| I6 wholesale replacement only | Post-hardening vault changes go through one controlled path; the exec read path never elevates |

**Honest boundary**: pwhide defends against secrets accidentally entering context/logs/backups. It does not defend against already-elevated malware or a malicious agent deliberately exfiltrating via encodings (see the threat model). Inline mode briefly exposes the password to `ps`; priority is script-stdin > env > inline, and on Linux ancestor processes can read `/proc/<pid>/environ`, making script-stdin the only mode avoiding both argv and environ.

Full threat model: [docs/threat-model.en.md](docs/threat-model.en.md) (Chinese original: [docs/threat-model.md](docs/threat-model.md)).

## Installation

| Platform | RID | Notes |
|---|---|---|
| macOS (Apple Silicon / Intel) | osx-arm64 / osx-x64 | ✅ CI green |
| Linux (x64 / arm64) | linux-x64 / linux-arm64 | ✅ CI green; full suite also run in a fresh root-context Docker harness (five adversarial scenarios) |
| Windows (x64 / arm64) | win-x64 / win-arm64 | ✅ x64 CI green (pwsh tested, cmd per §7.1). Chinese console output goes through WriteConsoleW; PowerShell pipes transcode by the session console code page; `doctor --output-encoding` is the manual fallback |

Download from [Releases](https://github.com/harry7988/pwhide/releases) (SHA256SUMS included) or the repo's `dist/` directory.

## Development

```bash
dotnet test          # 269 tests: unit (crypto/vault/placeholders/redaction/launcher/hardening/weak-secrets/probes) + integration (full CLI flows)
bash docker/run-linux-tests.sh   # full suite + real-root hardening scenarios in an isolated container
```

- Release flow: push main → CI green → bump version → tag → release workflow (six RIDs) → rebuild `dist/`.
- Website: [www.pwhide.com](https://www.pwhide.com) — bilingual (browser-language detection), sources in `docs/`.

## License

MIT
