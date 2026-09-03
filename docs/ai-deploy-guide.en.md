> English edition. The Chinese original at [ai-deploy-guide.md](ai-deploy-guide.md) is authoritative. / 英文版，中文原文为权威版本。

# pwhide AI Deployment and Usage Guide

This document is for AI coding tools (Claude Code, Cursor, and other Agents). Your tasks fall into two categories:

1. **Deployment**: follow the runbook in §1 to install, initialize, and verify pwhide for the user;
2. **Daily use**: discover the available credentials via the query interface (§3), and execute password-bearing commands on the user's behalf via the execution interface (§4) — without ever touching any real password.

> Note: pwhide is under development; this guide describes the v1 target behavior (see [PLAN.md](../PLAN.md)). If a command does not exist or the behavior differs, tell the user that the current version has not yet reached that milestone — do not invent makeshift alternatives.

---

## 0. Iron Rules (read these first)

1. **Never** ask the user for, record, output, or otherwise handle a real password. Entering a password is the user's own interaction (`pwhide set` hidden input); do not watch it, type it for them, or ask the user to paste it into the conversation.
2. Passwords and custom field values have **no query interface at all**. `pwhide list` / `pwhide inspect` return metadata only (type, account, tenant, field names).
3. Wherever a command needs a secret, always write a **placeholder**: `{{entry-name}}` (password), `{{entry-name.user}}`, `{{entry-name.tenant}}`, `{{entry-name.<field-name>}}`.
4. A `{{entry-name}}` appearing in execution results is pwhide's **redaction marker** (the real password was at that position); this is normal — do not attempt to "restore" it.
5. Prefer the safer modes: **script stdin > environment variable injection > args inline** (on Linux, an ancestor process can read the
   injected secret via /proc/<pid>/environ; script stdin is the only mode that avoids both argv and environ; see §4 and the threat model).
6. **Do not construct commands that echo placeholders** (`echo {{name}}` and the like are rejected — echoing a password has no legitimate use and can be exploited to infer passwords); do not attempt to infer password contents in any way.
7. At recording time, weak passwords (common passwords / common phrases) are rejected; guide the user to set a strong password (length ≥8, mixed characters, not a common phrase).

---

## 1. Deployment runbook

### 1.1 Identify the platform

```bash
uname -s && uname -m      # Darwin arm64 → osx-arm64; Linux x86_64 → linux-x64 …
```

On Windows use `pwsh`: `$env:PROCESSOR_ARCHITECTURE` tells x64/arm64.

### 1.2 Obtain the binary

**Option A: GitHub Release (recommended, available once published)**

```bash
# 1) Download the archive for the matching RID (version v is the latest release)
curl -LO https://github.com/harry7988/pwhide/releases/latest/download/pwhide-<rid>.tar.gz
# 2) Verify (mandatory)
curl -LO https://github.com/harry7988/pwhide/releases/latest/download/SHA256SUMS
shasum -a 256 --check SHA256SUMS --ignore-missing
# 3) Extract
tar xzf pwhide-<rid>.tar.gz
```

**Option B: build from source (requires the .NET 10 SDK)**

```bash
git clone git@github.com:harry7988/pwhide.git && cd pwhide
dotnet publish src/PwHide.Cli -c Release -r <rid> /p:PublishAot=true -o publish
# The artifact is publish/pwhide (pwhide.exe on Windows)
```

### 1.3 Install onto PATH

- Unix: `/usr/local/bin/pwhide` (needs sudo) or `~/.local/bin/pwhide` (make sure it is on PATH).
- Windows: `%LOCALAPPDATA%\Programs\pwhide\pwhide.exe`, and add that directory to the user PATH.

Verify: `pwhide version`.

### 1.4 Initialize

Guide the user to run this **in person** (you run the command, the user types the password):

```
pwhide init
```

- The user will set and confirm a **master passphrase** (used to encrypt the private key). Remind the user: if the passphrase is lost, all passwords are unrecoverable — there is no backdoor.
- init produces the basic mode (directory 700 / files 600); admin-level write protection requires a separate `pwhide harden` (asks for sudo/UAC — that is normal and recommended).

### 1.5 Verify

```
pwhide doctor
```

Confirm in the output: shell probing is OK, vault permissions / harden status are OK, and there is no interrupted state pending recovery.

### 1.6 Record the first credentials

Run by the user in person (the master passphrase is hidden input; pass non-sensitive config fields with `-f field=value`; for **sensitive field values** (api_key/token, etc.) use the interactive hidden input `-f field-name` — values passed on the command line end up in shell history, and pwhide will warn about this too):

```bash
pwhide set db-local -t database -u root -T prod -f host=127.0.0.1 -f port=3306
```

After recording, you can show the metadata to the user with `pwhide inspect db-local` to confirm it is correct.

### 1.7 Smoke test

Use a harmless command to verify the placeholder-substitution and redaction chain:

```bash
# Note: directly echoing a placeholder counts as probing and is rejected by default; manual verification of redaction requires an explicit --allow-echo
pwhide exec --allow-echo -- echo "password is {{db-local}}"
# Expected output: password is {{db-local}}   ← already redacted
```

---

## 2. Entry Data Model

| Field | Visibility | Notes |
|---|---|---|
| `name` | plaintext | entry name, the primary key referenced by placeholders |
| `type` | plaintext | account type: database / ssh / api / cloud / any custom string |
| `username` | plaintext | account |
| `tenant` | plaintext | tenant / environment label (e.g. prod, tenant-a) |
| password | **encrypted** | the password, placeholder `{{name}}` |
| `fields` | names plaintext, **values encrypted** | custom fields (host, api_key, token…), placeholder `{{name.<field-name>}}` |

Design intent: the **non-sensitive information needed to assemble commands** — type/account/tenant/field names — is queryable; **sensitive information** — passwords and field values — can only be injected into the subprocess via placeholders.

## 3. Query Interface

```bash
pwhide list            # human-readable table
pwhide list --json     # machine-readable (recommended for AI use)
pwhide inspect <name>  # single-entry details + the list of available placeholders
```

Example `pwhide list --json` output:

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

## 4. Execution Interface

From most to least secure (consistent with threat-model §5.9: script stdin is the only mode that avoids both argv and /proc/<pid>/environ):

```bash
# ① Script stdin mode (recommended: the only mode that avoids both argv and /proc/<pid>/environ)
pwhide exec -f deploy.sh --shell auto

# ② Environment variable injection (the password stays out of argv; note that on Linux an ancestor process can read the injected secret via /proc/<pid>/environ)
pwhide exec --env db-local:MYSQL_PWD -- mysql -u {{db-local.user}} -e "SELECT 1"

# ③ args inline (best compatibility; the password is briefly visible via ps while the subprocess runs)
pwhide exec -- mysql -u {{db-local.user}} -p{{db-local}} -e "SELECT 1"
```

Common options: `--shell auto|bash|sh|pwsh|cmd|none`, `--env NAME:VAR` (repeatable), `--timeout` seconds (default 120).

Exit codes: `0` success (the child process's code is passed through) | `2` usage error | `3` vault/passphrase error | `4` unknown placeholder | `124` timeout.

## 5. Error Handling

| Symptom | Meaning | Your action |
|---|---|---|
| Exit code 4 (unknown placeholder) | the entry or field does not exist | verify the name with `pwhide list`; if it does not exist, ask the user to record it in person with `pwhide set` |
| Exit code 3 (passphrase/key error) | the master passphrase is not unlocked or is wrong | prompt the user to configure `PWHIDE_PASSPHRASE_FILE` or enter it interactively; do not try to guess |
| Exit code 124 | the child process timed out and was killed | check whether the command needs interaction / hangs; add `--timeout` if necessary |
| Output contains `{{…}}` | a normal redaction marker | just relay the result as-is |
| `pwhide exec` triggers sudo/UAC | abnormal (the read path never elevates) | run `pwhide doctor` to check the vault status and report back to the user |

## 6. Contract to paste into a project's AGENTS.md / CLAUDE.md

```
When you need to execute a command that contains a password:
1. Never ask the user for the real password; use a {{entry-name}} placeholder instead;
2. If unsure which credentials are available, query `pwhide list --json` first (visible: account type, account, tenant, custom field names, plaintext field values (non-sensitive info recorded with -pf, such as host/proto); not visible: passwords and encrypted field values);
3. Execute via `pwhide exec -- <command>`; pwhide fills the values in automatically and returns the result;
4. On "unknown entry" (exit code 4): if the entry does not exist, ask the user to run `pwhide set <name>` in person to record it;
5. A {{entry-name}} appearing in the output is the redacted password; this is normal.
```
