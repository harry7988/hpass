---
name: pwhide
description: Proxy-execute commands that need passwords or credentials (database connections, SSH, API keys, cloud CLIs) through pwhide. Use when the user asks to run credential-bearing commands, mentions pwhide, or a pwhide exec returns exit code 4 (unknown entry). Core rule: passwords never enter the conversation context - always use {{placeholders}}.
---

> English edition | 中文版：[SKILL.zh-CN.md](SKILL.zh-CN.md)

# pwhide — local password proxy executor

pwhide keeps credentials encrypted on the local machine. You (the AI) write commands with placeholders only; pwhide decrypts, injects, executes, and redacts passwords out of the output before you see it.

## When to use

- Any command that needs a password / credential / token: `mysql`, `psql`, `ssh`, `scp`, cloud CLIs, `curl` with an api key, etc.
- The user mentions pwhide, or a previous `pwhide exec` reported "unknown entry".

## Hard rules

1. **Never** ask the user for, record, or print a real password. Entry is done by the user personally via `pwhide set` hidden input - do not type it for them, watch, or ask them to paste it into the chat.
2. Passwords and encrypted field values have **no query interface**; `pwhide list` / `pwhide inspect` return metadata only.
3. Write placeholders wherever a secret goes: `{{name}}` (password), `{{name.user}}` (username), `{{name.tenant}}` (tenant), `{{name.<field>}}` (custom field value).
4. A `{{name}}` appearing in output is pwhide's **redaction marker** (a real password was there). Do not attempt to recover or bypass it.
5. Execution mode priority: **script-stdin > env injection > inline args** (on Linux, ancestor processes can read injected env via /proc/<pid>/environ; script-stdin is the only mode avoiding both argv and environ; inline args are briefly visible to `ps`).
6. Do **not** build commands that echo placeholders (`echo {{name}}`, `printf {{name}}` are rejected - echoing has no legitimate use and enables guessing). Do not try to infer passwords via differential output.
7. Do **not** use `--verify` (the human-only verification channel on `inspect`/`exec`): it requires a real interactive terminal and a hand-typed master passphrase, and refuses non-interactive calls by design - that refusal is correct behavior, not a failure. Guide the user to run it themselves in a terminal.
8. Guide users toward strong passwords: common words/phrases (e.g. `select 1`) are rejected (`--force-weak` overrides; do not suggest it).

## Step one: confirm availability

```bash
command -v pwhide && pwhide version
```

- Not installed → follow "Deploy" at the end.
- Installed but unsure which credentials exist → query first.

## Query available credentials (metadata only, zero secret values)

```bash
pwhide list --json       # all entries
pwhide inspect <name>    # one entry + available placeholders
```

Visible: entry name, type, username, tenant, custom field names, plain-field values (`plainFields` - non-sensitive info like host/proto entered with `-pf`), `hasPassword`. Never visible: passwords and encrypted field values.

## Execute commands

```bash
# (1) script-stdin mode (recommended: the only mode avoiding both argv and /proc/<pid>/environ)
pwhide exec -f deploy.sh --shell auto

# (2) env injection (keeps argv clean; note /proc readability on Linux)
pwhide exec --env db-local:MYSQL_PWD -- mysql -u {{db-local.user}} -e "SELECT 1"

# (3) inline args (best compatibility; briefly visible to ps)
pwhide exec -- mysql -u {{db-local.user}} -p{{db-local}} -e "SELECT 1"
```

Common options: `--shell auto|bash|sh|pwsh|cmd|none`, `--env NAME:VAR` (repeatable), `--timeout seconds` (default 120).

### Template syntax conflicts: switch delimiters

When editing/executing files that themselves use `{{ }}` templates (Helm, Jinja2, Go text/template, Ansible), add `--ph` and write placeholders as `#name#` (or `@name@`):

```bash
pwhide exec --ph '#' -- envsubst < helm-values.yaml   # {{db}} is a template literal here; #db# is the credential
pwhide exec --ph '@' -f deploy.sh --shell auto         # prefer @ in scripts dense with # comments
```

Rules: with `--ph` active, **only** the chosen delimiter is resolved (`{{db}}` is a literal, and vice versa); redaction output and error messages render with the active delimiter too. Field syntax is unchanged: `#name.user#`, `@name.field@`.

## Missing credential (exit code 4)

Ask the **user** to run the entry command themselves (hidden input):

```bash
pwhide set <name> -t <type:database|ssh|api|cloud|custom> -u <username> -T <tenant> -f <field=value>
```

Then show `pwhide inspect <name>` to the user to confirm metadata.

## Error handling

| Symptom | Meaning | Your move |
|---|---|---|
| exit code 4 | unknown entry/field | check with `pwhide list`; if absent, the user runs `pwhide set` |
| exit code 3 | vault locked / wrong passphrase | suggest `pwhide keychain set` (configure once, zero interaction afterwards) or `PWHIDE_PASSPHRASE_FILE`; never guess |
| exit code 124 | child timed out | check for hangs; add `--timeout` |
| output contains `{{...}}` | normal redaction marker | relay the result as-is |
| `pwhide exec` triggers sudo/UAC | abnormal (the read path never elevates) | run `pwhide doctor` and tell the user |

## Deploy (when not installed)

Follow the runbook in `docs/ai-deploy-guide.en.md` in the repo. Summary: download the platform binary from GitHub Releases (SHA256SUMS provided), place it on PATH, `pwhide init`, then `pwhide keychain set` for zero-interaction runs.
