> English edition. The Chinese original at [threat-model.md](threat-model.md) is authoritative. / 英文版，中文原文为权威版本。

# pwhide Threat Model

> This document states plainly what pwhide defends against and what it does not. The goal is "preventing passwords from accidentally entering AI context / logs / backups", not countering malware that already holds elevated privileges.
> Maintained in sync with the implementation; behavior changes must land here first. See [PLAN.md](../PLAN.md) for the overall design.

## 1. Assets

| Asset | Location | Protection |
|---|---|---|
| Passwords and custom field values (plaintext) | pwhide process memory only (byte[], cleared after use) | Minimized lifetime; no plaintext-at-rest path exists |
| vault.json (ciphertext + metadata) | `~/.pwhide/vault.json` | AES-256-GCM (AAD prevents ciphertext swapping); file protection (see §3) |
| master.key (passphrase-encrypted RSA private key) | `~/.pwhide/master.key` | PBKDF2-SHA512(600k) + AES-256-GCM; 600 |
| master passphrase | user memory / `PWHIDE_PASSPHRASE[_FILE]` | never stored in the vault; file mode requires permission 600 |
| Redacted command output | stdout/stderr | this is the AI-visible surface |

## 2. Attacker Model

### A1 Accidental Disclosure (primary goal, fully defended)

Passwords entering AI conversations, terminal echo, shell history, logs, mistakenly committed files.

Mitigations (each has a corresponding test):
- **No plaintext output commands** (I1): there is no `get/show`-style command; `list`/`inspect` return metadata only (type/account/tenant/field names). The sole exception is the `--verify` human verification channel: it requires a real interactive terminal (any stdin/stdout redirection is rejected) and forces manual entry of the master passphrase (env/file/OS keychain are ignored), for the owner's own eyeball check — by design, no ciphertext-reading path is reachable by any pipeline/script/AI.
- **Refuse to run with unknown placeholders** (I2): entry/field existence is pre-validated (metadata query only, no passphrase needed); any unknown → exit code 4, the subprocess is not started.
- **Streaming output redaction** (I3): when a secret used in the current run appears in subprocess stdout/stderr, it is replaced back with `{{name}}`, safe across buffer boundaries.
- **Never echo the resolved command** (I5): error/timeout messages contain only the placeholder version.
- **shell history contains placeholders only**: commands are spawned directly by pwhide; `set` passwords use hidden input; plaintext in argv is forbidden.

### A2 Theft at Rest (fully defended)

Obtaining a copy of the vault file (cloud-drive sync, accidentally committed to git, backup leak).

- The private key is stored passphrase-encrypted; a vault leaked on its own cannot be decrypted (I4).
- Every entry is AEAD + AAD bound to entry name/field path → localized tampering and entry/field swapping necessarily fail authentication.
- Briefly visible via `ps`: exists only in args inline mode (the password enters the subprocess argv); mitigated by promoting env injection and script stdin mode (clean argv) as the preferred modes.

### A3 User-Mode Malicious Process (partially defended)

Malware / an AI subprocess with the same privileges as the user wants to modify the vault.

- **File protection** (I6): admin level = root owner + schg/`chattr +i`; user level (macOS) = uchg. Changes only ever go through
  "clear protection → atomic rename overwrite → re-apply protection"; any write that bypasses this path fails outright (EPERM/EACCES).
- A user-mode process can still **read** (ciphertext, useless); real confidentiality still rests on passphrase + private key.
- Reading passwords still requires the passphrase → a malicious process cannot get the private key (unless the passphrase is also in the environment).

### A4 Malicious AI Agent (partially defended, stated plainly)

- Passive surface: same as A1, fully covered (all the Agent ever sees is placeholders and redacted output).
- **Active bypass**: the Agent constructs transformations such as `pwhide exec -- sh -c 'echo {{db}} | base64'` to exfiltrate — output redaction
  matches bytes exactly, and once encoded they no longer match, so this is **not defended**. This belongs to the malware category (an Agent
  with network access could exfiltrate data directly anyway). The positioning is "defend against accidents, not against malice".
- **Echo probing (dictionary attack)**: the Agent runs `echo` with various candidate strings and observes which one gets replaced by a
  placeholder, thereby confirming the password — i.e. "the replacement positions themselves are a disclosure surface". Mitigation: `exec`
  uses **whole-invocation co-occurrence semantics** — within a single invocation, the co-occurrence of an "echo primitive
  (echo/printf/Write-Output/puts…)" with a "secret placeholder" is rejected (the earlier "same statement" rule could be bypassed by
  ordering such as `x={{db}}; echo cand`); `--allow-echo` explicitly allows it. Cost: combinations such as
  `echo progress && mysql -p{{db}} …` are also blocked and need --allow-echo. Combined with A7 weak-password interception,
  weak answers that could be probed cannot be recorded.
- Agent-induced privilege escalation: `_install-staged` has a path whitelist (staging must sit under `run/staging`, and the final targets
  can only be the three vault files), so it cannot be used as an arbitrary root file mover; the sudo password is typed by the user
  and cannot be obtained from pwhide by the Agent.

### A7 Weak Passwords = Common Phrases (intercepted at the recording source)

If the password itself is high-frequency text (e.g. `select 1`, `connection refused`, `password`), it causes double harm:
1. Normal output (logs, SQL results) gets mis-replaced with placeholders on a large scale, destroying output usability;
2. **The replaced positions directly disclose the password's content** — seeing which phrase in the log turned into `{{db}}` tells you the password is that phrase.

Mitigations (layered):
- **Rejection at recording**: `set` runs weak detection on passwords (whole-string dictionary match against common passwords/common phrases,
  length <8, all digits, fewer than 4 character classes, short all-lowercase strings); a hit is rejected, with `--force-weak` as the
  explicit override (at your own risk). Field values (common config such as host=127.0.0.1) are not blocked, only warned about.
- **Runtime warning**: exec counts how many times each secret is replaced in the output; above 32 in a single run it prompts
  "suspected collision with common text; consider switching to a strong password".
- **Echo-probe interception**: see A4.

### A5 root / Administrator (not defended, stated plainly)

- Can clear any platform protection flag; owning the machine means owning everything. AEAD guarantees that localized tampering with existing entries is necessarily exposed; a wholesale re-created vault can be noticed as entry anomalies via `pwhide list`.

### A6 Physical and Side Channels (not defended)

- Memory dumps, ptrace, swap, cold boot, keyloggers. The decrypted byte[] in memory is cleared after use, but .NET GC/string residue is a known residual risk (stay at the byte layer as much as possible).

## 3. Privileged Hardening Semantics (I6)

| Level | Trigger | Effect | Change path |
|---|---|---|---|
| Basic | `init` default | directory 700 / files 600, atomic overwrite write | staged in `run/staging` → install |
| User level | `harden` (regular macOS user) | core vault files immutable via uchg | automatic: clear uchg → overwrite → re-apply uchg (done in user mode) |
| Admin level | `sudo pwhide harden` | root owner 440 (group aligned to SUDO_USER) + schg/`chattr +i`; directory 750 | automatic: sudo (first `-n` passwordless, then interactive) re-invokes itself to run `_install-staged`, **moving ciphertext only**; Windows goes through the icacls guidance |

Supplementary notes on the admin level:
- On macOS every local user's primary group is the shared staff group, so "group alignment" is equivalent to the ciphertext pair being
  readable by all local users on the machine (enabling offline brute force); to narrow this, combine with FileVault/home-directory
  permissions, or wait for the upcoming per-file ACL support. Linux primary groups are usually private and unaffected.
- The root path of `_install-staged`: symlink rejection along the staging directory chain (home/run/staging) + content structure
  validation (valid JSON ≤8MB) + new content written under an O_EXCL temporary name then renamed over (rename does not follow links)
  + the old real file moved aside as `.pwhide-orig-*` for re-checking, deleted only on success. Leftover `.pwhide-orig-*` /
  `.pwhide-new-*` from interruptions are reported by doctor (not auto-deleted — orig is the only copy of the old vault).
- `--env` injection likewise counts as a "secret reference" in echo-probe detection (a bypass closed during the second review round).

- The `exec` read path **never elevates** (AI invocations trigger no system privilege prompts).
- Interruption recovery: interrupted between clearing and re-applying protection → the file is left "unprotected but intact"; `doctor`
  detects this (partial protection = interrupted state), cleans up `run/staging` leftovers (ciphertext only), and restores missing protection.
- Failures leave no half-written state: on install failure the final file is unchanged and the staged ciphertext is kept for manual
  moving via `sudo _install-staged`.

## 4. Cryptographic Parameters

| Item | Value |
|---|---|
| Identity key | RSA-3072 (OAEP-SHA256 wraps the DEK) — Windows CNG does not support X25519, hence RSA for full cross-platform consistency |
| Data key DEK | random AES-256, stored in the vault as ciphertext only |
| Entry encryption | AES-256-GCM, 96-bit nonce, AAD=`entry name\|field path` (the password path is `\x01password`) |
| Passphrase derivation | PBKDF2-HMAC-SHA512, 600,000 iterations (OWASP's current recommendation; old vaults decrypt per their own stored values — compatible), 16-byte salt (Argon2id listed as a future item) |
| Randomness | `RandomNumberGenerator` (CSPRNG) |

## 5. Known Residual Risk List

1. In args inline mode the password is visible via `ps` while the subprocess runs (documented explicitly; env/script modes are the recommended primary modes).
2. Encoding transformations can bypass output redaction (A4, outside the stated scope).
3. root / Administrator has full power (A5).
4. The `PWHIDE_PASSPHRASE` environment-variable mode can be read by same-user processes (a trade-off between automation convenience and security; `PWHIDE_PASSPHRASE_FILE` with 600 permission is recommended).
5. .NET runtime memory residue (byte[] clearing is done; string scenarios minimized).
6. cmd.exe has unusual quoting semantics; pwsh is recommended when paths are complex.
7. Echo-probe interception is a **heuristic** (whole-invocation co-occurrence regex): it does not cover the output primitives of every
   programming language, nor can it stop the Agent from differentiating output by other means (e.g. writing command results to a file
   and then reading it); the weak-password dictionary cannot be exhaustive. The two defensive layers stacked together raise the bar
   significantly, but no completeness claim is made.
8. Non-echo verbatim exfiltration (e.g. `tee`/redirect to a file and then read it) still gets the secret's lines replaced with the placeholder — this is expected behavior (redaction always applies).
9. **env injection and /proc**: `--env db:MYSQL_PWD` puts the password into the subprocess environment; on Linux an ancestor process
   (the AI shell driving pwhide) can read it via `/proc/<pid>/environ` (yama ptrace_scope=1 does not block ancestors). Outside of argv,
   the only mode that simultaneously avoids both argv and environ is **script stdin** — the priority order should be:
   script stdin > env injection > args inline.
10. **Orphan process escape**: timeout kills use "independent process group + kill(-pgid)" plus Kill(entireProcessTree) as a double
    safeguard, but double-forked / init-adopted descendants can still escape and keep running with the injected secret in their environment.
11. **Cross-file atomicity of rotate**: vault.json and master.key are two separate installs; rotate automatically backs up the current pair
    to `run/rotate-backup.*` beforehand, so an old/new mismatch caused by an interruption can be recovered from it (the Unlock failure
    error message will point this out).
12. **Windows ACLs**: pwhide does not programmatically tighten ACLs on Windows (harden prints icacls guidance); when --home points to a
    directory with loose ACLs, metadata and ciphertext may be readable by group/others.
13. The defenses of the root install path are: staging-directory-chain symlink checks + content structure validation (valid JSON) +
    O_EXCL temporary names + rename overwrite (does not follow links) + post-operation re-checking. A same-UID malicious process can
    still race to overwrite the staging (installing a "structurally valid" forged vault) — this belongs to the declared same-UID
    DoS/forgery surface; root owner verification only narrows cross-user forgery.
14b. Concurrent-write mutual exclusion = bare open + flock with a time-limited queue (60s; on timeout it reports "retry later"); .NET's
     FileShare/Access is emulated on Unix as exclusive fcntl (a concurrent open conflicts immediately, no waiting), so the lock file does
     not go through managed FileStream (except on Windows).
14c. When run directly as root (su / root-shell, SUDO_USER missing or root): neither directories nor files change owner; only permissions
     are tightened + the immutable flag applied (there is no real user to align with; chown root:root would lock the user out of their own
     vault). Files are 444 in this case — ciphertext being readable by local users is an accepted fallback (see the macOS staff entry).
14d. On filesystems that do not support chattr/chflags (overlayfs/tmpfs/NFS, etc.) the immutable flag degrades automatically (install is
     not blocked; the protection level is reported as-is by doctor/GetLevel).
14. DefaultShell in `config.json` (user-writable) is whitelisted (auto/bash/sh/pwsh/cmd/none only); an arbitrary executable path can
    only be specified via `--shell` typed in person by the user.
15. When a grandchild process holds the stdout pipe, the normal exit path waits at most another 10s, after which the tail of the output may be truncated (a data-loss surface, not a leak surface).
16. The rotate backup `run/rotate-backup.*` (600) is kept until the next rotate overwrites it; it is encrypted with the same passphrase as the current vault, so its leak surface is equivalent to the ciphertext itself.
17. **Shell metacharacter variants**: when the secret contains `"`/`'`/`$`/backtick/`\` and the placeholder goes through a nested shell
    (`sh -c "… {{db}} …"`) or script stdin mode, the second-level shell parses the secret into de-quoted/word-split/expanded variants —
    byte-exact redaction misses the variants, and variants or fragments may enter the output. Mitigation: exec prints a warning when it
    detects this combination; **secrets containing metacharacters should always be injected via `--env`** (the value travels through the
    environment and is never parsed by a shell — immune).
18b. **Windows output encoding**: PowerShell 5.1/cmd use the OEM/ANSI code page by default for redirected output — non-ASCII secrets
     are emitted as non-UTF-8 bytes and mismatch the redaction rules. Mitigation: command mode already forces UTF-8 output up front
     ([Console]::OutputEncoding / chcp 65001); script stdin mode is rejected outright on PS 5.1. If the target program itself emits
     the secret as non-UTF-8 (third-party program behavior), mismatches can still occur — on Windows, prefer --env injection and use
     ASCII secrets where possible.
18. **Wholesale home swapping** (Linux already re-checks key operations with inode snapshots; macOS relies on O_NOFOLLOW + up-front
    validation): in the combined scenario of multi-user + NOPASSWD + millisecond-scale races, the file operations of root install/harden
    can in theory still be redirected to another user's vault (a cross-user integrity break with no confidentiality gain) — an extension
    of the same-UID race surface into multi-user environments.
