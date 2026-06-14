# Check catalogue

Every finding the scanner can emit, what it means, and how to think about clearing it. This file exists so the tool is auditable: a security-conscious person should be able to read it in a few minutes and see exactly what is and isn't being checked. The skill is shared on the same untrusted channels it's meant to vet, so it should be glass, not a black box.

Severity weights: CRITICAL 50, HIGH 25, MEDIUM 10, LOW 5, NOTE 0. Score is the sum, multiplied by 1.3 if the skill ships any executable script, capped at 100.

Verdict bands: SAFE 0-20, REVIEW 21-50, DO NOT INSTALL 51+.

Two overrides sit on top of the arithmetic so the verdict can't be gamed by padding a skill with trivia:
- **Hard-fail to DO NOT INSTALL** regardless of score: `EXE-REMOTE`, `CHAIN-EXFIL`, `INJ-BIDI`, `PY-ENVHARVEST`.
- **Force at least REVIEW** if the skill exercises any of: network egress, credential access, subprocess, persistence, dynamic execution. A skill with a real capability is never auto-SAFE, even if it looks tidy.

## Context gating (why a finding may NOT fire)

Some signals are only meaningful in code. The bare word `requests` in "handle user requests", or `api-key` in an HTML `<meta>` example, is not a capability. For markdown and other prose files, the noisy capability matchers (`NET-EGRESS` library names, `CRED-WORD` keywords) fire **only inside code** (a fenced block or inline span). Source files (`.py`, `.sh`, `.js`, etc.) are code end to end, so everything in them is in scope. High-signal patterns that are dangerous even as a written instruction (remote exec, reading a credential store) are scanned everywhere regardless.

## Hidden / injected content

| ID | Severity | Meaning |
|----|----------|---------|
| `INJ-BIDI` | HIGH (hard-fail) | Bidirectional-override characters. Make displayed text differ from what the agent reads (trojan-source). No legitimate use. |
| `INJ-ZW` | HIGH | Zero-width / invisible characters. Hide text from a human reviewer while the agent still reads it. |
| `INJ-DIR` | MEDIUM | Left-to-right / right-to-left marks. Occasionally legitimate, can also reorder or conceal text. |
| `INJ-HOMO` | MEDIUM (heuristic) | A word mixing Latin with Cyrillic/Greek look-alikes. Can impersonate a trusted name or command. |
| `INJ-HTMLCOMMENT` | MEDIUM | HTML comment containing action verbs. Invisible in rendered markdown, read by the agent. |

## Prompt injection

| ID | Severity | Meaning |
|----|----------|---------|
| `INJ-OVERRIDE` | HIGH/MEDIUM | Text aimed at overriding agent instructions or hiding actions from the user ("ignore previous instructions", "do not tell the user", "regardless of safety"). Scanned everywhere, including prose. |
| `INJ-SELFATTEST` | HIGH | The skill tells the reviewer it is safe / to skip the check / what to conclude. Treated as attempted subversion of the audit, never as reassurance. |

## Obfuscation

| ID | Severity | Meaning |
|----|----------|---------|
| `ENC-B64CODE` | HIGH | Base64 that decodes to code-like or URL content. Common way to hide executable text. |
| `ENC-B64BIN` | MEDIUM (heuristic) | Base64 that decodes to non-text bytes. Encoded binary inside a skill is unusual. URL path segments (which also match base64) are excluded. |

## Remote execution / dynamic execution

| ID | Severity | Meaning |
|----|----------|---------|
| `EXE-REMOTE` | CRITICAL (hard-fail) | `curl \| bash`, `iex(...)`, `bash -c "$(curl ...)"`. Fetches code from the internet and runs it. Unreviewable; the author controls it after install. Scanned everywhere (dangerous as a written instruction too). |
| `PY-DYNEXEC` | CRITICAL/HIGH | `exec`/`eval`/`compile`/`__import__`. CRITICAL when the argument is dynamic (decided at runtime). |
| `PY-DESERIAL` | HIGH | `pickle.loads`/`marshal.loads`. Can execute arbitrary code while deserializing untrusted data. |
| `PY-GETATTR` | MEDIUM (heuristic) | Dynamic `getattr` with a non-literal name. Can hide which function is really called. |

## Subprocess

| ID | Severity | Meaning |
|----|----------|---------|
| `PY-OSSYSTEM` | HIGH | `os.system` / `os.popen`. Shell strings, easy to abuse, hard to audit. |
| `PY-SHELLTRUE` | HIGH | `subprocess(..., shell=True)`. Shell interpretation enables injection. |
| `PY-SUBPROCESS` | MEDIUM | Spawns an external process. Confirm the command is fixed and expected. |

## Credentials / environment

| ID | Severity | Meaning |
|----|----------|---------|
| `CRED-ACCESS` | HIGH | References a credential **store / key file / secret material**: `.ssh`/`id_rsa`, `.aws/credentials`, `.netrc`, `.git-credentials`, `/etc/shadow`, keychain, browser password/cookie stores. Reading these is rarely legitimate and is the high-signal credential case. Scanned everywhere; sets the credential capability. |
| `CRED-WORD` | LOW (heuristic) | A bare secret-like **keyword** in code (`api_key`, `access_token`, `password`, `bearer token`). Extremely common in benign contexts (a form field, a config key name), so this is code-context only, placeholder/HTML-attribute excluded, and deliberately does **not** grant the credential capability — it cannot by itself trigger the exfiltration chain. A glance, not an alarm. |
| `PY-ENVHARVEST` | HIGH (hard-fail) | Iterates over *all* environment variables. The pattern of sweeping every secret on the machine. |
| `PY-ENVIRON` | MEDIUM | Reads `os.environ`. Routine for one specific value; serious when combined with network egress. |

## Network

| ID | Severity | Meaning |
|----|----------|---------|
| `NET-EGRESS` | MEDIUM | Uses a network library or shell HTTP fetch. Fine for web-oriented skills; this is also how data leaves the machine. Code-context only in prose files (the word "requests" in a sentence is not the library). |
| `NET-SHORTENER` | MEDIUM | URL shortener. Hides the real destination. |
| `NET-RAWIP` | MEDIUM (heuristic) | Hard-coded raw IP rather than a named host. Unusual for legitimate endpoints. |

## Persistence

| ID | Severity | Meaning |
|----|----------|---------|
| `PERSIST` | HIGH | Touches a startup file, scheduler, or agent-config location (`crontab`, `.bashrc`, LaunchAgents, systemd, registry Run keys, `.claude/`, MCP config). Keeps running after the task or reconfigures the agent. |

## Supply chain

| ID | Severity | Meaning |
|----|----------|---------|
| `DEP-URL` | MEDIUM | Dependency installed from a URL/VCS rather than a pinned index package. Contents can change silently. |
| `DEP-UNPINNED` | LOW (heuristic) | Dependency with no version pin. A future malicious release could be pulled in. |
| `DEP-NPMHOOK` | HIGH | npm `pre`/`post`install hook. Runs at install time, before the skill is ever invoked. |
| `DEP-SETUPNET` | HIGH | `setup.py` does network/process work at install time. Installation should not have side effects. |

## Claim vs capability

| ID | Severity | Meaning |
|----|----------|---------|
| `META-MISMATCH` | MEDIUM (heuristic) | The code exercises a capability (network, credentials, subprocess, persistence) that the skill's description gives no hint of. Undisclosed capability is the most common tell of a plausible-looking but unsafe skill. In a multi-skill repo this is computed per skill, against that skill's own description. |
| `META-NODESC` | LOW (heuristic) | No description found to compare against. Only emitted when there is no `SKILL.md` description anywhere; in a multi-skill repo the per-skill descriptions are used instead. |

## Exfiltration chain

| ID | Severity | Meaning |
|----|----------|---------|
| `CHAIN-EXFIL` | CRITICAL (hard-fail) | **Within a single skill**, the code both accesses credentials/secrets and can reach the network. Conservative heuristic (not full taint tracking): the two together are the ingredients of credential exfiltration. Scoped per skill unit, so a credential reference in one skill and a network reference in an unrelated skill (or a research note) do not fuse into a false chain. |

## Meta

| ID | Severity | Meaning |
|----|----------|---------|
| `META-BINARY` | NOTE | A binary/non-UTF-8 file couldn't be analyzed. Static scanning is blind to it. |
| `PY-PARSE` | NOTE | A `.py` file couldn't be parsed, so its code wasn't AST-analyzed. Review manually. |

## Deep semantic review (`--deep`)

Opt-in. Does not call a model or the network; it extracts directive **prose** for the reviewing agent to classify against `references/semantic-review.md`. Output lives under `semantic_review` in the JSON, not in the findings list, and is keyed `SEM-NNN`. Candidates carry one or more signal categories:

| Signal | What it flags |
|--------|---------------|
| `secrets_access` | A secret/credential noun (credential, api key, private key, `.ssh`, `.aws`, `.env`, keychain, cookie, wallet) together with an access verb (read, open, send, fetch, dump, leak, ...) on the same line. |
| `agent_subversion` | Prose aimed at the agent: ignore/override/bypass prior or system instructions, "do not tell the user", "without asking", "regardless of safety", "on every message", "do not flag", "skip the check", or "silently/secretly + action". |
| `remote_exec` | A written instruction to fetch-and-run (`curl ... \| bash`), pipe to a shell, or "run this script". |
| `broad_access` | Sweeping reads: every file, the user's home/filesystem, enumerate/walk the directory, every environment variable, all of your memory/context/files. |
| `exfil` | An exfiltration verb (send, upload, transmit, forward, beacon, leak, post) pointed at a destination (http(s), url, endpoint, server, webhook, email, external/remote). |

**Merge policy (one direction only — escalate, never relax):** any candidate classified malicious → DO NOT INSTALL; any suspicious → at least REVIEW; all benign → keep the deterministic verdict.

## Known limits

- Static only: no runtime/dynamic behavior is observed.
- English-biased: injection text in other languages may be missed.
- Can't read binary, encrypted, or heavily obfuscated content.
- Taint tracking is a coarse co-occurrence heuristic (per skill), not real data-flow analysis.
- No live CVE/dependency database lookup (would require network and a dependency). Candidate for a later optional deep-scan mode.
- Deep mode is **non-deterministic** (the agent's judgment can vary), still English-biased, and exposes the reviewing agent to attacker-controlled prose. It raises recall on prose-level attacks; it does not make the verdict provable. An isolated model-call variant is intentionally omitted to keep the tool network-free and credential-free.
- **Self-scan paradox:** the scanner embeds every dangerous pattern it looks for as literal strings, so pointing it at its own source (or at any security tool that ships a signature list) returns a false DO NOT INSTALL. The AST checks stay clean; the text-level matchers trip on their own catalogue. This is expected. Do not run it on itself and read the result as a verdict.
