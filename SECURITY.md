# Security Policy

## Disclaimer

Community-maintained open-source project. **Not affiliated with, endorsed by, or
sponsored by Ollama or IGEL.** Product and trademark names (Ollama, IGEL AI
Armor) belong to their owners. Source is publicly auditable under the MIT license.

## Reporting Vulnerabilities

Report privately via a GitHub Security Advisory on
[github.com/AIops-tools/AI-Guardian](https://github.com/AIops-tools/AI-Guardian/security/advisories)
or email zhouwei008@gmail.com. Please do not open public issues for security
reports.

## Security Design

### Credential Management
- A bearer token is **optional** — local Ollama usually runs open. When used,
  per-target tokens live **encrypted** in `~/.ai-guardian/secrets.enc`
  (Fernet/AES-128 + scrypt-derived key; chmod 600), never in `config.yaml` and
  never in source. The master password is never stored — only a per-store random
  salt and the ciphertext are on disk.
- A legacy plaintext env var `AI_GUARDIAN_<TARGET_NAME_UPPER>_TOKEN` is honoured
  as a fallback with a deprecation warning (`ai-guardian secret migrate`).
- When present the token is an `Authorization: Bearer` header held only in memory;
  never logged or echoed. The config file holds only host, port, scheme, TLS, and
  the (non-secret) model allow/deny policy + digest pins.

### Content handling — the prompt scanner never re-emits what it catches
- The scanner (`scan_prompt`, `guarded_generate`, `observe_chat`) flags secrets /
  PII / source-code / jailbreak content. Every finding is **redacted** to a short
  masked preview, so a finding never echoes the full secret it caught.
- The observed-usage log (`~/.ai-guardian/usage.db`) stores only the prompt
  **length** + the (already-masked) findings — **never the raw prompt text**. It
  never becomes a second copy of the secrets it detected.

### Governed Operations
Every MCP tool runs through the bundled `@governed_tool` harness
(`ai_guardian.governance`):
- **Audit** — every call logged to a local SQLite DB under `~/.ai-guardian/`
  (relocatable via `AI_GUARDIAN_AIOPS_HOME`), agent-attributed, secret-redacted.
- **Token/runaway budget** — hard ceilings (`AI_GUARDIAN_MAX_TOOL_CALLS` /
  `AI_GUARDIAN_MAX_TOOL_SECONDS`) plus an on-by-default guard that trips a tight
  poll/retry loop, preventing unbounded API consumption (e.g. polling a slow
  session).
- **Graduated risk tiers** — `~/.ai-guardian/rules.yaml` `risk_tiers` gate
  writes by environment/tag; the highest tiers require a recorded approver.
- **Undo-token recording** — reversible writes capture prior state and record an
  inverse (e.g. `remove_model` captures the manifest so the harness records a
  re-pull undo; `set_model_allowlist`/`set_model_denylist` restore the prior policy).

### State-Changing Operations
The only destructive op is `remove_model` (`risk_level=high`): it deletes a local
model, so it accepts a `dry_run` preview, is double-confirmed at the CLI, and
requires a recorded approver (`AI_GUARDIAN_AUDIT_APPROVED_BY`) under the policy.
`pull_model` (refused if it violates the deny/allow policy), `unload_model`, the
policy writes, and `guarded_generate`/`observe_chat` are `risk_level=medium`.

### Prompt-Injection Protection
A local model's metadata (names, licenses, templates) and all responses are
treated as untrusted: they pass through a `sanitize()` truncate + control-char
strip before reaching the agent.

### Network Scope
The only outbound calls are to the configured **Ollama** endpoint(s) — no
webhooks, no telemetry, no other outbound traffic. No post-install scripts or
background services.

## Static Analysis

```bash
uvx bandit -r ai_guardian/ mcp_server/
uv run ruff check .
```

## Supported Versions

The latest released version receives security fixes. This is a preview (0.x);
pin a version in production.
