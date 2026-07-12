# AI Guardian v0.1.0 — preview

Governed **observability + governance for on-endpoint local LLMs (Ollama)** for
AI agents — the complement to **IGEL AI Armor**. AI Armor governs *whether* a
local model may run; ai-guardian records *what it did* and gates *what leaves in
the prompt*. Ships with a bundled governance harness (audit, policy, token/runaway
budget, undo-token recording, graduated risk tiers) and an encrypted credential
store. Standalone — no external skill-family dependency.

> **Preview / mock-only.** The scanner, policy, and risk-band are pure
> deterministic offline logic; the Ollama API paths are exercised against mocked
> responses. The fastest live check is `ai-guardian doctor` against a local Ollama.

## Highlights

- **18 MCP tools** (10 read, 8 write), every one wrapped with `@governed_tool`.
  - Read: `list_models` (annotated with allow/deny verdict), `running_models`,
    `model_details`, `server_status`, `vram_usage`, `policy_view`,
    `model_provenance`, `scan_prompt` (pure — no model call), `usage_events`,
    `anomaly_report`.
  - Write: `pull_model` (refused if it violates policy), `remove_model` (high,
    dry-run + undo re-pull, approver-gated), `unload_model`, `set_model_allowlist`,
    `set_model_denylist`, `pin_model_digest`, `guarded_generate` /
    `observe_chat` (the route-through guard).
- **Two observation modes** — passive inventory/state auditing over `/api/tags`,
  `/api/ps`, `/api/show`, `/api/version`; and opt-in **route-through content
  governance** that scans + policy-gates + records a prompt before calling Ollama.
- **Deterministic offline scanner** — secrets (AWS AKIA, private-key blocks,
  GitHub / Slack / OpenAI / Google tokens, JWTs, assigned `api_key=…`,
  high-entropy fallback), PII (email, US SSN, credit card with a Luhn check),
  source/config-leak heuristics, and jailbreak / prompt-injection signatures →
  a weighted risk band (low / medium / high / critical). Findings are redacted.
- **Model allow/deny policy** (shell globs) so shadow models show `allowed:false`,
  plus **provenance digest pinning** to flag re-pulled / tampered models.
- **Encrypted token store** (`~/.ai-guardian/secrets.enc`, Fernet + scrypt) — a
  bearer token is optional (rare for local Ollama); never plaintext on disk;
  legacy `AI_GUARDIAN_<TARGET>_TOKEN` env fallback.
- **CLI** with an `init` onboarding wizard, `secret` management, `guard`
  sub-commands (policy / provenance / scan / usage / anomalies), and `doctor`.
- **Zero-config** — works out of the box against a local Ollama on
  `localhost:11434`.

## Install

```bash
uv tool install ai-guardian-aiops
ai-guardian init      # optional: Ollama endpoint(s) + optional token + model allowlist
ai-guardian doctor
```

## Caveats

- **Preview / mock-only** — not yet validated against a production Ollama fleet.
- v0.1 content governance is **opt-in route-through**; a **transparent capture
  proxy** for other clients' traffic is **v0.2 roadmap**.
- **IGEL AI Armor interop** is doc-level positioning, not a wired integration.
- Out of scope by design: GPU inference-cluster ops, model training/fine-tuning,
  and any non-Ollama local-LLM runtime.
