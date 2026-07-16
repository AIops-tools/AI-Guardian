# Changelog

## v0.2.1 — 2026-07-16

### Fixed
- **`secrets.enc` now follows `AI_GUARDIAN_AIOPS_HOME`** (secretstore hardcoded the real
  home directory; config/audit/undo already relocated — found in live verification).
- **Audit fidelity**: failures sanitized into `{"error": ...}` results by the MCP error
  layer are now audited as `status=error` (they previously read as `ok`, hiding failed
  attempts from exception reports), and no undo is recorded for a call that failed.

### Tests
- `doctor` and the `init` wizard are now fully covered (previously ~10–20%); plus a
  regression test for the sanitized-failure audit status.

## v0.2.0 — 2026-07-13

Security-hardening release from a line-wide code review.

### Changed (behavior)
- **Secure by default**: with no `rules.yaml`, high/critical operations now require a
  named approver (`AI_GUARDIAN_AUDIT_APPROVED_BY`). A fresh install no longer allows
  destructive writes unattended; `init` seeds a starter `rules.yaml` you can edit,
  and an operator-authored rules file is honoured as-is.
- `__version__` is now single-sourced from package metadata (the previous release
  self-reported a stale version string).
- Sanitize docs no longer overstate scope: it strips control/format characters and
  truncates; semantic prompt-injection resistance must come from the consuming agent.

### Fixed
- (no tool-specific fixes; line-wide items above)

### Tests
- Governance persistence is now tested against REAL `audit.db`/`undo.db` files
  (write → audit row + inverse undo row with captured prior state).
- The CLI confirmed-write path (dry-run / double-confirm / governed execution) is
  covered end-to-end.
- `pytest-cov` added to the dev dependencies.

## v0.1.1

- Fix: `AI_GUARDIAN_AIOPS_HOME` now also relocates `config.yaml` (was hardcoded to `~/.ai-guardian`).
- Fix: **CLI writes are now audited + undo-recorded** via the governance path — previously only the MCP tools recorded audit/undo; CLI `manage`/`remediate`/etc. writes now go through the same `@governed_tool` layer (they keep their dry-run + double-confirm). CLI write output is now the governed JSON result. No API/tool changes.


All notable changes to ai-guardian are documented here. This project adheres
to [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

## [0.1.0] — preview

Initial preview release: governed observability + governance for on-endpoint
local LLMs (Ollama) — the complement to IGEL AI Armor. Ships with a bundled
governance harness. **Mock-validated only — not yet verified against a
production Ollama fleet.**

### Added

- **18 MCP tools** (10 read, 8 write), every one wrapped with the bundled
  `@governed_tool` harness (audit, policy, token/runaway budget, undo,
  risk-tiers):
  - **Inventory / state (read)** — `list_models` (each model annotated with the
    allow/deny verdict; shadow models show `allowed:false`), `running_models`
    (VRAM + residency), `model_details` (license/params/capabilities),
    `server_status` (reachability + version), `vram_usage` (flag over-budget).
  - **Policy / provenance (read)** — `policy_view` (allow/deny + digest pins),
    `model_provenance` (digest-drift detection).
  - **Content governance (read)** — `scan_prompt` (pure deterministic scan →
    findings + risk band, no model call), `usage_events` (query the observed-usage
    log), `anomaly_report` (rollup: shadow models, digest drift, high-risk +
    blocked prompts).
  - **Model lifecycle (write)** — `pull_model` (medium; refused if it violates
    policy), `remove_model` (high; dry-run + undo → re-pull; approver-gated),
    `unload_model` (medium; `keep_alive:0` VRAM evict).
  - **Policy writes** — `set_model_allowlist` (medium; undo → prior),
    `set_model_denylist` (medium; undo → prior), `pin_model_digest` (medium).
  - **Route-through guard (write)** — `guarded_generate` and `observe_chat`
    (medium): scan the prompt (secrets/PII/code/jailbreak), check the model
    against policy, record it, and only call Ollama if the risk band is below
    `block_threshold` (default `high`) and the model is allowed. The raw prompt is
    never stored — only its length + redacted findings.
- **Deterministic offline scanner** (`ai_guardian.scanner`) — secrets (AWS AKIA,
  private-key blocks, GitHub / Slack / OpenAI / Google tokens, JWTs, assigned
  `api_key=…`, high-entropy fallback), PII (email, US SSN, credit card with a Luhn
  check), source/config-leak heuristics, and jailbreak / prompt-injection
  signatures → a weighted risk band (low / medium / high / critical; any critical
  dominates). Findings are redacted.
- **Model policy + provenance** (`ai_guardian.ops.policy`) — shell-glob
  `allowed_models` / `denied_models` (deny always wins; empty allowlist =
  allow-all) and `pinned_digests` for drift detection.
- **Observed-usage log** (`ai_guardian.usage`) — SQLite at
  `~/.ai-guardian/usage.db`, separate from the governance `audit.db`.
- **Encrypted secret store** — an optional bearer token is stored encrypted in
  `~/.ai-guardian/secrets.enc` (Fernet + scrypt); never plaintext on disk. Legacy
  `AI_GUARDIAN_<TARGET>_TOKEN` env var honoured as a fallback.
- **CLI** (`ai-guardian`) — `init` wizard, `overview`, `model`
  (list/running/details/pull/remove/unload), `guard`
  (policy/provenance/scan/usage/anomalies), `secret`
  (set/list/rm/migrate/rotate-password), `doctor`, `mcp`. Works zero-config
  against the local Ollama.
- **Connection layer** over Ollama's REST API (`/api/*`, default
  `http://localhost:11434`); optional `Authorization: Bearer` token.

### Known limitations

- Preview / mock-only: the Ollama API paths are exercised against mocked
  responses and need live verification against a production fleet.
- v0.1 content governance is **opt-in route-through**; a **transparent capture
  proxy** for other clients' traffic is planned for **v0.2**.
- IGEL AI Armor interop is doc-level positioning, not a wired integration.
- Out of scope by design: GPU inference-cluster ops, model training/fine-tuning,
  and non-Ollama local-LLM runtimes.
