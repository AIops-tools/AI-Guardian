# Changelog

## v0.10.0 — 2026-08-11

### Added
- **Transparent capture proxy** (`ai-guardian proxy serve`) — the v0.2 roadmap item this tool has advertised since v0.1. `guarded_generate` only governs callers that choose to route through it; the proxy applies the same scan, model policy, and recording to traffic from a client that never opted in. Point the client at the listener instead of the runtime (`OLLAMA_HOST=http://127.0.0.1:11435`) and nothing else changes. Governs `/api/generate`, `/api/chat`, `/v1/chat/completions`, `/v1/completions`; every other path is forwarded untouched. Built on the standard library's threading HTTP server plus the `httpx` already depended on — no new dependency, because a governance tool should not grow a web framework and an undeclared transport dependency is its own bug class.
- **`proxy_guidance`** (read, 21st tool) composes the command and the client-side change, and writes nothing. CLI-only for `serve` itself: it blocks for the lifetime of the listener, so an MCP tool that started it would hang the calling agent — the same line the sibling compliance tool draws with its cron hint.

### Design decisions worth stating plainly
- **It is a chokepoint, not an enforcement boundary.** A client that can still reach the runtime's real port bypasses the proxy completely, and nothing here can detect that. A control assumed to be mandatory while being trivially bypassable is the false-safety failure this line hunts, so it is in the tool's return value, in the docs, and printed by the CLI on **every** start — not buried. Making it enforcing is an operator task (bind the runtime to localhost, expose only the proxy, or firewall the runtime port); until then captured traffic is a sample, not the population.
- **Requests are inspected; responses stream through untouched.** These clients default to `stream: true`, and buffering a response to inspect the completion would turn every streaming caller into a blocking one — breaking the thing the proxy was installed to protect. The guard governs prompts, exactly as the opt-in path already does.
- **An unscannable request on a governed path is refused, not forwarded.** A body that cannot be parsed as JSON, or that exceeds the scan size cap, is rejected: a proxy a malformed body walks straight past is a suggestion rather than a control.
- **Raw prompts are still never stored.** Captured traffic lands in the ordinary usage log with prompt length, risk band, and redacted findings, so `usage_events` and `anomaly_report` surface it with no new read surface.
- A failing recorder logs and continues: recording is bookkeeping, and losing it must not drop a client's request.

### Verified
Driven over **real HTTP** rather than mocks — a stub upstream on a real socket with a real proxy in front of it, plus the actual CLI against a stub runtime:
- a prompt carrying an AWS access key was blocked with `riskBand: critical` and **never reached the upstream** (asserted on what the upstream received, not merely on the client's 403);
- a denied model was refused with the policy reason while an allowed model passed;
- an ungoverned path (`/api/tags`) passed through and recorded nothing;
- a chunked multi-part response relayed through intact and in order, with upstream headers preserved and hop-by-hop headers dropped;
- an unreachable upstream produced a 502 naming the proxy, so it cannot be mistaken for a model failure;
- the usage log contained the lengths, bands, and findings — and a byte search of the database found **no raw prompt text**.

**Still unverified:** no run against a real Ollama. The request/response shapes exercised are this tool's own, not measured from the runtime, so treat the Ollama-specific behaviour (streaming NDJSON semantics in particular) as unconfirmed until `docs/VERIFICATION.md` says otherwise.

### Fixed
- OpenAI multi-part message content contributed empty strings for non-text parts (an `image_url`), padding the scanned text with blank lines and inflating the recorded `promptChars`. Caught by a unit test on the extractor.
- `proxy serve` crashed on startup with `'AppConfig' object has no attribute 'name'`: `get_connection` returns `(conn, AppConfig)`, and the resolved target has to come from the config. Caught by running the command rather than only its parts.

## v0.9.0 — 2026-08-10

### Fixed
- **An undetermined outcome no longer exits as a plain failure.** A write whose response was lost carries *both* `error` and `outcomeUnknown`, and the harness deliberately judges unknown first when writing the audit row — the change may have taken effect, so a blind retry could apply it twice. The CLI guard judged `error` first, so the audit said "may have taken effect" while the exit status told a script it had not happened. The two layers now agree (exit 2, not 1), and a test pins the ordering so it cannot silently flip back.
- **The CLI reported a refused or failed governed write as a success.** 4 write call sites printed the governed twin's payload and exited **0** whatever it said — and `@tool_errors` flattens every refusal, guard rejection and upstream failure into `{"error": ...}` rather than raising, so nothing downstream of a `&&` chain or a CI step could tell a blocked write from a landed one. The dry-run path already exited non-zero, which made the asymmetry worse: the preview was stricter than the write it previews. Results now route through a `checked()` helper — exit 1 on an error payload, exit 2 on an undetermined outcome, unchanged on success. This defect class had been fixed repo-by-repo several times and kept coming back; an audit across the whole line found it live in **18 of the 24 tools at once (87 call sites)**, so each tool now carries an invariant test that fails if any future CLI command prints a governed result without checking it.

## v0.8.0 — 2026-08-03

### Fixed
- **An unusable digest pin no longer switches the provenance guard off.** A pin that was not a string travelled through and then read as falsy, so `model_provenance` reported the model `unpinned` with `driftCount: 0` — a tamper check answering "nothing to check" instead of "this does not match". YAML is the usual culprit: an unquoted all-digit digest parses as an int. Pins are normalised to strings at the config boundary, so an unusable one simply never matches and surfaces as `DRIFT`. A blank value is still treated as "no pin", which is what it looks like.
- **`undo apply` replays against the target the original write ran on.** It dispatched the inverse against whatever target the *caller* named — in practice the config's first entry — while the write's own target sat unused in the undo record. On a multi-target config the inverse therefore ran against the wrong host; it only looks harmless because the resource usually is not there, but two hosts holding the same name and the inverse **succeeds on the wrong one, silently**. An explicitly named target still wins. Line-wide: all 24 copies had the identical defect. Caught live in container-host-aiops, where a stop recorded against a Podman target replayed against a Portainer one.

## v0.7.0 — 2026-08-02

### Changed (BREAKING)
- **Requires MCP SDK 2.0** (`mcp[cli]>=2.0,<3.0`). `mcp.server.fastmcp` no longer exists in 2.0; the server is now built with `MCPServer` and reports its package version in the stdio handshake.

### Fixed
- **`undo apply` works from the CLI.** Every write tool is imported lazily inside its own CLI command, so a CLI-driven undo ran in a process where the inverse tool was never registered and failed with "inverse tool is not registered" — for every write tool. Only the MCP entry point, which imports the whole server, worked. Found while live-verifying against a real cluster.
- **An undetermined outcome is audited `unknown`, not `ok`.** The harness only classified a result as undetermined when the payload *also* carried an `error` key, so a write that looked successful but had not been confirmed was recorded as a success.


## v0.6.0 — 2026-07-21

### Changed (BREAKING)
- **Removed the authorization layer** — read-only mode, the approver gate, and rules.yaml deny are gone. The skill no longer decides read vs write; that is the agent's judgement or the connecting account's permissions. `<PREFIX>_READ_ONLY` now has no effect (a startup warning is logged); `<PREFIX>_AUDIT_APPROVED_BY`/`_RATIONALE` are optional audit annotations.
- The retained guarantee is **unbypassable audit over MCP and CLI alike** — no unaudited entry point. Harness = audit + runaway safety guard + undo + sanitize; `risk_level` is a descriptive audit label, not a gate.

See RELEASE_NOTES.md for tool-specific changes.


## v0.5.0 — 2026-07-20

### Fixed
- **`remove_model` no longer records an undo it knows will be refused.** Its inverse is `pull_model`, which the tool's own policy engine rejects for a denied model — so the natural sequence (deny a model, then remove it) left a token that looked valid in `undo_list` and failed at `undo_apply`.
- Harness: a write whose response is lost is audited `status=unknown`, not `error` — it may have taken effect. Undo tokens gain `effectVerified` (undo.db migrated in place).
- Harness: a dry-run no longer records an undo token, and no longer requires a named approver. Guards now run on the preview path.
- Truncated strings end in an ellipsis instead of being cut silently; error messages are capped at 800 chars, not 300.

See RELEASE_NOTES.md for the full detail.

## v0.3.0 — 2026-07-17

### Added
- **New:** llama.cpp / LM Studio / local vLLM runtimes via one OpenAI-compatible transport.
- **Undo executor**: `undo list` / `undo apply <id>` (CLI + MCP) — apply a recorded replayable inverse; the dispatched inverse is re-gated by its own risk tier; single-use, dry-run, double-confirm, both wrapper + inverse audited.

## v0.7.0 — 2026-08-02

### Added
- **Multiple local-LLM runtimes** beyond Ollama, via a runtime registry
  (`ai_guardian/runtimes.py`) selected per target by a `runtime` config field:
  - **llama.cpp** (`llama-server`) — OpenAI-compatible `/v1` plus native `/health`
    and `/props` (served model path/size → a pinnable provenance digest).
  - **LM Studio** — OpenAI-compatible local server (default `:1234`).
  - **vLLM** — OpenAI-compatible **LOCAL single-node** endpoint (default `:8000`).
    GPU inference-**cluster** ops remain out of scope (→ inference-aiops).
  All three share ONE `openai_compat` transport (`ai_guardian/ops/openai_compat.py`);
  per-runtime metadata (default port, health path, provenance strength) lives in
  the registry. Allow/deny policy verdicts, the route-through guard
  (`guarded_generate` / `observe_chat`), provenance drift, `doctor`, and the `init`
  wizard now all work across runtimes.
- Provenance is honest per runtime: `digest` (Ollama), `props`-derived (llama.cpp),
  and `id_only` (LM Studio / vLLM) — a pinned id-only model with no digest is
  reported `unverifiable`, never a false `DRIFT`.

### Notes
- Model lifecycle writes (`pull` / `remove` / `unload`) are Ollama-only; the
  OpenAI-compatible servers load a model at startup and refuse those writes with a
  clear message.

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
