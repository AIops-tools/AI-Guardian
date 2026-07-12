---
name: ai-guardian
description: >
  Use this skill whenever the user needs to observe or govern on-endpoint local LLMs running on Ollama — inventory installed/running models with an allow/deny verdict (shadow-AI detection), inspect VRAM residency, model license/params/capabilities and server version, view the model policy, detect model provenance/digest drift (re-pulled or tampered weights), scan a prompt for secrets / PII / source-code / jailbreak with a weighted risk band, route a prompt THROUGH a guard that scans + policy-gates + records + runs-if-allowed (guarded_generate / observe_chat), query the observed-usage log, and roll up anomalies (shadow models, digest drift, high-risk + blocked prompts).
  Always use this skill for "what local models are installed", "find shadow / unsanctioned AI models", "which model is loaded in VRAM", "scan this prompt for secrets/PII before sending", "stop secrets leaking into a local model", "block a prompt with an API key", "detect a jailbreak / prompt injection", "set a model allowlist / denylist", "detect a tampered / re-pulled model", "audit local LLM usage", or "the complement to IGEL AI Armor".
  Do NOT use for GPU inference CLUSTERS (multi-node vLLM/Ray serving) — this is for single-endpoint LOCAL LLMs via Ollama; point cluster/serving work to the other AIops-tools. Also not for hypervisors, storage, backup, Kubernetes, or network devices.
  Preview — passive inventory/state auditing plus opt-in route-through content governance, with a bundled governance harness (audit, policy, token budget, undo, risk-tiers). Mock-validated only; a transparent capture proxy is v0.2 roadmap.
installer:
  kind: uv
  package: ai-guardian
argument-hint: "[model name, a prompt to scan, or describe your local-LLM task]"
allowed-tools:
  - Bash
metadata: {"openclaw":{"requires":{"env":[],"bins":["ai-guardian"],"config":["~/.ai-guardian/config.yaml"]},"optional":{"env":["AI_GUARDIAN_AIOPS_MASTER_PASSWORD"],"config":["~/.ai-guardian/secrets.enc","~/.ai-guardian/usage.db"]},"homepage":"https://github.com/AIops-tools/AI-Guardian","emoji":"🛡️","os":["macos","linux"]}}
compatibility: >
  Standalone, self-governed local-LLM (Ollama) observability + content governance (preview). The governance harness (audit, policy, token/runaway budget, undo, risk-tiers) is bundled in the package — no external skill-family dependency.
  Every tool call is audited to a local SQLite DB at ~/.ai-guardian/audit.db (relocatable via AI_GUARDIAN_AIOPS_HOME); the OBSERVED local-LLM usage log is a SEPARATE DB at ~/.ai-guardian/usage.db.
  Zero-config: ai-guardian defaults to the local Ollama at http://localhost:11434 with no token. Ollama endpoints usually run open on a trusted host, so a bearer token is OPTIONAL; when one is supplied it is stored ENCRYPTED in ~/.ai-guardian/secrets.enc (Fernet/AES-128 + scrypt-derived key) — never plaintext on disk. The store is unlocked by a master password from AI_GUARDIAN_AIOPS_MASTER_PASSWORD (non-interactive/MCP/CI) or an interactive prompt (CLI on a TTY). A legacy plaintext env var AI_GUARDIAN_<TARGET_NAME_UPPER>_TOKEN is still honoured as a fallback with a deprecation warning (migrate with 'ai-guardian secret migrate').
  The prompt scanner is deterministic and offline (no I/O, no network); route-through guards (guarded_generate/observe_chat) call Ollama only if the prompt's risk band is below block_threshold AND the model is allowed. The raw prompt is never stored — only its length + redacted findings.
  State-changing operations: remove_model (high, dry-run + double confirm at the CLI, undo re-pull, approver-gated); pull/unload/allowlist/denylist/pin/guarded writes are medium. All write tools pass through the @governed_tool decorator (pre-check + budget guard + audit + risk-tier gate).
  Webhooks: none — no outbound network calls beyond the configured Ollama REST API.
  Transitive dependencies: httpx (HTTP client) and the MCP SDK. No post-install scripts or background services.
  PREVIEW: mock-validated only; content governance is opt-in route-through in v0.1, a transparent capture proxy is v0.2 roadmap, and IGEL AI Armor interop is doc-level positioning.
---

# AI Guardian (preview)

> **Disclaimer**: Community-maintained open-source project, **not affiliated with, endorsed by, or sponsored by Ollama, IGEL, or any AI-security vendor.** Product and trademark names belong to their owners. Source at [github.com/AIops-tools/AI-Guardian](https://github.com/AIops-tools/AI-Guardian) under the MIT license.

Governed observability + governance for **on-endpoint local LLMs (Ollama)** —
**18 MCP tools**, every one wrapped with the bundled `@governed_tool` harness: a
local unified audit log under `~/.ai-guardian/`, policy engine, token/runaway
budget guard, undo-token recording, and graduated-autonomy risk tiers. It is the
**complement to IGEL AI Armor**: AI Armor governs *whether* a local model may run;
ai-guardian records *what it did* and gates *what leaves in the prompt*.

Ollama keeps **no queryable prompt history** (context is client-supplied each
request), so ai-guardian observes on two fronts: **passive inventory / state
auditing** over `/api/tags`, `/api/ps`, `/api/show`, `/api/version`; and **opt-in
route-through content governance** — a caller sends a prompt *through*
`guarded_generate` / `observe_chat`, which scans + policy-gates + records it and
only then calls Ollama.

> **Standalone**: the governance harness is bundled in the package
> (`ai_guardian.governance`) — no external skill-family dependency. **Preview /
> mock-only**: a transparent capture proxy for other clients' traffic is v0.2
> roadmap, and IGEL AI Armor interop is doc-level positioning.

## What This Skill Does

| Group | Tools | Count | Read/Write |
|-------|-------|:-----:|:----------:|
| **Inventory / state** | `list_models`, `running_models`, `model_details`, `server_status`, `vram_usage` | 5 | read |
| **Policy / provenance** | `policy_view`, `model_provenance` | 2 | read |
| **Content governance (read)** | `scan_prompt`, `usage_events`, `anomaly_report` | 3 | read |
| **Model lifecycle** | `pull_model` (medium), `remove_model` (high), `unload_model` (medium) | 3 | write |
| **Policy writes** | `set_model_allowlist`, `set_model_denylist`, `pin_model_digest` (all medium) | 3 | write |
| **Route-through guard** | `guarded_generate`, `observe_chat` (medium) | 2 | write |

`scan_prompt` is pure (no Ollama call). `guarded_generate` / `observe_chat` block
when the prompt's risk band `>= block_threshold` (default `high`) **or** the model
is disallowed; blocked calls never reach Ollama and are recorded as blocked.

## Quick Install

```bash
uv tool install ai-guardian-aiops
ai-guardian doctor          # works zero-config against a local Ollama
ai-guardian init            # optional: endpoint(s) + optional token + model allowlist
```

## When to Use This Skill

- Inventory local models and **spot shadow AI** (`list_models` / `anomaly_report`): unsanctioned models show `allowed:false`
- **Scan a prompt before sending it** (`scan_prompt`): secrets / PII / source-code / jailbreak → a weighted risk band, no model call
- **Stop secrets or PII leaking into a local model** (`guarded_generate` / `observe_chat`): scan + policy-gate + record, then run only if allowed
- **Detect a tampered / re-pulled model** (`model_provenance`): current digest vs its pin → drift
- Enforce which models may run (`set_model_allowlist` / `set_model_denylist`) and pin trusted digests (`pin_model_digest`)
- Inspect VRAM residency (`running_models` / `vram_usage`) and audit observed usage (`usage_events`)

**Do NOT use when** the target is a GPU inference **cluster** (multi-node serving) — that is a different tool in the AIops-tools line. Also not for hypervisors, storage appliances, backup products, container clusters, or network devices.

## Related Skills — Skill Routing

| If the user wants… | Use |
|--------------------|-----|
| On-endpoint local LLM (Ollama): scan prompts, shadow-AI, provenance, policy | **ai-guardian** (this skill) |
| GPU inference **cluster** serving/ops | another AIops-tools skill for cluster serving |
| Hypervisor / storage / backup / container / network ops | the matching AIops-tools skill |

## Common Workflows

### Find shadow (unsanctioned) local models

1. `list_models` → every model with its allow/deny verdict; anything `allowed:false` is shadow AI
2. `anomaly_report` → a one-shot rollup of shadow models + digest drift + high-risk / blocked prompts
3. Tighten the policy: `set_model_allowlist(["llama3.*", "qwen*"])` so future shadow models are refused at `pull_model`

### Stop secrets leaking into a local model

1. Route the call through the guard: `guarded_generate(model, prompt, block_threshold="high")`
2. The guard scans the prompt (secrets/PII/code/jailbreak), records it to the usage log, and **blocks** before Ollama if the risk band is `>= high` or the model is disallowed
3. Review what was caught with `usage_events(allowed=False)` — the raw prompt is never stored, only its length + redacted findings

### Detect a tampered / re-pulled model

1. Pin the trusted digest once: `pin_model_digest(model, digest)` (digest from `list_models` / `model_details`)
2. Later, `model_provenance` → any model whose current digest differs from its pin shows `status: DRIFT` (re-pulled / tampered weights)

### Scan a prompt before sending (no model call)

Call `scan_prompt("…text…")` (or `ai-guardian guard scan "…"`) to get findings +
the weighted risk band deterministically — useful to pre-check anything offline
before it ever reaches a local model.

## Governance & Safety

- Every tool call is audited to `~/.ai-guardian/audit.db` (relocatable via `AI_GUARDIAN_AIOPS_HOME`); observed local-LLM usage lives in a **separate** `~/.ai-guardian/usage.db`.
- High-risk `remove_model` can require a named approver: set `AI_GUARDIAN_AUDIT_APPROVED_BY` and `AI_GUARDIAN_AUDIT_RATIONALE`.
- `remove_model` supports `--dry-run` + double confirmation at the CLI and records an undo (re-pull); allowlist/denylist writes record an undo → the prior list.
- The scanner is deterministic and offline; findings are redacted so a secret is never re-emitted.

## References

- `references/capabilities.md` — full 18-tool + endpoint reference
- `references/cli-reference.md` — CLI command reference
- `references/setup-guide.md` — onboarding, optional token, and connectivity
