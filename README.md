<!-- mcp-name: io.github.AIops-tools/ai-guardian -->

# AI Guardian (preview)

> **Disclaimer**: Community-maintained open-source project. **Not affiliated with, endorsed by, or sponsored by Ollama, IGEL, or any AI-security vendor.** Product and trademark names belong to their owners. MIT licensed.

Governed **observability + governance for on-endpoint local LLMs** (Ollama). It
lets you **observe + audit what your local models are actually fed, and gate
what leaves in a prompt** — the complement to **IGEL AI Armor**. AI Armor governs
*whether* a local model may run on the endpoint; ai-guardian records *what it did*
and gates *what goes into the prompt* (secrets, PII, source, jailbreaks) plus
*which model* may serve it. Self-contained: it talks to Ollama's REST API
(default `http://localhost:11434`, usually no auth) and needs nothing beyond
`httpx` and the MCP SDK. **Preview — mock-validated only; v0.1 route-through
content governance, with a transparent capture proxy on the v0.2 roadmap.**

## What it does

Ollama persists **no queryable prompt/response history** — conversational context
is client-supplied on every request. So ai-guardian observes on two fronts:

- **Passive inventory / state auditing** — over `/api/tags`, `/api/ps`,
  `/api/show`, `/api/version`: what models are installed and running, their VRAM
  residency, license/params/capabilities, and their **provenance digests**. Every
  model is annotated with an allow/deny **policy verdict**, so shadow
  (unsanctioned) models show `allowed: false`.
- **Opt-in route-through content governance** — callers send a prompt *through*
  ai-guardian (`guarded_generate` / `observe_chat`). It **scans** the text
  (secrets / PII / source / jailbreak), **checks the model** against policy,
  **records** the interaction to its own usage log (`~/.ai-guardian/usage.db`),
  and **only then** calls Ollama — blocking when the risk band is too high or the
  model is disallowed. The raw prompt is never stored (only its length + redacted
  findings).

> A transparent reverse-proxy shim that captures *other* clients' Ollama traffic
> passively is a documented **v0.2 roadmap** item, not v0.1.

## Key features

- **Deterministic, offline prompt scanner** — no I/O, no network, so it is fully
  testable offline. Flags **secrets** (AWS `AKIA`, private-key blocks,
  GitHub / Slack / OpenAI / Google tokens, JWTs, assigned `api_key=…`, high-entropy
  fallback), **PII** (email, US SSN, credit card **with a Luhn check**),
  **source/config-leak** heuristics, and **jailbreak / prompt-injection**
  signatures — rolled up into a **weighted risk band** (low / medium / high /
  critical; any critical dominates). Findings are **redacted** — the scanner never
  re-emits the secret it caught.
- **Model allow/deny policy** (shell-glob patterns) so shadow / unsanctioned
  models surface as `allowed: false`, plus **provenance digest pinning** to flag a
  model whose digest drifted (re-pulled / tampered).
- **Route-through guard** — `guarded_generate` / `observe_chat` scan + policy-gate
  + record + run-if-allowed, blocking on risk-band >= `block_threshold` (default
  `high`) or a disallowed model.
- **Vendored governance harness** — audit log, token/runaway budget guard,
  graduated-autonomy risk tiers, and undo-token recording, bundled in the package
  (no external dependency).
- **Highly self-testable** — Ollama is free + local for the API parts; the
  scanner, policy, and risk-band are pure deterministic offline logic.

## Capability matrix (18 MCP tools)

### Reads (10)

| Tool | Risk | What it returns |
|------|:----:|-----------------|
| `list_models` | low | installed models, each with the allow/deny verdict (shadow → `allowed:false`) |
| `running_models` | low | loaded models: VRAM footprint + residency expiry |
| `model_details` | low | license / parameters / capabilities for one model |
| `server_status` | low | Ollama reachability + version |
| `vram_usage` | low | total VRAM used by loaded models; flag over-budget |
| `policy_view` | low | current allow/deny policy + provenance digest pins |
| `model_provenance` | low | each installed digest vs its pin; flag **drift** |
| `scan_prompt` | low | pure text scan → findings + weighted risk band (**no model call**) |
| `usage_events` | low | query the observed-usage log |
| `anomaly_report` | low | rollup: shadow models, digest drift, high-risk + blocked prompts |

### Writes (8)

| Tool | Risk | Undo / safety |
|------|:----:|---------------|
| `pull_model` | medium | refused if it violates policy |
| `remove_model` | **high** | dry-run + undo (re-pull); requires an approver |
| `unload_model` | medium | evict from VRAM (`keep_alive:0`) |
| `set_model_allowlist` | medium | undo → prior allowlist |
| `set_model_denylist` | medium | undo → prior denylist |
| `pin_model_digest` | medium | pin a model's expected provenance digest |
| `guarded_generate` | medium | the route-through guard: scan + policy-gate + record + run-if-allowed |
| `observe_chat` | medium | same, for `/api/chat` messages |

Risk-band gating: `guarded_generate` / `observe_chat` **block** when the prompt's
risk band `>= block_threshold` (default `high`) **or** the model is disallowed.
Blocked calls never reach Ollama and are recorded as blocked in the usage log.

## Quick start

```bash
uv tool install ai-guardian          # or: pipx install ai-guardian
ai-guardian doctor                   # Ollama reachability + policy summary (works zero-config)
ai-guardian overview                 # models installed/running, shadow count, usage stats
ai-guardian model list               # installed models with allow/deny verdicts
ai-guardian guard scan "my key is AKIAIOSFODNN7EXAMPLE"   # deterministic scan → risk band
```

Route a prompt through the guard (scan + policy-gate + record + run-if-allowed) via
MCP:

```
guarded_generate(model="llama3.2:3b", prompt="…", block_threshold="high")
```

Run as an MCP server (stdio) — the full 18-tool surface; the CLI is a convenience
subset:

```bash
export AI_GUARDIAN_AIOPS_MASTER_PASSWORD=...   # only if a target has a stored token
ai-guardian mcp                                # or: ai-guardian-mcp
```

## Governance

Every MCP tool passes through the bundled `@governed_tool` harness:

- **Audit** — every call (params, result, status, duration, risk tier, approver,
  rationale) is logged to `~/.ai-guardian/audit.db` (relocatable via
  `AI_GUARDIAN_AIOPS_HOME`). This is **separate** from `~/.ai-guardian/usage.db`,
  which holds the observed local-LLM usage.
- **Budget / runaway guard** — token and call budgets trip a circuit breaker.
- **Risk tiers** — graduated autonomy; high-risk ops (e.g. `remove_model`) can
  require a named approver (`AI_GUARDIAN_AUDIT_APPROVED_BY` /
  `AI_GUARDIAN_AUDIT_RATIONALE`).
- **Undo recording** — reversible writes record an inverse descriptor.

## Supported scope + limitations (preview)

- **Scope**: on-endpoint **local LLMs via Ollama** — single-endpoint local-LLM
  observability + content governance. Not GPU inference-cluster ops.
- **v0.1** = passive inventory/state auditing **plus opt-in route-through content
  governance**. A **transparent capture proxy** for other clients' traffic is
  **v0.2 roadmap**, not v0.1.
- **IGEL AI Armor interop** is **doc-level** positioning today (complementary
  roles), not a wired integration.
- **Preview / mock-only** — the scanner, policy, and risk-band are exercised
  offline; the Ollama API paths are the fastest live check (`ai-guardian doctor`).

## Missing a capability?

Want a passive capture proxy, another scanner signature, a richer policy model, or
an AI Armor hook? **Open an issue or PR — feedback and contributions welcome.**
