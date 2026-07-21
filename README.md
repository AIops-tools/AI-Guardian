<!-- mcp-name: io.github.AIops-tools/ai-guardian -->

# AI Guardian

> **Disclaimer**: Community-maintained open-source project. **Not affiliated with, endorsed by, or sponsored by Ollama, IGEL, or any AI-security vendor.** Product and trademark names belong to their owners. MIT licensed.

Governed **observability + governance for on-endpoint local LLMs**. It lets you
**observe + audit what your local models are actually fed, and gate what leaves in
a prompt** — the complement to **IGEL AI Armor**. AI Armor governs *whether* a
local model may run on the endpoint; ai-guardian records *what it did* and gates
*what goes into the prompt* (secrets, PII, source, jailbreaks) plus *which model*
may serve it. Self-contained: it talks to each runtime's REST API and needs
nothing beyond `httpx` and the MCP SDK. v0.1 provides opt-in route-through
content governance; a transparent capture proxy is on the v0.2 roadmap.

### Supported runtimes

One tool, several **local** runtimes, selected per target by a `runtime` field in
`config.yaml` (the `init` wizard asks). Ollama uses its native API; the other three
share one OpenAI-compatible transport (`/v1/models` + `/v1/chat/completions`).

| Runtime | `runtime` | Default port | List / policy | Scan + route-through guard | Provenance |
|---------|-----------|:---:|:---:|:---:|-----------|
| **Ollama** | `ollama` | 11434 | ✅ | ✅ | **digest** (content hash — strong) |
| **llama.cpp** (`llama-server`) | `llamacpp` | 8080 | ✅ | ✅ | **props** — `/props` model path/size → pinnable id |
| **LM Studio** | `lmstudio` | 1234 | ✅ | ✅ | **id only** — weaker; pins report `unverifiable` |
| **vLLM** (local single-node) | `vllm` | 8000 | ✅ | ✅ | **id only** — weaker; pins report `unverifiable` |

The allow/deny model policy, the deterministic prompt scanner, the route-through
guard (`guarded_generate` / `observe_chat`), provenance drift, and `doctor` work
across **all** runtimes. **Model lifecycle writes** (`pull` / `remove` / `unload`)
are Ollama-only — the OpenAI-compatible servers load a model at startup and expose
no lifecycle endpoint, so those writes are refused with a clear message.

Provenance honesty: only Ollama (content digest) and llama.cpp (a `/props`-derived
path/size identity) expose something to pin. LM Studio and vLLM expose only a model
**id**, so a pinned digest is reported `unverifiable` rather than a false `DRIFT`.

> **vLLM here is a LOCAL endpoint-guarding use case.** GPU inference-**cluster**
> operations (autoscale, drain, Ray Serve/Jobs, model lifecycle at fleet scale)
> belong to a different tool in the line — **GPU cluster ops → inference-aiops**.

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
  descriptive risk tiers, and undo-token recording, bundled in the package
  (no external dependency).
- **Highly self-testable** — Ollama is free + local for the API parts; the
  scanner, policy, and risk-band are pure deterministic offline logic.

## What this tool does, and does not, decide

It delivers local-LLM observability and operations — reads and writes —
accurately, and records every one of them. It does **not** decide whether a
write to the model estate is allowed to happen. That is the agent's judgement,
or the permission of the host and account you run it under: point it at a
runtime the account cannot administer — an Ollama daemon whose model store the
user can't modify, or an endpoint the agent reaches read-only — and the writes
fail at the runtime, the place that actually owns the permission. Simplest of
all, hand the connecting agent only the scan/observe tools.

So the harness has no read-only switch, no deny-rules file, and no approval gate
to configure. (Content governance is a separate, product-level thing that stays:
the model allow/deny policy and the `guarded_generate` block threshold still
scan and gate what a model is asked to do.) The one thing the harness guarantees
is that nothing is silent: **every call, over MCP and over the CLI alike, lands
an audit row** in `~/.ai-guardian/audit.db`, and destructive writes still capture
their before-state and record an inverse where one exists.

> Each tool declares a `risk_level`, kept in agreement with its `[READ]`/`[WRITE]`
> documentation tag by a test, and carried into the audit row as a descriptive
> tier — so a reviewer can see at a glance that a row was a high-risk delete. It
> is a label, not a gate.

Running a smaller / local model? See
[agent-guardrails.md](skills/ai-guardian/references/agent-guardrails.md) — it lists
the guardrails this tool now enforces for you (so you don't spend prompt budget
restating them) and gives a ready-made system prompt for what's left.

## Capability matrix (20 MCP tools)

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
| `remove_model` | **high** | dry-run + undo (re-pull) |
| `unload_model` | medium | evict from VRAM (`keep_alive:0`) |
| `set_model_allowlist` | medium | undo → prior allowlist |
| `set_model_denylist` | medium | undo → prior denylist |
| `pin_model_digest` | medium | pin a model's expected provenance digest |
| `guarded_generate` | medium | the route-through guard: scan + policy-gate + record + run-if-allowed |
| `observe_chat` | medium | same, for `/api/chat` messages |

### Undo (2)

| Tool | Risk | What it does |
|------|:----:|--------------|
| `undo_list` | low | list recorded undo tokens |
| `undo_apply` | medium | replay a recorded inverse descriptor |

Risk-band gating: `guarded_generate` / `observe_chat` **block** when the prompt's
risk band `>= block_threshold` (default `high`) **or** the model is disallowed.
Blocked calls never reach Ollama and are recorded as blocked in the usage log.

## Quick start

```bash
uv tool install ai-guardian-aiops          # or: pipx install ai-guardian-aiops
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

Run as an MCP server (stdio) — the full 20-tool surface; the CLI is a convenience
subset:

```bash
export AI_GUARDIAN_AIOPS_MASTER_PASSWORD=...   # only if a target has a stored token
ai-guardian mcp                                # or: ai-guardian-mcp
```

## Governance

Every operation — MCP **and** CLI — passes through the bundled `@governed_tool`
harness. It records; it does not authorize (see above).

- **Audit** — every call (params, result, status, duration, risk tier, and any
  operator-supplied approver/rationale) is logged to `~/.ai-guardian/audit.db`
  (relocatable via `AI_GUARDIAN_AIOPS_HOME`). This is **separate** from
  `~/.ai-guardian/usage.db`, which holds the observed local-LLM usage.
- **Runaway guard** — a safety backstop, not an authorization gate: the same
  call hammered in a tight loop trips a circuit breaker so a stuck agent can't
  burn unbounded calls/time. Disable with `AI_GUARDIAN_RUNAWAY_MAX=0`; optional
  hard ceilings via `AI_GUARDIAN_MAX_TOOL_CALLS` / `AI_GUARDIAN_MAX_TOOL_SECONDS`.
- **Undo recording** — reversible writes record an inverse descriptor built from
  the fetched before-state.
- **Risk tier** — a descriptive label on the audit row derived from
  `risk_level`; it gates nothing.

## Supported scope + limitations

- **Scope**: on-endpoint **local LLMs** — Ollama plus the OpenAI-compatible
  llama.cpp / LM Studio / local single-node vLLM — single-endpoint local-LLM
  observability + content governance. Not GPU inference-cluster ops
  (→ inference-aiops).
- **v0.1** = passive inventory/state auditing **plus opt-in route-through content
  governance**. A **transparent capture proxy** for other clients' traffic is
  **v0.2 roadmap**, not v0.1.
- **IGEL AI Armor interop** is **doc-level** positioning today (complementary
  roles), not a wired integration.
- **Validation status** — the scanner, policy, and risk-band are pure
  deterministic offline logic and are exercised as such by the test suite. The
  core Ollama route-through (real generation + policy deny + undo capture) was
  exercised against a live Ollama 0.24.0 on 2026-07-13; the rest of the Ollama
  surface and the OpenAI-compatible dialects (llama.cpp / LM Studio / local
  vLLM) are still covered by mocked responses only. `ai-guardian doctor` is the
  fastest live check; see [`docs/VERIFICATION.md`](docs/VERIFICATION.md) for
  exactly which boxes are ticked.

## Missing a capability?

Want a passive capture proxy, another scanner signature, a richer policy model, or
an AI Armor hook? **Open an issue or PR — feedback and contributions welcome.**
