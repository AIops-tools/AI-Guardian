# Live verification — ai-guardian

`ai-guardian` is published on PyPI, the MCP Registry, and ClawHub. Its
verification story splits cleanly in two, and the split matters:

> **The scanner, policy engine, and risk-band are pure deterministic offline
> logic** — no model, no network — and are verified as such by the test suite.
> **The runtime API paths** are partly verified: the core Ollama route-through
> (generate + policy deny) was exercised against a real Ollama 0.24.0 on
> 2026-07-13 — see the section below for exactly which boxes that covered. The
> remaining Ollama surface, and the whole OpenAI-compatible dialect
> (llama.cpp / LM Studio / local vLLM), are still mock-only.

This document defines exactly what a live verification run must cover, and the
criteria for recording this tool as live-verified. It is deliberately
checklist-shaped so the result is reproducible and auditable — not a subjective
"seems fine".

## Already live-verified — partial ✅ (2026-07-13, real Ollama 0.24.0)

A live run against a real Ollama **0.24.0** was completed on 2026-07-13 and
closed the governance loop end-to-end. What it actually covered:

- **Scanner on real content** — a prompt carrying a real-format AWS key, an SSN,
  and a jailbreak phrase: all three categories fired (section 3, box 1).
- **Route-through against a real model** — `guarded_generate` reached Ollama and
  returned a genuine completion from `llama3` (section 4, box 1).
- **Policy deny actually intercepted** — a disallowed model was blocked on policy
  before the runtime call (section 4, box 3).
- **Undo capture** — a governed write recorded its inverse descriptor and the
  audit row landed (section 5, box 1).

Those boxes are ticked below. **Everything else in this checklist remains
unverified** — notably undo *replay*, VRAM/residency reads, provenance drift
detection, and the entire OpenAI-compatible multi-runtime surface
(llama.cpp / LM Studio / local vLLM), which has never been run live.

## What the test suite already guarantees

- Every module imports; the CLI builds; every MCP tool carries the
  `@governed_tool` harness marker (`tests/test_smoke.py`).
- **Scanner determinism**: the same input text always yields the same findings
  and the same weighted risk band. Secret, PII, source-code, and jailbreak
  signatures each fire on positive fixtures and stay quiet on negatives.
- **Redaction**: findings carry only a short masked preview — a detected secret
  is never re-emitted in the finding, the usage log, or the audit row.
- **Policy gating**: allowlist/denylist verdicts are computed correctly,
  including glob patterns, and `pull_model` is refused on a policy violation.
- **Block threshold**: `guarded_generate` / `observe_chat` block before the
  runtime call when the band is `>= block_threshold` or the model is disallowed.
- Write tools carry the correct risk tier and record the correct inverse undo
  descriptor (allowlist/denylist → prior list, `remove_model` → re-pull).
- Governance genuinely persists: audit rows and undo tokens land in a real
  SQLite DB; observed usage lands in a **separate** `usage.db`.

What it does **not** guarantee: that real Ollama `/api/tags`, `/api/ps`,
`/api/show`, `/api/version`, `/api/generate`, `/api/chat` and `/api/pull`
response shapes — and the OpenAI-compatible dialects of llama.cpp / LM Studio /
local vLLM — match what these tools parse.

## Prerequisites for a live run

Cheap and local. You need:

- A real **Ollama** on `http://localhost:11434` with at least two small models
  pulled (one to sanction, one to treat as "shadow"), and one you are willing to
  **remove**. A 1–3B model keeps the pulls fast.
- For the multi-runtime section, one OpenAI-compatible local runtime
  (llama.cpp server, LM Studio, or a local single-node vLLM).
- No GPU is strictly required — Ollama on CPU exercises every API path; only
  `vram_usage` needs a GPU to return interesting numbers.

```bash
uv tool install ai-guardian-aiops
ai-guardian doctor         # works zero-config against a local Ollama
```

## Verification checklist

Tick every box. A box that cannot be ticked is a verification gap — record it,
do not silently pass.

### 1. Connectivity (the fastest live gate)
- [ ] `ai-guardian doctor` → green: real reachability plus the version reported
      by `/api/version`.
- [ ] `server_status` → the actual running version, not a default.

### 2. Reads return real, well-shaped data
- [ ] `ai-guardian model list` → every model you actually pulled, with correct
      digests and a correct allow/deny verdict per the current policy.
- [ ] `ai-guardian model running` / `running_models` → after a generation, the
      loaded model appears with a plausible VRAM footprint and residency expiry;
      after `keep_alive` lapses, it disappears.
- [ ] `model_details` → license / parameters / capabilities populated for a real
      model, and no crash on a model whose modelfile lacks those fields.
- [ ] `vram_usage` → matches `nvidia-smi` (or the platform equivalent) while a
      model is resident.
- [ ] `ai-guardian overview` → model counts and shadow count agree with
      `model list`.

### 3. The scanner and risk band on real content
- [x] `ai-guardian guard scan` on a text containing a **real-format** AWS key,
      an SSN, and a jailbreak phrase → all three categories fire with the
      expected severities and the band is `high`. — **verified 2026-07-13 (Ollama 0.24.0)**.
- [ ] The same scan run twice → **byte-identical** findings and band
      (determinism holds outside the test fixtures too).
- [ ] The findings contain only a **masked preview** — grep the output, the
      usage log, and `~/.ai-guardian/audit.db` to confirm the full secret
      appears **nowhere**. This is a **blocking** check.
- [ ] A benign prompt → band low, zero findings (no false-positive storm on
      ordinary text).

### 4. Route-through governance actually blocks
- [x] `guarded_generate(model, benign_prompt)` → the call reaches Ollama and
      returns a real completion; the event is recorded in `usage.db`. — **verified 2026-07-13 (Ollama 0.24.0)** (llama3).
- [ ] `guarded_generate(model, secret_laden_prompt, block_threshold="high")` →
      **blocked before Ollama**. Confirm the runtime never saw it by checking
      Ollama's own logs, not just this tool's output.
- [x] `guarded_generate(disallowed_model, benign_prompt)` → blocked on policy,
      regardless of band. — **verified 2026-07-13 (Ollama 0.24.0)**.
- [ ] `observe_chat` → same behaviour for `/api/chat`-shaped messages.
- [ ] `ai-guardian guard usage` → blocked and allowed events are both present,
      with prompt **length** recorded but never the prompt itself.

### 5. A reversible write + its undo (governance closes the loop)
- [x] `set_model_allowlist([...])` → the verdicts in `model list` change
      accordingly; the result carries an `_undo_id`; a row lands in
      `~/.ai-guardian/audit.db`. — **verified 2026-07-13 (Ollama 0.24.0)** (capture only — replay below is still open).
- [ ] `ai-guardian undo list` → `undo apply <id>` restores the **prior**
      allowlist exactly (proves undo captured pre-state, not a guess).
- [ ] `set_model_denylist` then `undo apply` → same.
- [ ] `ai-guardian model remove <throwaway> --dry-run` → prints the call, removes
      nothing; then for real → the model is gone and `undo apply` re-pulls it.
      Note the re-pull comes from the registry, so verify the digest afterwards
      rather than assuming bit-identity.
- [ ] `unload_model` → the model leaves `running_models` and VRAM is freed.

### 6. Provenance drift detection
- [ ] `pin_model_digest(model, digest)` → the pin is stored and shown by
      `policy_view`.
- [ ] `model_provenance` immediately after → `status` is clean for that model.
- [ ] Force a drift: `ollama pull` a **different tag** of the same name (or
      re-pull an updated model) → `ai-guardian guard provenance` reports
      `status: DRIFT`.
- [ ] `anomaly_report` → the drift, the shadow model, and the blocked prompts
      from section 4 all appear in the rollup.

### 7. Governance actually gates
- [ ] With no `~/.ai-guardian/rules.yaml`, `remove_model` is **refused** unless
      `AI_GUARDIAN_AUDIT_APPROVED_BY` names an approver (secure-by-default).
- [ ] With the approver set, the removal proceeds and the audit row records the
      approver and `AI_GUARDIAN_AUDIT_RATIONALE`.
- [ ] A failed write is audited with `status=error` and records **no** undo token.
- [ ] `AI_GUARDIAN_AIOPS_HOME` set to a temp dir relocates `audit.db`,
      `usage.db`, and the secret store (no hardcoded real `$HOME`).
- [ ] A tight scan loop trips the runaway budget guard.

### 8. Other local runtimes (separate pass)
- [ ] Repeat sections 1, 2, and 4 against one OpenAI-compatible runtime
      (llama.cpp / LM Studio / local vLLM) with `runtime` set accordingly.
      An Ollama-only run does **not** verify these dialects.

### 9. Cleanup
- [ ] Remove the throwaway model and the test pins; confirm the removals are
      audited and tagged with the right risk tier.

## Criteria to consider this tool live-verified

Record `ai-guardian` as live-verified **only when all of the following hold**:

1. Every box in sections 1–7 and 9 is ticked against a real Ollama, and the
   Ollama version is recorded (e.g. "verified on Ollama 0.24"). Section 8 is
   ticked and recorded **separately per runtime** — an Ollama-only run must be
   recorded as Ollama-only.
2. Section 3's redaction check passed by **grepping the on-disk logs**, not by
   reading the console output.
3. Section 4's block check was confirmed from the **runtime's own logs** — the
   claim is that the prompt never reached the model, and only the model's side
   can prove that.
4. Any response-shape mismatch found during the run is fixed **and covered by a
   test**, so the mock suite cannot regress it.
5. The run is written up in this repo's release notes with the date, the tool
   version, and the runtime version, matching how the line records its other
   live-verified tools.

Note the scope of the claim even when fully green: route-through governance is
**opt-in**. It governs what is routed through it, and nothing else. Any client
calling the runtime directly bypasses it entirely — a transparent capture proxy
is a v0.2 roadmap item. A green checklist must not be described as fleet-wide
coverage.

## Notes for maintainers

- `ai-guardian doctor` is the single fastest live entry point; start there.
- This tool is among the cheapest in the line to verify: a laptop, Ollama, and
  two small models cover sections 1–7.
- The scanner half needs no live run at all — it is pure and deterministic, and
  the suite already covers it. Spend the live time on the API paths and on the
  two claims that can only be proven externally: redaction (section 3) and
  genuine pre-runtime blocking (section 4).
- The verification story for the whole product line is tracked centrally; add
  this tool's result there once green so the verification-debt ledger stays
  accurate.
