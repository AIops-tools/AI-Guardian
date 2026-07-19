# Agent guardrails — running ai-guardian with a smaller / local model

There is a pleasing recursion here: ai-guardian governs local LLMs, and this page
is about driving ai-guardian *with* one. The same weaknesses this tool exists to
observe — a model that answers confidently without checking, that cannot tell
"unknown" from "none", that reports a truncated view as complete — are the ones
you will hit while operating it.

If you drive these tools with a local model (Llama, Qwen, Mistral … via Goose,
Ollama, LM Studio, or any OpenAI-compatible runtime), you will get noticeably
better results with a short system prompt. This page gives you one, and — more
importantly — tells you which guardrails you **no longer need to write**, because
the tool now enforces them itself.

## What the tool now enforces — do not waste prompt budget on these

| You might be tempted to prompt | Why you don't need to |
|---|---|
| "Only observe, never change the model estate" | Set `AI_GUARDIAN_READ_ONLY=1`. Write tools are then **not registered at all** — they never appear in the tool list, so the model cannot call one even if it tries. That includes `pull_model`, `remove_model`, `unload_model`, **and the policy writes** (`set_model_allowlist`, `set_model_denylist`, `pin_model_digest`) — an agent cannot widen its own allowlist while read-only mode is on. `guarded_generate` / `observe_chat` go too, since they call the runtime and append to the usage log. Pure `scan_prompt` stays: it calls nothing and records nothing. |
| "Don't invent a digest / version / license" | A field the runtime cannot report comes back as `null`, never as `""`. This is load-bearing: Ollama and llama.cpp expose a pinnable identity, while LM Studio and vLLM expose only a model id. |
| "Don't call it tampering when you just can't tell" | `model_provenance` reports a pinned model with no obtainable digest as `unverifiable`, never as `DRIFT`. Only a digest that is present **and** different is drift. |
| "Tell me if the output was cut off" | `usage_events` returns `{"events": [...], "count": N, "returned": N, "limit": L, "truncated": true/false}`. Truncation is measured (one extra row is fetched), not guessed. An under-reported usage log otherwise looks exactly like an absence of risky prompts. |
| "Never log the prompt text itself" | The route-through path stores only the prompt's length, its risk band, and the redacted findings. The raw prompt is never written to the usage log. |
| "Redact secrets before showing me" | The scanner's findings are already redacted; matched secrets and PII are reported by type and location, not by value. |
| "Confirm before anything destructive" | `remove_model` is high-risk, requires a `--dry-run`-able preview + double confirmation at the CLI, captures the model manifest for an undo (re-pull), and needs a named approver (`AI_GUARDIAN_AUDIT_APPROVED_BY`). |
| "Log what you did" | Every call is audited to `~/.ai-guardian/audit.db` regardless of what the model says it did. |

## What still needs a prompt

These are model-behaviour problems the harness cannot fix from the outside.
Copy this into your agent's system prompt:

```text
You operate ai-guardian, which observes and governs local LLM runtimes (Ollama,
llama.cpp, LM Studio, vLLM) on this machine.

TOOL USE
- Before answering any question about which models are installed, running,
  sanctioned, or what has been observed, you MUST call a tool. Never answer from
  memory — you are not a reliable witness to the machine you are running on.
- Actually invoke the tool. Do not describe the call you would make, and do not
  emit an example JSON response in place of calling it.
- If a tool call fails, report the real error verbatim. An unreachable runtime
  means unknown state, not "no models installed".

REPORTING WHAT CAN AND CANNOT BE KNOWN
- A null digest means the runtime cannot identify the weights. Report that as
  "unverifiable" — never as clean, and never as drift.
- A null version or license means the API does not expose it, not that the model
  has none.
- If usage_events returns truncated: true, say so. Never conclude "no risky
  prompts were observed" from a truncated log.
- A shadow model is a model present but not sanctioned by policy. That is a
  policy finding, not evidence of malice. Report what the policy says, not what
  you infer about intent.
- scan_prompt results are heuristic. A "none" risk band means no pattern matched,
  which is not the same as "this prompt is safe". Say which one you mean.

SCOPE
- Separate observation from interpretation. State what the tools returned, then
  any interpretation, clearly marked as such.
- Do not recommend removing a model on the basis of it being unsanctioned alone —
  surface it and let a human decide. remove_model deletes local weights.
- Do not confuse the identifier kinds: a model name (llama3:8b) carries a tag, a
  base name (llama3) does not, and a digest identifies the weights. A pinned
  digest belongs to an exact model name.
```

## Recommended setup for a local model

```bash
# Observe only — no pulls, no removals, no policy edits, no route-through.
export AI_GUARDIAN_READ_ONLY=1
ai-guardian doctor
```

Then, when you are ready to allow writes, unset it and set an approver so the
high-risk tier has an accountable name on it:

```bash
unset AI_GUARDIAN_READ_ONLY
export AI_GUARDIAN_AUDIT_APPROVED_BY="your.name@example.com"
export AI_GUARDIAN_AUDIT_RATIONALE="removing unsanctioned model per policy review"
```

Note that read-only mode disables the route-through path (`guarded_generate`,
`observe_chat`) as well, since it calls the runtime and appends to the usage log.
If you want content governance active, run without read-only mode and rely on the
policy layer — that is what the block threshold and the allow/deny lists are for.

## If your model still struggles

Some behaviours are model-capacity limits rather than prompt problems:

- **The model reports "no drift" for an unverifiable runtime.** Ask it to quote
  the `status` field per model rather than summarising; `unverifiable` and `ok`
  are visually similar in a rollup but mean opposite things about confidence.
- **Multi-tool workflows time out or drift.** Lead with `posture_overview` or
  `anomaly_report` — they fold inventory, policy verdicts, and usage stats into
  one call.
- **The model ignores later tool results in a long context.** Ask about one model
  at a time with `model_details` rather than dumping the whole inventory.
- **The model describes calls instead of making them.** This is usually a
  runtime/tool-calling-format mismatch, not a prompt problem — check that your
  client advertises the tools in the format your model was trained on.

Feedback on running this with a specific local model is genuinely useful —
open an issue at
[github.com/AIops-tools/AI-Guardian](https://github.com/AIops-tools/AI-Guardian/issues)
with the model, runtime, and what went wrong.
