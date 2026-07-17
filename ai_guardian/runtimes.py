"""Local-LLM runtime registry.

AI Guardian started Ollama-only. It now guards several **local** LLM runtimes,
each modelled by an immutable :class:`RuntimeSpec` in the :data:`RUNTIMES`
registry. A target's ``runtime`` field (config / init wizard) selects one.

Two transports cover every runtime:

- ``ollama``        — Ollama's native REST API (``/api/tags``, ``/api/chat``…),
                      with content-hash **digests** for strong provenance.
- ``openai_compat`` — one shared OpenAI-compatible transport (``/v1/models`` +
                      ``/v1/chat/completions``) serving **llama.cpp**
                      (``llama-server``), **LM Studio**, and **local single-node
                      vLLM**. Per-runtime metadata (default port, health path,
                      provenance richness) lives here so there is exactly ONE
                      OpenAI-compatible code path, not three copies.

Provenance strength is deliberately honest per runtime:

- ``digest``  (Ollama)   — content-addressed digest; real drift detection.
- ``props``   (llama.cpp) — ``/props`` exposes the served model path/size, from
                            which a stable identity is derived (weaker than a
                            content hash, but pinnable).
- ``id_only`` (LM Studio, vLLM) — only a model **id** is exposed; there is no
                            weight identity to pin, so a pinned digest is flagged
                            ``unverifiable`` rather than silently drifting.

NOTE (routing): the vLLM entry here is for guarding a **LOCAL single-node**
endpoint. GPU inference-**cluster** operations (autoscale, drain, Ray) are a
different tool in the line — **GPU cluster ops → inference-aiops**.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

OLLAMA = "ollama"
LLAMACPP = "llamacpp"
LMSTUDIO = "lmstudio"
VLLM = "vllm"

TRANSPORT_OLLAMA = "ollama"
TRANSPORT_OPENAI = "openai_compat"

# provenance strength tiers
PROV_DIGEST = "digest"  # strong: content-addressed hash (Ollama)
PROV_PROPS = "props"  # medium: derived from served model path/size (llama.cpp)
PROV_ID_ONLY = "id_only"  # weak: only a model id is exposed (LM Studio, vLLM)


@dataclass(frozen=True)
class RuntimeSpec:
    """Immutable metadata for one local-LLM runtime."""

    name: str
    display_name: str
    transport: str
    default_port: int
    provenance: str
    health_path: str
    props_path: str | None
    start_hint: str
    description: str

    @property
    def is_openai_compat(self) -> bool:
        return self.transport == TRANSPORT_OPENAI

    @property
    def supports_lifecycle(self) -> bool:
        """Only the Ollama transport can pull / remove / unload models; the
        OpenAI-compatible servers load a single model at startup."""
        return self.transport == TRANSPORT_OLLAMA


_SPECS: tuple[RuntimeSpec, ...] = (
    RuntimeSpec(
        name=OLLAMA,
        display_name="Ollama",
        transport=TRANSPORT_OLLAMA,
        default_port=11434,
        provenance=PROV_DIGEST,
        health_path="/api/version",
        props_path=None,
        start_hint="Check that Ollama is running (ollama serve) and the host/port.",
        description="Ollama native REST API; content-hash digests for provenance.",
    ),
    RuntimeSpec(
        name=LLAMACPP,
        display_name="llama.cpp",
        transport=TRANSPORT_OPENAI,
        default_port=8080,
        provenance=PROV_PROPS,
        health_path="/health",
        props_path="/props",
        start_hint="Start it with 'llama-server -m <model.gguf> --port 8080'.",
        description=(
            "llama.cpp llama-server: OpenAI-compatible /v1 plus native /health and "
            "/props (served model path/size for provenance)."
        ),
    ),
    RuntimeSpec(
        name=LMSTUDIO,
        display_name="LM Studio",
        transport=TRANSPORT_OPENAI,
        default_port=1234,
        provenance=PROV_ID_ONLY,
        health_path="/v1/models",
        props_path=None,
        start_hint="Start the LM Studio local server (Developer tab > Start Server).",
        description=(
            "LM Studio local server: OpenAI-compatible /v1/models + "
            "/v1/chat/completions (model id only — weaker provenance)."
        ),
    ),
    RuntimeSpec(
        name=VLLM,
        display_name="vLLM",
        transport=TRANSPORT_OPENAI,
        default_port=8000,
        provenance=PROV_ID_ONLY,
        health_path="/v1/models",
        props_path=None,
        start_hint=(
            "Start it with 'vllm serve <model>' (LOCAL single-node endpoint; "
            "GPU cluster ops belong to inference-aiops)."
        ),
        description=(
            "Local single-node vLLM: OpenAI-compatible /v1/models + "
            "/v1/chat/completions (model id only). NOT for GPU-cluster ops "
            "(use inference-aiops)."
        ),
    ),
)

RUNTIMES: dict[str, RuntimeSpec] = {spec.name: spec for spec in _SPECS}

DEFAULT_RUNTIME = OLLAMA


def get_runtime(name: str | None) -> RuntimeSpec:
    """Resolve a runtime name to its spec; ``None`` → the Ollama default.

    Fails fast with a clear message on an unknown runtime (validated at the
    config boundary), never returns a silent default for a typo.
    """
    key = (name or DEFAULT_RUNTIME).strip().lower()
    spec = RUNTIMES.get(key)
    if spec is None:
        available = ", ".join(RUNTIMES)
        raise ValueError(f"Unknown runtime '{name}'. Supported: {available}.")
    return spec


def runtime_for_conn(conn: Any) -> RuntimeSpec:
    """Return the :class:`RuntimeSpec` for a connection's target.

    Defaults to Ollama when a connection/target exposes no string ``runtime``
    (keeps older fakes, mocks, and zero-config targets on the native path)."""
    target = getattr(conn, "target", None)
    runtime = getattr(target, "runtime", DEFAULT_RUNTIME)
    if not isinstance(runtime, str):
        runtime = DEFAULT_RUNTIME
    return get_runtime(runtime)
