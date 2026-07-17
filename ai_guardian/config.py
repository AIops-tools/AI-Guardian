"""Configuration management for AI Guardian.

Loads local-LLM endpoint targets from a YAML config file plus the model
**allow / deny policy**. A "target" is one local-LLM runtime; its ``runtime``
field selects the family — ``ollama`` (default, ``http://localhost:11434``) or an
OpenAI-compatible ``llamacpp`` / ``lmstudio`` / ``vllm`` (see
:mod:`ai_guardian.runtimes`). The port defaults to that runtime's conventional
port when unspecified. Local runtimes frequently run open on a trusted host, so
the bearer **token is optional**: if none is stored, requests are sent
unauthenticated. When a token is used it is NEVER stored in the config file or in
plaintext — it lives in the encrypted store ``~/.ai-guardian/secrets.enc`` (see
:mod:`ai_guardian.secretstore`), with a legacy env var
(``AI_GUARDIAN_<TARGET>_TOKEN``) honoured as a fallback.

The model policy (``allowed_models`` / ``denied_models``, shell-glob patterns) is
non-secret and lives in the config file; it drives the allowlist checks that flag
shadow / unsanctioned local models.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from ai_guardian.governance.paths import ops_home
from ai_guardian.runtimes import DEFAULT_RUNTIME, RuntimeSpec, get_runtime
from ai_guardian.secretstore import SecretStoreError, get_secret, has_store

CONFIG_DIR = ops_home()
CONFIG_FILE = CONFIG_DIR / "config.yaml"
ENV_FILE = CONFIG_DIR / ".env"

# ai-guardian's own observed-usage log (separate from the governance audit.db,
# which records the guardian's own tool calls).
USAGE_DB = CONFIG_DIR / "usage.db"

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 11434

SECRET_ENV_PREFIX = "AI_GUARDIAN_"  # nosec B105 — env-var name, not a secret
SECRET_ENV_SUFFIX = "_TOKEN"  # nosec B105 — env-var name, not a secret

_log = logging.getLogger("ai-guardian.config")


def _secret_env_key(name: str) -> str:
    """Legacy per-target token env var name, e.g. AI_GUARDIAN_LOCAL_TOKEN."""
    return f"{SECRET_ENV_PREFIX}{name.upper().replace('-', '_')}{SECRET_ENV_SUFFIX}"


def _resolve_secret(name: str) -> str:
    """Return a target's bearer token, or "" when none is configured (auth optional)."""
    if has_store():
        try:
            return get_secret(name)
        except SecretStoreError:
            pass
    legacy = os.environ.get(_secret_env_key(name))
    if legacy:
        _log.warning(
            "Using plaintext env var %s. Migrate to the encrypted store with "
            "'ai-guardian secret migrate'.",
            _secret_env_key(name),
        )
        return legacy
    return ""  # no token → unauthenticated (common for local Ollama)


@dataclass(frozen=True)
class TargetConfig:
    """A connection target for one local-LLM runtime.

    ``runtime`` selects the runtime family (``ollama`` default, plus the
    OpenAI-compatible ``llamacpp`` / ``lmstudio`` / ``vllm``); see
    :mod:`ai_guardian.runtimes`."""

    name: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    scheme: str = "http"
    verify_ssl: bool = False
    runtime: str = DEFAULT_RUNTIME

    @property
    def spec(self) -> RuntimeSpec:
        """The resolved runtime metadata for this target."""
        return get_runtime(self.runtime)

    @property
    def token(self) -> str:
        return _resolve_secret(self.name)

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass(frozen=True)
class AppConfig:
    """Top-level application config: endpoints + model policy."""

    targets: tuple[TargetConfig, ...] = ()
    allowed_models: tuple[str, ...] = ()
    denied_models: tuple[str, ...] = ()
    # model name -> expected digest (provenance pins); a mismatch = drift.
    pinned_digests: tuple[tuple[str, str], ...] = ()

    @property
    def pins(self) -> dict[str, str]:
        return dict(self.pinned_digests)

    def get_target(self, name: str) -> TargetConfig:
        for t in self.targets:
            if t.name == name:
                return t
        available = ", ".join(t.name for t in self.targets) or "(none)"
        raise KeyError(f"Target '{name}' not found. Available: {available}")

    @property
    def default_target(self) -> TargetConfig:
        if not self.targets:
            raise ValueError("No targets configured. Check config.yaml")
        return self.targets[0]

    def model_allowed(self, model: str) -> bool:
        """A model is disallowed if it matches a deny glob, or if an allowlist
        exists and it matches none of it. Empty allowlist = allow-all."""
        if any(fnmatch.fnmatch(model, pat) for pat in self.denied_models):
            return False
        if self.allowed_models:
            return any(fnmatch.fnmatch(model, pat) for pat in self.allowed_models)
        return True


def _build_target(t: dict) -> TargetConfig:
    """Build one target, validating its runtime and defaulting the port to the
    runtime's default when unspecified (11434 Ollama / 8080 llama.cpp / 1234 LM
    Studio / 8000 vLLM). An unknown runtime fails fast (get_runtime raises)."""
    runtime = t.get("runtime", DEFAULT_RUNTIME)
    spec = get_runtime(runtime)  # validates; ValueError on unknown
    return TargetConfig(
        name=t["name"],
        host=t.get("host", DEFAULT_HOST),
        port=t.get("port", spec.default_port),
        scheme=t.get("scheme", "http"),
        verify_ssl=t.get("verify_ssl", False),
        runtime=spec.name,
    )


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load endpoints + model policy from YAML."""
    path = config_path or CONFIG_FILE
    if not path.exists():
        # A sensible zero-config default: the local Ollama on this host.
        return AppConfig(targets=(TargetConfig(name="local"),))

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    targets = tuple(
        _build_target(t) for t in raw.get("targets", [{"name": "local"}])
    )
    return AppConfig(
        targets=targets,
        allowed_models=tuple(raw.get("allowed_models", []) or []),
        denied_models=tuple(raw.get("denied_models", []) or []),
        pinned_digests=tuple((raw.get("pinned_digests", {}) or {}).items()),
    )
