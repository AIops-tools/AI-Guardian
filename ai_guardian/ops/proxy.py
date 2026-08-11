"""Proxy guidance + the event recorder that feeds captured traffic to the usage log.

``proxy_guidance`` writes nothing and starts nothing — it composes the exact
command an operator runs and, more importantly, states the one thing a capture
proxy must never leave implicit: it is a chokepoint, not an enforcement boundary.
A client that can still reach the runtime's real port ignores it entirely.
"""

from __future__ import annotations

from typing import Any

from ai_guardian.config import AppConfig
from ai_guardian.ops._util import s

DEFAULT_LISTEN_PORT = 11435


def make_recorder(config: AppConfig, store: Any, target_name: str) -> Any:
    """Return a callable that records one proxy verdict into the usage log.

    Uses the same store and the same fields as the opt-in path, so captured
    traffic and routed-through traffic land in one queryable history rather than
    two. The prompt text is not among those fields — only its length and the
    redacted findings — which is the existing contract and the reason this proxy
    can sit in front of real traffic at all.
    """

    def _record(verdict: dict) -> None:
        store.record(
            target=s(target_name),
            model=s(verdict.get("model") or "(unknown)"),
            agent="proxy",
            user="",
            prompt_chars=int(verdict.get("promptChars") or 0),
            risk_level=verdict.get("riskBand") or "none",
            findings=verdict.get("findings") or [],
            allowed=not verdict.get("blocked"),
        )

    return _record


def proxy_guidance(
    config: AppConfig,
    listen_host: str = "127.0.0.1",
    listen_port: int = DEFAULT_LISTEN_PORT,
    target: str | None = None,
) -> dict:
    """[READ] The command to run the capture proxy, and what it does not guarantee.

    WRITES NOTHING and starts no listener. Returns the composed command, the
    client-side change needed, and the enforcement caveat spelled out — because a
    control that is assumed mandatory while being trivially bypassable is worse
    than no control.
    """
    resolved = config.get_target(target) if target else config.default_target
    upstream = resolved.base_url
    listen = f"{listen_host}:{listen_port}"
    command = (
        f"ai-guardian proxy serve --listen {listen} --target {resolved.name}"
    )
    return {
        "action": "proxy_guidance",
        "writesNothing": True,
        "startsNothing": True,
        "target": s(resolved.name),
        "upstream": s(upstream),
        "listen": listen,
        "command": command,
        "clientChange": (
            f"Point clients at http://{listen} instead of {upstream} "
            f"(OLLAMA_HOST=http://{listen} for the official client/SDKs)."
        ),
        "governedPaths": [
            "/api/generate", "/api/chat", "/v1/chat/completions", "/v1/completions",
        ],
        "notEnforcement": (
            "This proxy is a CHOKEPOINT, not an enforcement boundary. Any client "
            f"that can still open {upstream} directly bypasses it completely, and "
            "nothing in this tool can detect that. To make it enforcing, the "
            "runtime must be unreachable except through the proxy — bind the "
            "runtime to localhost and run the proxy on the only reachable "
            "interface, or firewall the runtime port to the proxy's host. Until "
            "then, treat captured traffic as a sample, not as the population."
        ),
        "responseHandling": (
            "Requests are scanned before forwarding; responses stream through "
            "untouched. Completions are NOT inspected — buffering them to look "
            "would turn every streaming client into a blocking one."
        ),
        "unparseableBodies": (
            "A request on a governed path whose body cannot be parsed, or which "
            "exceeds the scan size cap, is REFUSED rather than forwarded "
            "unscanned."
        ),
    }
