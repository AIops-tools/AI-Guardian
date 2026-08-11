"""Transparent capture proxy: the same guard applied to traffic that never opted in.

``guarded_generate`` only governs callers that choose to route through this tool.
This proxy sits in front of the runtime so an ordinary client — a chat UI, an SDK,
a script — is scanned, policy-checked, and recorded without changing its code:
point it at this listener instead of the runtime.

Two properties decide whether such a proxy is honest.

**It inspects the request, and streams the response through untouched.** A
client's request body is complete before anything is forwarded, so scanning it
costs nothing and changes no semantics. Responses are a different matter:
Ollama clients default to ``stream: true``, and a proxy that buffered them to
inspect the completion would convert every streaming client into a blocking one —
breaking the thing it was installed to protect. The guard therefore governs
prompts, exactly as the opt-in path already does (which likewise records prompt
length and redacted findings, never the raw text).

**It is a chokepoint, not an enforcement boundary.** A client that can reach the
runtime's real port can ignore this proxy entirely. That is not a caveat to bury:
a control which believes it is mandatory while being trivially bypassable is the
false-safety failure this line hunts. :func:`proxy_guidance` states it, the CLI
prints it on startup, and nothing here claims otherwise.

Built on the standard library's threading HTTP server plus the ``httpx`` client
this package already depends on — a governance tool should not grow a web
framework, and an undeclared transport dependency is its own bug class.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx

from ai_guardian import scanner
from ai_guardian.ops._util import s

logger = logging.getLogger("ai-guardian.proxy")

#: Request paths whose body carries a prompt this proxy scans. Anything else is
#: forwarded untouched — a tags/show/embeddings call has no prompt to govern, and
#: inventing an opinion about it would only add failure modes.
GENERATE_PATHS = ("/api/generate",)
CHAT_PATHS = ("/api/chat",)
OPENAI_CHAT_PATHS = ("/v1/chat/completions",)
OPENAI_COMPLETION_PATHS = ("/v1/completions",)
INSPECTED_PATHS = (
    GENERATE_PATHS + CHAT_PATHS + OPENAI_CHAT_PATHS + OPENAI_COMPLETION_PATHS
)

#: Largest request body this proxy will buffer in order to scan it. A body over
#: the cap is NOT silently forwarded unscanned — see :func:`decide`.
MAX_BODY_BYTES = 4 * 1024 * 1024

#: Hop-by-hop headers that must not be forwarded (RFC 9110 §7.6.1).
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
})

_BANDS = ("none", "low", "medium", "high", "critical")


def _band_ge(band: str, threshold: str) -> bool:
    try:
        return _BANDS.index(band) >= _BANDS.index(threshold)
    except ValueError:
        return False


def extract_prompt(path: str, body: bytes) -> dict:
    """Pull the governable text out of a request body.

    Returns ``{"model", "text", "parsed"}``. ``parsed`` is False when the body is
    not JSON we understand — which the caller must treat as "could not inspect",
    never as "nothing to worry about".
    """
    if not any(path.startswith(p) for p in INSPECTED_PATHS):
        return {"model": "", "text": "", "parsed": False, "inspectable": False}
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"model": "", "text": "", "parsed": False, "inspectable": True}
    if not isinstance(payload, dict):
        return {"model": "", "text": "", "parsed": False, "inspectable": True}

    model = str(payload.get("model") or "")
    if any(path.startswith(p) for p in CHAT_PATHS + OPENAI_CHAT_PATHS):
        messages = payload.get("messages")
        parts = []
        for message in messages if isinstance(messages, list) else []:
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                # OpenAI's multi-part content: keep the text parts only. Parts
                # with no text (an image_url) must contribute nothing at all —
                # emitting "" for them pads the joined text with blank lines and
                # inflates promptChars, which is a recorded number.
                parts.extend(
                    text
                    for part in content
                    if isinstance(part, dict) and (text := str(part.get("text") or ""))
                )
        return {"model": model, "text": "\n".join(p for p in parts if p),
                "parsed": True, "inspectable": True}

    prompt = payload.get("prompt")
    if isinstance(prompt, list):  # /v1/completions allows an array of prompts
        prompt = "\n".join(str(p) for p in prompt)
    return {"model": model, "text": str(prompt or ""), "parsed": True,
            "inspectable": True}


def decide(
    path: str,
    body: bytes,
    *,
    model_allowed: Any,
    block_threshold: str = "high",
    oversize: bool = False,
) -> dict:
    """Scan + policy-gate one request. Pure: no I/O, no clock, fully testable.

    ``model_allowed`` is a callable taking a model name — the config's own check,
    passed in so this stays free of configuration lookups.

    A body that could not be parsed on an inspected path is **blocked**, not
    waved through. The alternative is a proxy that a malformed body walks
    straight past, which turns the control into a suggestion.
    """
    extracted = extract_prompt(path, body)
    if not extracted["inspectable"]:
        return {"inspected": False, "blocked": False, "model": "",
                "riskBand": None, "findings": [], "reason": None}

    if oversize:
        return {
            "inspected": False, "blocked": True, "model": extracted["model"],
            "riskBand": None, "findings": [],
            "reason": (
                f"request body exceeds the {MAX_BODY_BYTES} byte scan limit, so it "
                f"could not be inspected — refused rather than forwarded unscanned"
            ),
        }
    if not extracted["parsed"]:
        return {
            "inspected": False, "blocked": True, "model": "",
            "riskBand": None, "findings": [],
            "reason": (
                "request body on a governed path could not be parsed as JSON, so "
                "it could not be inspected — refused rather than forwarded "
                "unscanned"
            ),
        }

    summary = scanner.summarize(scanner.scan_text(extracted["text"]))
    band = summary["riskBand"]
    allowed_model = bool(model_allowed(extracted["model"])) if extracted["model"] else True
    risk_blocked = _band_ge(band, block_threshold)
    blocked = (not allowed_model) or risk_blocked
    reason = None
    if not allowed_model:
        reason = f"model {extracted['model']!r} is not permitted by policy"
    elif risk_blocked:
        reason = f"prompt risk band '{band}' >= block threshold '{block_threshold}'"
    return {
        "inspected": True,
        "blocked": blocked,
        "model": extracted["model"],
        "riskBand": band,
        "findings": summary["findings"],
        "promptChars": len(extracted["text"]),
        "reason": reason,
    }


def _forwardable(headers: Any) -> dict:
    out = {}
    for key, value in headers.items():
        if key.lower() not in _HOP_BY_HOP:
            out[key] = value
    return out


class _Handler(BaseHTTPRequestHandler):
    """One request. ``server`` carries the upstream client, policy, and usage log."""

    protocol_version = "HTTP/1.1"
    server_version = "ai-guardian-proxy"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        logger.info("%s - %s", self.address_string(), fmt % args)

    # ── plumbing ─────────────────────────────────────────────────────────
    def _read_body(self) -> tuple[bytes, bool]:
        """``(body, oversize)`` — a body over the cap is drained, never scanned."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            # Drain so the connection stays usable, but report it as unscannable.
            remaining = length
            while remaining > 0:
                remaining -= len(self.rfile.read(min(65536, remaining)) or b"")
            return b"", True
        return (self.rfile.read(length) if length else b""), False

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-AI-Guardian", "blocked" if status >= 400 else "pass")
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self, method: str) -> None:
        body, oversize = self._read_body()
        srv = self.server  # type: ignore[assignment]
        verdict = decide(
            self.path, body,
            model_allowed=srv.model_allowed,           # type: ignore[attr-defined]
            block_threshold=srv.block_threshold,       # type: ignore[attr-defined]
            oversize=oversize,
        )
        if verdict["inspected"] or verdict["blocked"]:
            srv.record(verdict)                        # type: ignore[attr-defined]
        if verdict["blocked"]:
            # A JSON error, because every client on these paths parses JSON, and
            # named as coming from the proxy so nobody debugs the runtime instead.
            self._send_json(403, {
                "error": (
                    f"ai-guardian proxy blocked this request: {verdict['reason']}"
                ),
                "blockedBy": "ai-guardian",
                "riskBand": verdict["riskBand"],
                "findings": verdict["findings"],
            })
            return
        self._stream_upstream(method, body)

    def _stream_upstream(self, method: str, body: bytes) -> None:
        """Forward and relay the response, streaming chunks as they arrive.

        Deliberately not buffered: these clients default to ``stream: true``, and
        collecting the whole response to look at it would turn every streaming
        caller into a blocking one. The guard is on the request.
        """
        srv = self.server  # type: ignore[assignment]
        client: httpx.Client = srv.client  # type: ignore[attr-defined]
        try:
            with client.stream(
                method, self.path, content=body or None,
                headers=_forwardable(self.headers),
            ) as upstream:
                self.send_response(upstream.status_code)
                for key, value in upstream.headers.items():
                    if key.lower() not in _HOP_BY_HOP:
                        self.send_header(key, value)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("X-AI-Guardian", "pass")
                self.end_headers()
                for chunk in upstream.iter_raw():
                    if not chunk:
                        continue
                    self.wfile.write(f"{len(chunk):x}\r\n".encode())
                    self.wfile.write(chunk)
                    self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
        except httpx.HTTPError as exc:
            self._send_json(502, {
                "error": (
                    f"ai-guardian proxy could not reach the upstream runtime: "
                    f"{s(exc, 200)}"
                ),
                "blockedBy": None,
            })

    # ── methods ──────────────────────────────────────────────────────────
    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        self._proxy("POST")

    def do_GET(self) -> None:  # noqa: N802
        self._proxy("GET")

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy("DELETE")

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy("PUT")

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy("HEAD")


class GuardianProxy(ThreadingHTTPServer):
    """A listening proxy in front of one runtime endpoint."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        listen: tuple[str, int],
        upstream: str,
        *,
        model_allowed: Any,
        block_threshold: str = "high",
        on_event: Any = None,
        timeout_seconds: float = 300.0,
    ) -> None:
        super().__init__(listen, _Handler)
        self.upstream = upstream.rstrip("/")
        self.model_allowed = model_allowed
        self.block_threshold = block_threshold
        self._on_event = on_event
        # A generous read timeout: a local model generating a long answer is slow,
        # and a proxy that times out mid-generation looks like a model failure.
        self.client = httpx.Client(base_url=self.upstream, timeout=timeout_seconds)

    def record(self, verdict: dict) -> None:
        """Hand one verdict to the usage log (never the prompt text itself)."""
        if self._on_event is None:
            return
        try:
            self._on_event(verdict)
        except Exception as exc:  # noqa: BLE001 — recording must not break traffic
            logger.warning("could not record a proxy event: %s", exc)

    def server_close(self) -> None:
        try:
            self.client.close()
        finally:
            super().server_close()
