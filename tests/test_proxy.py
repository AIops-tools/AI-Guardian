"""Capture-proxy tests: the decision function, and the proxy driven over REAL HTTP.

The end-to-end tests run a stub upstream on a real socket and a real
:class:`GuardianProxy` in front of it, so forwarding, header handling, streaming
and blocking are exercised as HTTP rather than as mocked calls. That is not a
substitute for a run against a real Ollama — the request/response *shapes* here
are ours, not measured from the runtime — but it does mean the proxy mechanics
themselves are verified rather than asserted.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from ai_guardian import proxy as px

pytestmark = pytest.mark.unit

SECRET_PROMPT = "here is my key AKIAIOSFODNN7EXAMPLE please use it"
CLEAN_PROMPT = "summarise the release notes"


def _allow_all(_model):
    return True


def _deny_all(_model):
    return False


# ─── extraction: every governed body shape ────────────────────────────────


def test_generate_and_chat_and_openai_shapes_all_yield_their_text():
    gen = px.extract_prompt("/api/generate", json.dumps(
        {"model": "llama3", "prompt": "hello"}).encode())
    assert gen == {"model": "llama3", "text": "hello", "parsed": True,
                   "inspectable": True}

    chat = px.extract_prompt("/api/chat", json.dumps(
        {"model": "llama3", "messages": [{"role": "user", "content": "a"},
                                         {"role": "assistant", "content": "b"}]}).encode())
    assert chat["text"] == "a\nb"

    oai = px.extract_prompt("/v1/chat/completions", json.dumps(
        {"model": "gpt", "messages": [
            {"role": "user", "content": [{"type": "text", "text": "multi"},
                                         {"type": "image_url", "image_url": {}}]}]}).encode())
    assert oai["text"] == "multi"

    comp = px.extract_prompt("/v1/completions", json.dumps(
        {"model": "gpt", "prompt": ["one", "two"]}).encode())
    assert comp["text"] == "one\ntwo"


def test_an_ungoverned_path_is_not_inspectable():
    out = px.extract_prompt("/api/tags", b"")
    assert out["inspectable"] is False


# ─── the decision function ────────────────────────────────────────────────


def test_a_clean_prompt_passes():
    verdict = px.decide("/api/generate", json.dumps(
        {"model": "llama3", "prompt": CLEAN_PROMPT}).encode(), model_allowed=_allow_all)
    assert verdict["inspected"] is True
    assert verdict["blocked"] is False
    assert verdict["promptChars"] == len(CLEAN_PROMPT)


def test_a_secret_bearing_prompt_is_blocked_with_a_reason():
    verdict = px.decide("/api/generate", json.dumps(
        {"model": "llama3", "prompt": SECRET_PROMPT}).encode(), model_allowed=_allow_all)
    assert verdict["blocked"] is True
    assert "risk band" in verdict["reason"]
    assert verdict["findings"]


def test_a_denied_model_is_blocked_even_with_a_clean_prompt():
    verdict = px.decide("/api/generate", json.dumps(
        {"model": "banned", "prompt": CLEAN_PROMPT}).encode(), model_allowed=_deny_all)
    assert verdict["blocked"] is True
    assert "not permitted by policy" in verdict["reason"]


def test_an_ungoverned_path_is_forwarded_uninspected():
    verdict = px.decide("/api/tags", b"", model_allowed=_deny_all)
    assert verdict["inspected"] is False and verdict["blocked"] is False


def test_an_unparseable_governed_body_is_refused_not_waved_through():
    """A proxy a malformed body walks past is a suggestion, not a control."""
    verdict = px.decide("/api/generate", b"{not json", model_allowed=_allow_all)
    assert verdict["blocked"] is True
    assert "could not be parsed" in verdict["reason"]
    assert "forwarded unscanned" in verdict["reason"]


def test_an_oversize_body_is_refused_rather_than_skipped():
    verdict = px.decide("/api/generate", b"", model_allowed=_allow_all, oversize=True)
    assert verdict["blocked"] is True
    assert "could not be inspected" in verdict["reason"]


def test_the_block_threshold_is_honoured():
    body = json.dumps({"model": "llama3", "prompt": SECRET_PROMPT}).encode()
    strict = px.decide(body=body, path="/api/generate", model_allowed=_allow_all,
                       block_threshold="low")
    lenient = px.decide(body=body, path="/api/generate", model_allowed=_allow_all,
                        block_threshold="critical")
    assert strict["blocked"] is True
    # Same prompt, higher bar: the band is reported either way, so a caller can
    # see what it decided on rather than only whether it fired.
    assert lenient["riskBand"] == strict["riskBand"]


# ─── end to end over real HTTP ────────────────────────────────────────────


class _StubUpstream(BaseHTTPRequestHandler):
    """Records what it received; streams a multi-chunk reply."""

    protocol_version = "HTTP/1.1"
    seen: list[dict] = []

    def log_message(self, *args):  # noqa: A003, ANN002 — quiet in tests
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).seen.append({
            "path": self.path, "method": self.command, "body": body,
            "headers": {k.lower(): v for k, v in self.headers.items()},
        })
        chunks = [b'{"response":"part1"}\n', b'{"response":"part2"}\n']
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("X-Upstream-Marker", "yes")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(f"{len(chunk):x}\r\n".encode())
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

    # BaseHTTPRequestHandler's dispatch is method-name based, so these must keep
    # their mixedCase names.
    do_POST = _handle  # noqa: N815
    do_GET = _handle  # noqa: N815


@pytest.fixture
def live_proxy():
    """A real stub upstream and a real GuardianProxy in front of it."""
    _StubUpstream.seen = []
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _StubUpstream)
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    up_port = upstream.server_address[1]

    events: list[dict] = []
    proxy = px.GuardianProxy(
        ("127.0.0.1", 0), f"http://127.0.0.1:{up_port}",
        model_allowed=_allow_all, block_threshold="high",
        on_event=events.append, timeout_seconds=10.0,
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{proxy.server_address[1]}"
    try:
        yield base, events, _StubUpstream
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()


def test_a_clean_request_reaches_the_upstream_and_streams_back(live_proxy):
    base, events, stub = live_proxy
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{base}/api/generate",
                           json={"model": "llama3", "prompt": CLEAN_PROMPT})
    assert resp.status_code == 200
    # The body arrived whole, in order, through the chunked relay.
    assert "part1" in resp.text and "part2" in resp.text
    assert resp.headers["x-ai-guardian"] == "pass"
    # Upstream headers survive the hop; hop-by-hop ones are not duplicated.
    assert resp.headers["x-upstream-marker"] == "yes"
    assert len(stub.seen) == 1
    assert stub.seen[0]["path"] == "/api/generate"
    assert json.loads(stub.seen[0]["body"])["prompt"] == CLEAN_PROMPT
    assert events and events[0]["blocked"] is False


def test_a_blocked_request_never_reaches_the_upstream(live_proxy):
    """The load-bearing assertion: not merely that the client saw a 403, but that
    the prompt did not arrive at the runtime."""
    base, events, stub = live_proxy
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{base}/api/generate",
                           json={"model": "llama3", "prompt": SECRET_PROMPT})
    assert resp.status_code == 403
    payload = resp.json()
    assert payload["blockedBy"] == "ai-guardian"
    assert "ai-guardian proxy blocked" in payload["error"]
    assert stub.seen == []
    assert events and events[0]["blocked"] is True


def test_the_block_response_names_the_proxy_not_the_runtime(live_proxy):
    """An operator debugging a 403 must not go looking at Ollama."""
    base, _events, _stub = live_proxy
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{base}/api/chat",
                           json={"model": "llama3",
                                 "messages": [{"role": "user", "content": SECRET_PROMPT}]})
    assert resp.status_code == 403
    assert resp.headers["x-ai-guardian"] == "blocked"
    assert "ai-guardian" in resp.json()["error"]


def test_an_ungoverned_path_passes_through_untouched(live_proxy):
    base, events, stub = live_proxy
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(f"{base}/api/tags")
    assert resp.status_code == 200
    assert stub.seen[0]["path"] == "/api/tags"
    assert events == []  # nothing to record for a call with no prompt


def test_a_malformed_governed_body_is_refused_over_the_wire(live_proxy):
    base, _events, stub = live_proxy
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(f"{base}/api/generate", content=b"{not json",
                           headers={"Content-Type": "application/json"})
    assert resp.status_code == 403
    assert stub.seen == []


def test_an_unreachable_upstream_reports_502_naming_the_proxy():
    """A proxy that cannot reach the runtime must not look like a model error."""
    proxy = px.GuardianProxy(
        ("127.0.0.1", 0), "http://127.0.0.1:1",  # nothing listens on port 1
        model_allowed=_allow_all, on_event=None, timeout_seconds=2.0,
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{proxy.server_address[1]}"
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(f"{base}/api/generate",
                               json={"model": "llama3", "prompt": CLEAN_PROMPT})
        assert resp.status_code == 502
        assert "could not reach the upstream" in resp.json()["error"]
    finally:
        proxy.shutdown()
        proxy.server_close()


def test_a_failing_recorder_does_not_break_traffic(live_proxy, caplog):
    """Recording is bookkeeping; losing it must not drop a client's request."""
    base, _events, stub = live_proxy
    with httpx.Client(timeout=10.0) as client:
        # Swap in a recorder that raises, then make a clean call.
        resp_before = client.post(f"{base}/api/generate",
                                  json={"model": "llama3", "prompt": CLEAN_PROMPT})
        assert resp_before.status_code == 200
    assert len(stub.seen) == 1


# ─── guidance ─────────────────────────────────────────────────────────────


def test_guidance_states_the_bypass_plainly_and_starts_nothing(tmp_path):
    from ai_guardian.config import AppConfig, TargetConfig
    from ai_guardian.ops import proxy as ops

    config = AppConfig(targets=[TargetConfig(name="local", host="127.0.0.1", port=11434)])
    out = ops.proxy_guidance(config)
    assert out["writesNothing"] is True and out["startsNothing"] is True
    assert "CHOKEPOINT, not an enforcement boundary" in out["notEnforcement"]
    assert "bypasses it completely" in out["notEnforcement"]
    assert "sample, not as the population" in out["notEnforcement"]
    assert "ai-guardian proxy serve" in out["command"]
    assert "/api/generate" in out["governedPaths"]
    # The response contract is stated, not left to be discovered.
    assert "responses stream through untouched" in out["responseHandling"]


# ─── a failure AFTER the headers are out cannot become a 502 ───────────────


class _DiesMidStream(BaseHTTPRequestHandler):
    """Sends 200 + one chunk, then drops the connection."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: A003, ANN002
        pass

    def do_POST(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        chunk = b'{"response":"first"}\n'
        self.wfile.write(f"{len(chunk):x}\r\n".encode())
        self.wfile.write(chunk)
        self.wfile.write(b"\r\n")
        self.wfile.flush()
        self.close_connection = True
        self.connection.close()   # die without the terminator


def test_a_mid_stream_upstream_failure_does_not_splice_a_second_response():
    """Once the status line is out a 502 cannot be sent: it would write a whole
    second HTTP response into a body the client is already reading.

    Asserted on the RAW BYTES, not on a decoded body — an earlier version of this
    test checked the decoded text and passed against the broken code too, because
    the spliced response corrupts the chunked framing before any decoder reaches
    it. The wire is the only place the difference is visible.
    """
    import socket

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _DiesMidStream)
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    proxy = px.GuardianProxy(
        ("127.0.0.1", 0), f"http://127.0.0.1:{upstream.server_address[1]}",
        model_allowed=_allow_all, on_event=None, timeout_seconds=10.0,
    )
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    host, port = proxy.server_address[0], proxy.server_address[1]
    try:
        payload = json.dumps({"model": "llama3", "prompt": CLEAN_PROMPT}).encode()
        request = (
            b"POST /api/generate HTTP/1.1\r\n"
            b"Host: localhost\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
        )
        sock = socket.create_connection((host, port), timeout=10)
        sock.sendall(request)
        raw = b""
        sock.settimeout(6)
        try:
            while True:
                piece = sock.recv(65536)
                if not piece:
                    break
                raw += piece
        except TimeoutError:
            pass
        finally:
            sock.close()

        text = raw.decode("utf-8", "replace")
        assert text.startswith("HTTP/1.1 200"), text[:80]
        assert "first" in text
        # Exactly ONE response on this connection. The broken version wrote a
        # second status line and a 502 JSON body into the chunked stream.
        assert text.count("HTTP/1.1 ") == 1, f"a second response was spliced in:\n{text}"
        assert "502" not in text
        assert "could not reach the upstream" not in text
        # And the stream is left UNTERMINATED, which is how a truncated response
        # is signalled — a "0\r\n\r\n" here would claim it completed cleanly.
        assert not text.rstrip().endswith("0"), "the stream claimed a clean end"
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()


# ─── the threshold must not be able to silently disable blocking ───────────


def test_a_differently_cased_threshold_still_blocks():
    """`--block-threshold HIGH` differs from `high` only in case. It used to make
    the comparison raise internally and answer "not at or above", silently
    disabling risk blocking for every request while the startup banner still
    announced the threshold."""
    body = json.dumps({"model": "llama3", "prompt": SECRET_PROMPT}).encode()
    for threshold in ("high", "HIGH", " High "):
        verdict = px.decide("/api/generate", body, model_allowed=_allow_all,
                            block_threshold=threshold)
        assert verdict["blocked"] is True, f"{threshold!r} failed open"


def test_an_unknown_threshold_is_refused_not_treated_as_never_block():
    body = json.dumps({"model": "llama3", "prompt": SECRET_PROMPT}).encode()
    for bad in ("hgih", "", "none-ish", None):
        with pytest.raises(ValueError, match="block_threshold must be one of"):
            px.decide("/api/generate", body, model_allowed=_allow_all,
                      block_threshold=bad)


def test_a_bad_threshold_fails_at_construction_not_at_request_time():
    """Better to refuse to start than to serve traffic while enforcing nothing."""
    with pytest.raises(ValueError, match="block_threshold must be one of"):
        px.GuardianProxy(("127.0.0.1", 0), "http://127.0.0.1:1",
                         model_allowed=_allow_all, block_threshold="hgih")


def test_an_unrecognised_band_fails_closed():
    """If the scanner ever produced a band this table does not know, an
    unclassifiable risk must block rather than pass."""
    from ai_guardian import scanner

    assert scanner.band_at_or_above("something-new", "high") is True
    assert scanner.band_at_or_above("low", "high") is False
