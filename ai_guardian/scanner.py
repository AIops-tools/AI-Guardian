"""Deterministic, offline content scanner for local-LLM prompts.

The heart of ai-guardian's "what did the model see" observation: a pure function
that flags **secrets** (API keys, cloud keys, private-key blocks, JWTs), **PII**
(emails, US SSNs, credit cards with a Luhn check), and **jailbreak /
prompt-injection** signatures in a piece of text. No I/O, no network — so it is
fully deterministic and testable offline, which is exactly what a data-exfil
guard needs to be.

Matches are **redacted** in findings (only a short masked preview) so the scanner
never re-emits the very secret it caught.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    category: str  # "secret" | "pii" | "jailbreak"
    kind: str      # e.g. "aws_access_key", "email", "ignore_instructions"
    severity: str  # low | medium | high | critical
    preview: str   # redacted


# ── secret patterns (masked previews only) ─────────────────────────────────
_SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("aws_access_key", "critical", r"\bAKIA[0-9A-Z]{16}\b"),
    ("private_key_block", "critical", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("github_token", "critical", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    ("slack_token", "high", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ("jwt", "high", r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\b"),
    ("google_api_key", "high", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("openai_key", "critical", r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("generic_api_key", "medium",
     r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
)

# ── PII patterns ───────────────────────────────────────────────────────────
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_CC_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,16}\b")

# ── jailbreak / prompt-injection signatures ────────────────────────────────
_JAILBREAK = (
    ("ignore_instructions", r"(?i)ignore (?:all |your |the )?(?:previous|prior|above) (?:instructions|prompts?)"),
    ("disregard_guidelines", r"(?i)disregard (?:your |all |the )?(?:guidelines|rules|policies|safety|system prompt)"),
    ("dan_mode", r"(?i)\b(?:DAN|do anything now)\b"),
    ("developer_mode", r"(?i)developer mode (?:enabled|on)"),
    ("roleplay_bypass", r"(?i)you are now (?:an? )?(?:unrestricted|uncensored|jailbroken|DAN)"),
    ("no_restrictions", r"(?i)pretend you have no (?:rules|restrictions|guidelines)"),
    ("system_prompt_leak", r"(?i)(?:reveal|print|repeat|output) (?:the |your )?(?:system|hidden|initial) (?:prompt|instructions)"),
)
_JAILBREAK_RE = tuple((k, re.compile(p)) for k, p in _JAILBREAK)

# ── source-code / config-leak heuristics (need >= 2 signals to fire) ────────
_CODE_SIGNALS = (
    re.compile(r"(?m)^\s*(?:import |from \w+ import |#include|package |func |public class |def |const |export )"),
    re.compile(r"```"),
    re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),  # RFC1918
    re.compile(r"\.(?:internal|local|corp)\b"),
    re.compile(r"(?m)[;{}][ \t]*$"),  # trailing braces/semicolons (code density)
)

# severity → numeric weight for the banded risk rollup.
_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 15}


def _mask(text: str) -> str:
    """Short masked preview — never echo a full secret."""
    t = text.strip()
    if len(t) <= 8:
        return t[0] + "***"
    return f"{t[:4]}…{t[-2:]} ({len(t)} chars)"


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 16:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def scan_text(text: str) -> list[Finding]:
    """Scan text for secrets, PII, and jailbreak signatures (deterministic)."""
    text = text or ""
    findings: list[Finding] = []

    for kind, severity, pat in _SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            findings.append(Finding("secret", kind, severity, _mask(m.group(0))))

    for m in _EMAIL.finditer(text):
        findings.append(Finding("pii", "email", "low", _mask(m.group(0))))
    for m in _SSN.finditer(text):
        findings.append(Finding("pii", "us_ssn", "high", _mask(m.group(0))))
    for m in _CC_CANDIDATE.finditer(text):
        if _luhn_ok(m.group(0)):
            findings.append(Finding("pii", "credit_card", "high", _mask(m.group(0))))

    for kind, rx in _JAILBREAK_RE:
        if rx.search(text):
            findings.append(Finding("jailbreak", kind, "medium", "signature match"))

    if sum(1 for rx in _CODE_SIGNALS if rx.search(text)) >= 2:
        findings.append(Finding("code_leak", "source_or_config", "medium", "code/config heuristics"))

    return findings


def risk_band(findings: list[Finding]) -> str:
    """Weighted-sum risk band: any critical dominates; else band the score.

    Weights low=1 / medium=3 / high=7 / critical=15. Bands: low 0-2, medium 3-6,
    high 7-14, critical >=15 (or any single critical finding).
    """
    if not findings:
        return "none"
    if any(f.severity == "critical" for f in findings):
        return "critical"
    score = sum(_WEIGHT.get(f.severity, 0) for f in findings)
    if score >= 15:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def summarize(findings: list[Finding]) -> dict:
    """A JSON-friendly rollup: weighted risk band + findings by category."""
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {
        "riskBand": risk_band(findings),
        "findingCount": len(findings),
        "byCategory": by_cat,
        "findings": [
            {"category": f.category, "kind": f.kind, "severity": f.severity,
             "preview": f.preview}
            for f in findings
        ],
    }
