"""Prompt-injection defence for untrusted content.

Untrusted content reaches the model from four directions (spec section 17):
the engineer's issue description, Windows event log messages, Log Analytics
rows, and retrieved knowledge documents. None of it may ever act as an
instruction. Two defences apply:

1. **Structural** - untrusted text is fenced in a delimited block that the
   system prompt declares to be *data*, and never interpolated into an
   instruction position.
2. **Detective** - obvious override attempts are flagged, recorded to the audit
   trail, and neutralised.

Neither defence is load-bearing on its own. The load-bearing control is that the
model cannot execute anything: it may only select an action id from a closed
catalogue, and every write still passes policy validation and human approval.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction_override", re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|above|prior|all)\b.{0,20}\b(instruction|rule|prompt|direction)", re.I)),
    ("safety_bypass", re.compile(r"\b(bypass|skip|disable|turn off|override)\b.{0,30}\b(safety|approval|guardrail|policy|validation|check)", re.I)),
    ("role_hijack", re.compile(r"\b(you are now|act as|pretend to be|new persona|system prompt)\b", re.I)),
    ("privilege_escalation", re.compile(r"\b(grant|give|elevate)\b.{0,30}\b(yourself|your own|admin|owner|contributor|permission|role)", re.I)),
    ("auto_execute", re.compile(r"\b(execute|run|apply)\b.{0,40}\b(without|no)\b.{0,20}\b(approval|confirmation|asking|review)", re.I)),
    ("destructive_request", re.compile(r"\b(delete|remove|wipe|purge|destroy|format)\b.{0,40}\b(profile|disk|vhd|vhdx|share|storage|resource group|backup|snapshot)", re.I)),
    ("secret_exfiltration", re.compile(r"\b(print|show|reveal|output|dump|send)\b.{0,30}\b(secret|password|key|token|credential|connection string)", re.I)),
    ("embedded_directive", re.compile(r"(?:^|\n)\s*(?:system|assistant)\s*:\s", re.I)),
    ("markup_injection", re.compile(r"<\s*/?\s*(?:system|instructions?|tool_call|function_call)\s*>", re.I)),
)

UNTRUSTED_OPEN = "<<<UNTRUSTED_DATA"
UNTRUSTED_CLOSE = "UNTRUSTED_DATA>>>"
_FENCE_ESCAPE = re.compile(re.escape(UNTRUSTED_OPEN) + r"|" + re.escape(UNTRUSTED_CLOSE), re.I)


# Signatures that are only ever an *instruction* to the model. Reference
# material legitimately discusses destructive operations ("never delete the
# profile container"), so knowledge scanning uses this narrower set to avoid
# flagging correct documentation as an attack.
DIRECTIVE_KINDS: frozenset[str] = frozenset(
    {
        "instruction_override",
        "safety_bypass",
        "role_hijack",
        "privilege_escalation",
        "auto_execute",
        "secret_exfiltration",
        "embedded_directive",
        "markup_injection",
    }
)


class InjectionFinding(BaseModel):
    kind: str
    excerpt: str
    origin: str


def scan_for_injection(
    text: str, *, origin: str = "user_input", kinds: frozenset[str] | None = None
) -> list[InjectionFinding]:
    """Return every injection signature found in ``text``. Empty list = clean.

    ``kinds`` restricts which signatures apply; default is all of them.
    """
    if not text:
        return []
    findings: list[InjectionFinding] = []
    for kind, pattern in _PATTERNS:
        if kinds is not None and kind not in kinds:
            continue
        match = pattern.search(text)
        if match:
            start = max(match.start() - 20, 0)
            findings.append(
                InjectionFinding(
                    kind=kind,
                    excerpt=text[start : match.end() + 20].replace("\n", " ")[:160],
                    origin=origin,
                )
            )
    return findings


def wrap_untrusted(text: str, *, origin: str, max_chars: int = 2000) -> str:
    """Fence untrusted content so the model sees it as labelled data.

    The fence markers themselves are escaped inside the payload so content
    cannot close the block early and escape into instruction position.
    """
    body = _FENCE_ESCAPE.sub("[fence-marker-removed]", text or "")
    if len(body) > max_chars:
        body = body[:max_chars] + f"\n...[truncated, {len(text) - max_chars} chars omitted]"
    return (
        f"{UNTRUSTED_OPEN} origin={origin}\n"
        f"{body}\n"
        f"{UNTRUSTED_CLOSE}"
    )


def neutralise(text: str) -> str:
    """Strip embedded directives from text that will be shown back to a human.

    Used for event log messages surfaced in the UI so a poisoned log line cannot
    render as though it were agent guidance.
    """
    cleaned = text or ""
    for _, pattern in _PATTERNS:
        cleaned = pattern.sub("[redacted: possible injection]", cleaned)
    return cleaned
