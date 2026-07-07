#!/usr/bin/env python3
"""Secret redaction for scanner output snippets.

Bandit's JSON `code` field and the SARIF `region.snippet` both carry the
offending source line — which is exactly where hardcoded credentials live.
Persisting those snippets verbatim into a report means a security tool's
own output becomes a place where secrets land on disk. This module strips
known credential shapes before any snippet is written to a report or SARIF.

This is deterministic regex substitution (Rule: deterministic logic must not
be delegated to a model). Patterns are ordered most-specific first so that
tighter matches (PEM blocks, AKIA keys) run before the generic
`secret = "..."` fallback. Only the secret *value* is replaced with
``[REDACTED]``; surrounding context (variable name, assignment operator,
quotes) is preserved so the snippet stays useful for triage.

Usage:
    from redact import redact_secrets
    safe = redact_secrets(bandit_result["code"])
"""

from __future__ import annotations

import re
from typing import List, Tuple

REDACTED = "[REDACTED]"

# Each entry is (compiled_pattern, replacement). Replacement is either a string
# (whole match → string) or a callable receiving the match. Order matters:
# specific structured tokens first, then PEM blocks, then the generic
# keyword=value fallback last so it does not shadow the targeted patterns.
_SECRET_PATTERNS: List[Tuple[re.Pattern, object]] = [
    # --- AWS ---
    # IAM access key id (well-defined 20-char shape).
    (re.compile(r"AKIA[0-9A-Z]{16}"), REDACTED),
    # AWS secret access key (40-char base64) — only when explicitly labeled.
    (
        re.compile(
            r"(?i)(aws_secret_access_key|secret_access_key|aws_secret)\s*[:=]\s*"
            r"['\"]?[A-Za-z0-9/+=]{40}['\"]?"
        ),
        lambda m: re.sub(r"[A-Za-z0-9/+=]{40}", REDACTED, m.group(0)),
    ),
    # --- Public cloud / SaaS tokens with recognizable prefixes ---
    # GitHub personal access / fine-grained / OAuth / refresh / server tokens.
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), REDACTED),
    # Google API key.
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), REDACTED),
    # Slack token family.
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    # Stripe live secret key.
    (re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), REDACTED),
    # Stripe restricted key.
    (re.compile(r"\brk_live_[0-9A-Za-z]{24,}\b"), REDACTED),
    # --- PEM private key blocks (multi-line, any key type) ---
    (
        re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
            r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        REDACTED,
    ),
    # --- Generic labeled secret assignment ---
    # Catches `password = "..."`, `api_key: '...'`, `client_secret="..."`, etc.
    # Only the value is redacted; the keyword stays for triage. Requires the
    # value to be at least 12 chars and quoted, to avoid eating flag-like
    # booleans or short config strings.
    (
        re.compile(
            r"""(?i)(password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|"""
            r"""auth[_\-]?token|access[_\-]?token|private[_\-]?key|"""
            r"""client[_\-]?secret|bearer)\s*[:=]\s*"""
            r"""['"]([^\s'"]{12,})['"]"""
        ),
        lambda m: m.group(0).replace(m.group(2), REDACTED),
    ),
]


def redact_secrets(text: str) -> str:
    """Return ``text`` with recognized secret values replaced by ``[REDACTED]``.

    Returns the input unchanged if it is not a string (None / non-str types are
    passed through — callers may feed optional snippet fields).
    """
    if not isinstance(text, str) or not text:
        return text
    out = text
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out
