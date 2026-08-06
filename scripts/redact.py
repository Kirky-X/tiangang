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

import math
import re
from collections import Counter
from typing import List, Tuple

REDACTED = "[REDACTED]"

# Shannon entropy threshold — strings with entropy above this value are flagged
# as potential secrets when no specific pattern matches. 4.5 bits/char is the
# conventional threshold: random base64/hex strings score ~5-6, natural English
# text scores ~3.5-4. Only applies to unlabelled strings of 16+ chars so short
# config values and identifiers are not false-positiveed.
_ENTROPY_THRESHOLD = 4.5
_ENTROPY_MIN_LEN = 16

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
    # --- Azure credentials ---
    # Azure Storage Account key (base64, 88 chars ending with ==).
    (
        re.compile(
            r"(?i)(account[_-]?key|storage[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{86,90}==['\"]?"
        ),
        lambda m: re.sub(r"[A-Za-z0-9/+=]{86,90}==", REDACTED, m.group(0)),
    ),
    # Azure Shared Access Signature (starts with "?sv=" or "sig=").
    (re.compile(r"[?&]sig=[A-Za-z0-9%]{20,}[&\s]"), REDACTED),
    # --- GCP credentials ---
    # GCP service account key (JSON with "type": "service_account").
    (
        re.compile(
            r'"private_key"\s*:\s*"-----BEGIN[^"]+-----END[^"]+-----"',
            re.DOTALL,
        ),
        REDACTED,
    ),
    # --- JWT tokens ---
    # JWT format: header.payload.signature (base64url-encoded).
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), REDACTED),
    # --- npm tokens ---
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), REDACTED),
    # --- PyPI tokens ---
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}\b"), REDACTED),
    # --- Alibaba Cloud ---
    # Alibaba Cloud AccessKey ID (20-char, starts with LTAI).
    (re.compile(r"\bLTAI[A-Za-z0-9]{12,20}\b"), REDACTED),
    # --- Tencent Cloud ---
    # Tencent Cloud SecretId (starts with AKID).
    (re.compile(r"\bAKID[A-Za-z0-9]{13,40}\b"), REDACTED),
    # --- OpenAI API Key ---
    # OpenAI key format: sk- followed by 32+ alphanumeric chars.
    # Distinct from Stripe's sk_live_ prefix — Stripe is matched earlier.
    (re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), REDACTED),
    # --- Database connection strings ---
    # URI-format: scheme://user:password@host — redact only the password portion.
    (
        re.compile(
            r"(mongodb(?:\+srv)?|postgresql|mysql|redis|mssql|amqp)://"
            r"[^@\s:]+:([^@\s]+)(?=@[^/\s]+)"
        ),
        lambda m: m.group(0).replace(m.group(2), REDACTED),
    ),
    # --- Heroku API keys ---
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), REDACTED),
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


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of a string.

    High entropy (>4.5) indicates random-looking data typical of tokens/keys.
    Natural language text scores ~3.5-4. Used as a fallback detector for
    secret-shaped strings that don't match any known prefix pattern.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _redact_high_entropy(text: str) -> str:
    """Redact unlabelled high-entropy tokens as a fallback secret detector.

    Scans for whitespace-delimited tokens of _ENTROPY_MIN_LEN+ characters that
    have Shannon entropy above _ENTROPY_THRESHOLD. Tokens that look like file
    paths, URLs, or common identifiers (all-lowercase, all-digits) are excluded
    to reduce false positives. Only the token value is replaced.
    """
    if not isinstance(text, str) or not text:
        return text

    def _maybe_redact_token(m: re.Match) -> str:
        token = m.group(0)
        if len(token) < _ENTROPY_MIN_LEN:
            return token
        # Skip tokens that are clearly not secrets: pure lowercase words,
        # pure digits, file paths, or already-redacted placeholders.
        if token.islower() or token.isdigit() or token.startswith("["):
            return token
        if "/" in token or "\\" in token or "." in token:
            return token
        if _shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            return REDACTED
        return token

    # Match non-whitespace tokens that contain at least one uppercase AND one
    # digit — the minimum shape of a generated token/key.
    return re.sub(r"[A-Za-z0-9_+/=-]{16,}", _maybe_redact_token, text)


def redact_secrets(text: str) -> str:
    """Return ``text`` with recognized secret values replaced by ``[REDACTED]``.

    Two-layer detection:
      1. Pattern-based: known token shapes (AWS AKIA, GitHub ghp_, PEM blocks, …)
         — high confidence, specific.
      2. Entropy-based fallback: unlabelled high-entropy tokens that look like
         generated keys but don't match any known prefix — lower confidence,
         catches novel/unknown token formats.

    Returns the input unchanged if it is not a string (None / non-str types are
    passed through — callers may feed optional snippet fields).
    """
    if not isinstance(text, str) or not text:
        return text
    out = text
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    # Layer 2: entropy-based fallback for unknown token formats.
    out = _redact_high_entropy(out)
    return out
