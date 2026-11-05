"""Offline detection of credential-shaped strings in served files.

Matches are never validated, used, or replayed. Report text uses redacted
values; the raw response stays in the private evidence directory.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from .decoy import classify_credential

PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|dummy|placeholder|redacted|changeme|"
    r"your[_-]?|xxxx|insert[_-]|replace[_-]|test[_-]?key)"
)
# Only obvious marker words, so unrelated numbers near a real key do not
# suppress a match.
CONTEXT_PLACEHOLDER_RE = re.compile(
    r"(?i)(dummy|placeholder|redacted|changeme|not a real|"
    r"your[_-]?(?:key|token|secret)|test[_-]?key)"
)


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    regex: re.Pattern
    severity: str
    note: str


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "high",
        "An AWS access key ID can be paired with a secret key; revoke and "
        "rotate it after confirming exposure.",
    ),
    SecretPattern(
        "GitHub token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"
        ),
        "high",
        "A GitHub token can read or modify repositories depending on its scopes.",
    ),
    SecretPattern(
        "GitLab token",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
        "high",
        "A GitLab personal access token can access repositories and the API.",
    ),
    SecretPattern(
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "high",
        "A Slack token can read workspace messages or post as the app.",
    ),
    SecretPattern(
        "Stripe secret key",
        re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
        "critical",
        "A live Stripe secret key can initiate charges and read payment data.",
    ),
    SecretPattern(
        "SendGrid API key",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        "high",
        "A SendGrid key can send mail as the organization and read statistics.",
    ),
    SecretPattern(
        "Mailgun API key",
        re.compile(r"\bkey-[0-9a-fA-F]{32}\b"),
        "high",
        "A Mailgun key can send mail and read message logs.",
    ),
    SecretPattern(
        "Twilio API key",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "high",
        "A Twilio API key can place calls and messages billed to the account.",
    ),
    SecretPattern(
        "private key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        "critical",
        "A private key was served; treat the corresponding certificate or host "
        "as compromised.",
    ),
    SecretPattern(
        "Azure storage key",
        re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}"),
        "high",
        "An Azure storage account key grants full access to the storage account.",
    ),
    SecretPattern(
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{24,}\b"),
        "high",
        "An API key may allow billed model access; check the provider and rotate.",
    ),
    SecretPattern(
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "medium",
        "Google API keys are often public but should be restricted by referrer "
        "and API; verify that this key is not unrestricted.",
    ),
    SecretPattern(
        "credential in URL",
        re.compile(r"\bhttps?://[^/\s:@]+:[^/\s@]{6,}@[^\s\"'<>]+"),
        "medium",
        "A URL embeds a username and password; anyone who can read the file can "
        "reuse the credential.",
    ),
)


@dataclass
class SecretHit:
    kind: str
    severity: str
    note: str
    value: str = field(repr=False)
    pattern: str = ""
    context: str = ""
    offset: int = 0
    decoy: bool = False
    decoy_reason: str = ""

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.value.encode("utf-8", "replace")).hexdigest()
        return digest[:12]

    @property
    def redacted(self) -> str:
        return redact(self.value)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "redacted": self.redacted,
            "sha256_prefix": self.fingerprint,
            "context": self.context,
            "decoy": self.decoy,
            "decoy_reason": self.decoy_reason,
        }


def redact(value: str) -> str:
    if not value:
        return "(empty)"
    if len(value) <= 8:
        return "*" * len(value) + f" (len {len(value)})"
    return f"{value[:4]}...{value[-4:]} (len {len(value)})"


# --- plausibility filters -------------------------------------------------
# Patterns are deliberately broad, so every hit is re-checked before it is
# reported: filenames and prose slugs must never become "API key exposed".

_SLUG_WORD_RE = re.compile(r"[a-z]{2,}")
_FILE_AFTER_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|zip|rar|7z|csv|txt|json|xml|html?|php|"
    r"jpe?g|png|gif|svg|mp4|mp3)\b",
    re.IGNORECASE,
)
_OPENAI_PREFIXES = ("svcacct-", "admin-", "proj-", "ant-")
_KEY_KINDS_SKIPPING_SLUG_CHECK = {"private key", "credential in URL"}


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    size = len(value)
    return -sum(count / size * math.log2(count / size) for count in counts.values())


def _looks_like_slug(value: str) -> bool:
    parts = [part for part in re.split(r"[-_]+", value) if part]
    if len(parts) < 3:
        return False
    words = sum(1 for part in parts if _SLUG_WORD_RE.fullmatch(part))
    return words >= 3 and words * 100 // len(parts) >= 80


def _openai_body(value: str) -> str:
    body = value[3:] if value.startswith("sk-") else value
    for prefix in _OPENAI_PREFIXES:
        if body.startswith(prefix):
            return body[len(prefix):]
    return body


def _plausible_openai(value: str) -> bool:
    body = _openai_body(value)
    if len(body) < 24:
        return False
    if not re.search(r"\d", body) or not re.search(r"[A-Za-z]", body):
        return False
    return _entropy(body) >= 4.3


def _followed_by_filename(text: str, end: int) -> bool:
    return bool(_FILE_AFTER_RE.match(text, end))


def _plausible_hit(kind: str, value: str, text: str, end: int) -> bool:
    if kind in _KEY_KINDS_SKIPPING_SLUG_CHECK:
        return True
    if _looks_like_slug(value) or _followed_by_filename(text, end):
        return False
    if kind == "OpenAI API key":
        return _plausible_openai(value)
    return True


def _context(text: str, start: int, end: int) -> str:
    left = max(0, start - 60)
    right = min(len(text), end + 60)
    snippet = text[left:right]
    snippet = snippet[: start - left] + "<redacted>" + snippet[end - left:]
    return re.sub(r"\s+", " ", snippet).strip()[:180]


def scan_text(text: str, max_hits: int = 20) -> list[SecretHit]:
    if not text:
        return []
    hits: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()
    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(0)
            surrounding = text[max(0, match.start() - 80):match.end() + 80]
            if PLACEHOLDER_RE.search(value) or \
                    CONTEXT_PLACEHOLDER_RE.search(surrounding):
                continue
            if not _plausible_hit(
                    pattern.kind, value, text, match.end()):
                continue
            key = (pattern.kind, value)
            if key in seen:
                continue
            seen.add(key)
            override, decoy_reason = classify_credential(value)
            hits.append(SecretHit(
                kind=pattern.kind,
                severity=override or pattern.severity,
                note=pattern.note,
                value=value,
                pattern=pattern.regex.pattern,
                context=_context(text, match.start(), match.end()),
                offset=match.start(),
                decoy=bool(decoy_reason),
                decoy_reason=decoy_reason,
            ))
            if len(hits) >= max_hits:
                return hits
    return hits
