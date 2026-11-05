"""Verbatim evidence capture.

Evidence is written exactly as received: no truncation, no redaction, no
normalisation. Secrets that appear in a response are kept so the finding can be
reproduced and accepted. Redaction applies only to the optional AI audit payload
and to PoC commands, which never embed credentials.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .httpclient import HttpResult
from .models import Finding

DEFAULT_EVIDENCE_BYTES = 5 * 1024 * 1024
HARD_EVIDENCE_CEILING = 64 * 1024 * 1024

TEXTUAL_TYPES = (
    "text/",
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/x-javascript",
    "application/x-www-form-urlencoded",
    "application/yaml",
    "application/x-yaml",
    "application/csv",
    "image/svg+xml",
)

_SAFE_SLUG = re.compile(r"[^a-z0-9]+")


def evidence_limit(value: int | None) -> int:
    """Normalise --evidence-bytes. 0 means the hard ceiling, never unlimited."""
    if value is None:
        return DEFAULT_EVIDENCE_BYTES
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return DEFAULT_EVIDENCE_BYTES
    if parsed <= 0:
        return HARD_EVIDENCE_CEILING
    return min(parsed, HARD_EVIDENCE_CEILING)


def _slug(value: str, limit: int = 56) -> str:
    cleaned = _SAFE_SLUG.sub("-", value.lower()).strip("-")
    return cleaned[:limit] or "response"


def _header_value(value: str) -> str:
    return value.replace("\r", "\\r").replace("\n", "\\n")


def _is_textual(result: HttpResult) -> bool:
    content_type = result.content_type
    if content_type:
        return content_type.startswith(TEXTUAL_TYPES)
    sample = result.body[:8192]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _write_file(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path.name


@dataclass
class Captured:
    url: str
    status: int | None
    sha256: str
    size: int
    truncated: bool
    textual: bool
    body_text: str = ""
    body_file: str = ""
    headers_file: str = ""
    expected: int | None = None

    def files(self) -> list[str]:
        return [name for name in (self.body_file, self.headers_file) if name]

    def describe(self) -> str:
        lines = [
            f"Request: GET {self.url}",
            f"HTTP: {self.status if self.status is not None else 'no response'}",
        ]
        captured = f"Captured: {self.size} bytes"
        if self.truncated:
            target = f" of {self.expected}" if self.expected else ""
            captured += (
                f"{target} (TRUNCATED at the configured evidence limit; "
                "raise --evidence-bytes to capture more)"
            )
        elif self.expected is not None:
            captured += f" (complete; Content-Length {self.expected})"
        else:
            captured += " (complete)"
        lines.append(captured)
        lines.append(f"SHA-256: {self.sha256}")
        if self.body_file:
            lines.append(f"Raw body: {self.body_file}")
        if self.headers_file:
            lines.append(f"Raw headers: {self.headers_file}")
        content_type = "text" if self.textual else "binary"
        if self.textual:
            lines.extend([
                "",
                f"----- response body ({content_type}, {self.size} bytes) -----",
                self.body_text,
            ])
        else:
            lines.extend([
                "",
                f"----- response body ({content_type}, {self.size} bytes) -----",
                (
                    "Binary body not inlined; the exact bytes are in the raw body "
                    "file listed above."
                    if self.body_file else
                    "Binary body not inlined and no evidence directory was "
                    "configured to persist it."
                ),
            ])
        return "\n".join(lines)


@dataclass
class EvidenceStore:
    root: Path | None
    limit: int = DEFAULT_EVIDENCE_BYTES
    _counter: int = 0
    _records: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.root is not None:
            self.root = Path(self.root)
            self.root.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.root, 0o700)
            except OSError:
                pass

    @property
    def enabled(self) -> bool:
        return self.root is not None

    def _next_name(self, label: str) -> str:
        self._counter += 1
        return f"{self._counter:04d}-{_slug(label)}"

    def write_response(self, result: HttpResult, label: str) -> Captured:
        name = self._next_name(label)
        body = result.body or b""
        digest = hashlib.sha256(body).hexdigest()
        expected = None
        raw_length = result.headers.get("content-length")
        if raw_length:
            try:
                expected = int(raw_length)
            except ValueError:
                expected = None
        textual = _is_textual(result)
        body_file = ""
        headers_file = ""
        if self.root is not None:
            body_name = _write_file(self.root / f"{name}.body", body)
            body_file = f"{self.root.name}/{body_name}"
            header_lines = [
                f"request: GET {result.url}",
                f"final-url: {result.final_url}",
                f"status: {result.status if result.status is not None else 'no response'}",
                f"sha256: {digest}",
                f"bytes: {len(body)}",
                f"truncated: {str(result.truncated).lower()}",
            ]
            for header_name in sorted(result.headers):
                if header_name == "set-cookie":
                    continue
                header_lines.append(
                    f"{header_name}: {_header_value(result.headers[header_name])}"
                )
            for cookie in result.set_cookies:
                header_lines.append(f"set-cookie: {_header_value(cookie)}")
            headers_name = _write_file(
                self.root / f"{name}.headers",
                ("\n".join(header_lines) + "\n").encode("utf-8", "replace"),
            )
            headers_file = f"{self.root.name}/{headers_name}"
        captured = Captured(
            url=result.url,
            status=result.status,
            sha256=digest,
            size=len(body),
            truncated=bool(result.truncated),
            textual=textual,
            body_text=result.text if textual else "",
            body_file=body_file,
            headers_file=headers_file,
            expected=expected,
        )
        self._records.append({
            "label": label,
            "url": result.url,
            "status": result.status,
            "sha256": digest,
            "bytes": len(body),
            "truncated": bool(result.truncated),
            "files": captured.files(),
        })
        return captured

    def attach(
        self,
        finding: Finding,
        result: HttpResult,
        label: str,
        *,
        intro: str = "",
        extra: list[tuple[str, Captured]] | None = None,
    ) -> Captured:
        primary = self.write_response(result, label)
        finding.evidence_sha256 = primary.sha256
        finding.evidence_bytes = primary.size
        finding.evidence_file = primary.body_file
        finding.evidence_files = list(primary.files())
        finding.evidence_truncated = primary.truncated
        parts: list[str] = []
        if intro:
            parts.append(intro)
        for title, captured in extra or []:
            finding.evidence_files.extend(captured.files())
            parts.append(f"--- {title} ---\n{captured.describe()}")
        parts.append(primary.describe())
        finding.evidence = "\n\n".join(parts)
        return primary


def write_evidence_index(outdir: Path, findings: list[Finding]) -> Path | None:
    """Write evidence/index.json describing every captured raw response."""
    outdir = Path(outdir)
    entries = []
    for number, finding in enumerate(findings, start=1):
        if not (finding.evidence_files or finding.evidence_sha256):
            continue
        present = {}
        for relative in finding.evidence_files:
            present[relative] = (outdir / relative).exists()
        entries.append({
            "index": number,
            "title": finding.title,
            "severity": finding.severity,
            "host": finding.host,
            "url": finding.url,
            "sha256": finding.evidence_sha256,
            "bytes": finding.evidence_bytes,
            "truncated": finding.evidence_truncated,
            "files": list(finding.evidence_files),
            "present": present,
        })
    if not entries:
        return None
    path = outdir / "evidence" / "index.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "note": (
            "Raw evidence is verbatim and unredacted. It may contain live "
            "credentials, tokens, cookies, and personal data."
        ),
        "entries": entries,
    }, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path
