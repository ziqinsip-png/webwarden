"""Read-only proof-of-concept commands derived from findings.

Core commands use GET/HEAD requests (or an openssl certificate probe). A
nuclei command replays one specific template and may send template-defined
requests, so it is labelled separately. Credentials are never embedded: the
script uses the SESSION_A and SESSION_B environment variables that the
operator fills in locally.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from .models import Finding

SAFE_TEMPLATE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
SAFE_COMMENT = re.compile(r"[\x00-\x1f\x7f]+")
SAFE_SLUG = re.compile(r"[^a-z0-9]+")


def _quote(value: str) -> str:
    return shlex.quote(value)


def _comment(value: str, limit: int = 180) -> str:
    return SAFE_COMMENT.sub(" ", value).strip()[:limit]


def evidence_slug(url: str, label: str = "response") -> str:
    digest = hashlib.sha256(url.encode("utf-8", "ignore")).hexdigest()[:12]
    cleaned = SAFE_SLUG.sub("-", label.lower()).strip("-")[:32] or "response"
    return f"evidence/{cleaned}-{digest}"


def _curl(
    url: str,
    *,
    headers: list[str] | None = None,
    dump_headers: bool = False,
    auth_var: str | None = None,
) -> str:
    parts = ["curl", "-sS", "--max-time", "30"]
    if dump_headers:
        parts += ["-D", "-"]
    if auth_var:
        parts += ["-H", f'"${auth_var}"']
    for header in headers or []:
        parts += ["-H", _quote(header)]
    parts += ["-o", "/dev/null"]
    parts.append(_quote(url))
    return " ".join(parts)


def full_capture(
    url: str,
    prefix: str,
    *,
    headers: list[str] | None = None,
    auth_var: str | None = None,
) -> list[str]:
    """Save the complete response body and headers, then show how to verify it."""
    parts = ["curl", "-sS", "--max-time", "30", "-D", _quote(prefix + ".headers")]
    if auth_var:
        parts += ["-H", f'"${auth_var}"']
    for header in headers or []:
        parts += ["-H", _quote(header)]
    parts += ["-o", _quote(prefix + ".body"), _quote(url)]
    body = _quote(prefix + ".body")
    head = _quote(prefix + ".headers")
    return [
        "mkdir -p evidence",
        " ".join(parts),
        f'echo "bytes: $(wc -c < {body})"',
        f"sha256sum {body}",
        f"file {body}",
        f"echo '--- response headers ---'",
        f"cat {head}",
    ]


def tls_command(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    return (
        f"openssl s_client -connect {_quote(f'{host}:{port}')} "
        f"-servername {_quote(host)} </dev/null 2>/dev/null "
        "| openssl x509 -noout -subject -issuer -dates"
    )


def nuclei_command(url: str, template_id: str) -> str | None:
    if not SAFE_TEMPLATE_ID.match(template_id or ""):
        return None
    return (
        f"nuclei -u {_quote(url)} -id {_quote(template_id)} "
        "-no-interactsh -jsonl -silent"
    )


def for_finding(finding: Finding, *, has_auth_a: bool = True,
                has_auth_b: bool = False) -> list[str]:
    """Return safe reproduction commands for a finding."""
    if finding.poc:
        return list(finding.poc)
    category = finding.category.lower()
    url = finding.url
    if not url:
        return []

    if category in ("headers", "cookies"):
        return [_curl(url, dump_headers=True)]
    if category == "tls":
        if url.startswith("https://"):
            return [tls_command(url)]
        return [_curl(url, dump_headers=True)]
    if category == "cors":
        return [_curl(
            url,
            headers=["Origin: https://webwarden-poc.invalid"],
            dump_headers=True,
        )]
    if category == "redirect":
        return [_curl(url, dump_headers=True)]
    if category == "exposure":
        return full_capture(url, evidence_slug(url, "exposure"))
    if category == "nuclei":
        return full_capture(url, evidence_slug(url, "nuclei"))
    if category == "access-control":
        commands = [
            "# anonymous request; the complete body is saved, not truncated",
        ]
        commands += full_capture(url, evidence_slug(url, "idor-anonymous"))
        if has_auth_a:
            commands.append(
                "# session A; export SESSION_A locally, never paste it into this file"
            )
            commands += full_capture(
                url, evidence_slug(url, "idor-session-a"), auth_var="SESSION_A"
            )
        if has_auth_b:
            commands.append(
                "# session B; export SESSION_B locally, never paste it into this file"
            )
            commands += full_capture(
                url, evidence_slug(url, "idor-session-b"), auth_var="SESSION_B"
            )
        return commands
    if category == "cve-candidate":
        return [_curl(url, dump_headers=True)]
    return [_curl(url, dump_headers=True)]


def render_script(findings: list[Finding], target: str,
                  generated_at: str = "", has_auth_a: bool = True,
                  has_auth_b: bool = False) -> str:
    blocks: list[tuple[str, str, list[str]]] = []
    for finding in findings:
        commands = for_finding(
            finding, has_auth_a=has_auth_a, has_auth_b=has_auth_b
        )
        if commands:
            blocks.append((finding.severity, finding.title, commands))

    used_a = any("$SESSION_A" in command
                 for _severity, _title, commands in blocks
                 for command in commands)
    used_b = any("$SESSION_B" in command
                 for _severity, _title, commands in blocks
                 for command in commands)

    lines = [
        "#!/usr/bin/env bash",
        "# webwarden PoC script (read-only reproduction)",
        f"# Target: {target}",
    ]
    if generated_at:
        lines.append(f"# Generated: {generated_at}")
    lines.extend([
        "#",
        "# curl commands below are GET/HEAD only; openssl only reads certificate",
        "# metadata. A nuclei command replays one specific template and may send",
        "# template-defined requests. Nothing is modified, uploaded, or brute-forced.",
        "# Run only on assets inside your authorized bug bounty scope.",
        "#",
        "# Command output may contain sensitive data from the target.",
        "# Handle it per the program's disclosure policy.",
    ])
    if used_a or used_b:
        lines.extend([
            "#",
            "# Credentials are NOT stored in this file. Export your own test",
            "# sessions before running, for example:",
        ])
        if used_a:
            lines.append("#   export SESSION_A='Cookie: session=your-test-session-a'")
        if used_b:
            lines.append("#   export SESSION_B='Cookie: session=your-test-session-b'")
    lines.extend(["", "set -u", ""])
    if used_a:
        lines.append('SESSION_A="${SESSION_A:-}"')
    if used_b:
        lines.append('SESSION_B="${SESSION_B:-}"')
    if used_a or used_b:
        lines.append("")

    for severity, title, commands in blocks:
        lines.append(f"# [{severity.upper()}] {_comment(title)}")
        lines.extend(commands)
        lines.append("")
    if not blocks:
        lines.extend(["# No findings with reproduction commands.", ""])
    return "\n".join(lines)


def write_script(path: Path, findings: list[Finding], target: str,
                 generated_at: str = "", has_auth_a: bool = True,
                 has_auth_b: bool = False) -> Path:
    path = Path(path)
    path.write_text(
        render_script(
            findings,
            target,
            generated_at=generated_at,
            has_auth_a=has_auth_a,
            has_auth_b=has_auth_b,
        ),
        encoding="utf-8",
    )
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path
