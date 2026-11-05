"""Optional nuclei template matching with a conservative, scope-aware setup."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .models import (
    CONFIDENCE_CONFIRMED,
    CVE_STATUS_TEMPLATE,
    SEVERITIES,
    CveRef,
    Finding,
)
from .poc import nuclei_command
from .util import in_scope

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
VERSION_RE = re.compile(r"Nuclei Engine Version:\s*v?([0-9][^\s]*)", re.IGNORECASE)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]+")

# Templates carrying these tags can write, brute force, or call back out.
EXCLUDED_TAGS = ",".join((
    "intrusive", "dos", "fuzz", "brute-force", "default-login",
    "headless", "code", "file", "ssrf", "oob",
))
TEMPLATE_DIRS = (
    Path("/usr/share/nuclei-templates"),
    Path("/usr/local/share/nuclei-templates"),
    Path.home() / ".local" / "nuclei-templates",
    Path.home() / "nuclei-templates",
    Path.home() / ".config" / "nuclei" / "templates",
)


@dataclass
class NucleiStatus:
    installed: bool
    binary: str | None = None
    templates: str | None = None
    version: str | None = None
    note: str = ""


def _template_dir(explicit: str | None = None) -> str | None:
    candidates: list[Path] = []
    for value in (explicit, os.environ.get("WEBWARDEN_NUCLEI_TEMPLATES"),
                  os.environ.get("NUCLEI_TEMPLATES")):
        if value:
            candidates.append(Path(value).expanduser())
    candidates.extend(TEMPLATE_DIRS)
    for path in candidates:
        try:
            if path.is_dir() and any(path.iterdir()):
                return str(path)
        except OSError:
            continue
    return None


def _engine_version(binary: str) -> str | None:
    try:
        result = subprocess.run(
            [binary, "-version"], capture_output=True, text=True,
            timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = VERSION_RE.search(result.stdout + "\n" + result.stderr)
    return match.group(1) if match else None


def availability(binary: str | None = None,
                 templates: str | None = None) -> NucleiStatus:
    if binary:
        executable = shutil.which(binary) or (
            binary if Path(binary).is_file() else None
        )
    else:
        executable = shutil.which("nuclei")
    if not executable:
        return NucleiStatus(False, note="nuclei is not installed")
    version = _engine_version(executable)
    directory = _template_dir(templates)
    if not directory:
        return NucleiStatus(
            True, executable, None, version,
            "nuclei is installed but no template directory was found; "
            "run: nuclei -update-templates",
        )
    return NucleiStatus(True, executable, directory, version, "")


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in re.split(r"[,\s]+", value) if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _clean(value: object, limit: int = 4000) -> str:
    text = CONTROL_RE.sub(" ", str(value or "")).replace("\r", " ")
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _event_url(event: dict) -> str | None:
    for key in ("matched-at", "matched_at", "host", "url"):
        value = event.get(key)
        if not value:
            continue
        value = str(value).strip()
        if value.startswith(("http://", "https://")):
            return value
        if value and "/" not in value and " " not in value:
            return "https://" + value
    return None


def _event_cves(event: dict, template_id: str) -> list[CveRef]:
    info = event.get("info") or {}
    classification = info.get("classification") or {}
    found: list[str] = []
    for key in ("cve-id", "cve_id", "cve"):
        values = classification.get(key) if isinstance(classification, dict) else None
        for value in _as_list(values):
            for match in CVE_RE.findall(value):
                found.append(match.upper())
    for match in CVE_RE.findall(template_id or ""):
        found.append(match.upper())
    score = classification.get("cvss-score") if isinstance(classification, dict) else None
    try:
        score_value = float(score) if score not in (None, "") else None
    except (TypeError, ValueError):
        score_value = None
    severity = _clean(info.get("severity"), 20).lower() or None
    cves: list[CveRef] = []
    for cve_id in dict.fromkeys(found):
        cves.append(CveRef(
            id=cve_id,
            source="nuclei",
            status=CVE_STATUS_TEMPLATE,
            score=score_value,
            severity=severity,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        ))
    return cves


def _finding_from_event(event: dict, scopes: list[str]) -> Finding | None:
    if not isinstance(event, dict):
        return None
    template_id = _clean(
        event.get("template-id") or event.get("templateID") or event.get("template"),
        120,
    )
    if not template_id:
        return None
    url = _event_url(event)
    if not url:
        return None
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or (scopes and not in_scope(host, scopes)):
        return None

    info = event.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    title = _clean(info.get("name") or template_id, 180)
    severity = _clean(info.get("severity"), 20).lower()
    if severity not in SEVERITIES:
        severity = "info"
    description = _clean(info.get("description"), 4000) or (
        f"Nuclei template {template_id} matched the live response."
    )
    remediation = _clean(info.get("remediation"), 2000)
    evidence_lines = [
        f"template: {template_id}",
        f"matched-at: {url}",
    ]
    for label, key in (("matcher", "matcher-name"), ("type", "type")):
        value = event.get(key)
        if value:
            evidence_lines.append(f"{label}: {_clean(value, 120)}")
    extracted = event.get("extracted-results")
    if extracted:
        evidence_lines.append(
            "extracted: " + _clean(extracted, 1000)[:1000]
        )
    tags = _as_list(info.get("tags"))
    if tags:
        evidence_lines.append("tags: " + ", ".join(tags[:20]))

    references: list[str] = []
    for reference in _as_list(info.get("reference"))[:8]:
        if reference.startswith(("http://", "https://")):
            references.append(reference)

    poc: list[str] = []
    command = nuclei_command(url, template_id)
    if command:
        poc.append(command)

    return Finding(
        title=title,
        severity=severity,
        category="nuclei",
        host=host,
        url=url,
        description=description,
        remediation=remediation,
        evidence="\n".join(evidence_lines),
        confidence=CONFIDENCE_CONFIRMED,
        references=references,
        verified=True,
        verification=f"nuclei template '{template_id}' matched the live response",
        poc=poc,
        cves=_event_cves(event, template_id),
    )


def parse_jsonl(text: str, scopes: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        finding = _finding_from_event(event, scopes)
        if finding is None:
            continue
        key = (finding.title.lower(), finding.url)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
    return findings


def _targets(urls: list[str], scopes: list[str], limit: int) -> list[str]:
    selected: list[str] = []
    for url in urls:
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in ("http", "https") or not host:
            continue
        if scopes and not in_scope(host, scopes):
            continue
        if url not in selected:
            selected.append(url)
        if len(selected) >= limit:
            break
    return selected


def run_nuclei(
    urls: list[str],
    scopes: list[str],
    *,
    binary: str | None = None,
    templates: str | None = None,
    timeout: float = 300.0,
    rate: int = 25,
    max_targets: int = 12,
) -> tuple[list[Finding], dict]:
    """Run nuclei with safe tags. Returns findings and run metadata."""
    status = availability(binary, templates)
    meta: dict = {
        "enabled": status.installed and bool(status.templates),
        "installed": status.installed,
        "engine": status.version,
        "templates": status.templates,
        "targets": 0,
        "matches": 0,
        "note": status.note,
    }
    if not status.installed:
        return [], meta
    if not status.templates:
        return [], meta

    targets = _targets(urls, scopes, max_targets)
    meta["targets"] = len(targets)
    if not targets:
        meta["note"] = "no in-scope live URLs were available for nuclei"
        return [], meta

    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, prefix="webwarden-nuclei-",
        encoding="utf-8",
    )
    target_file = Path(handle.name)
    try:
        with handle:
            handle.write("\n".join(targets) + "\n")
        try:
            target_file.chmod(0o600)
        except OSError:
            pass
        command = [
            status.binary or "nuclei",
            "-l", str(target_file),
            "-jsonl", "-silent", "-nc",
            "-disable-update-check", "-no-interactsh",
            "-rl", str(max(1, int(rate))),
            "-c", "8",
            "-timeout", "10",
            "-retries", "1",
            "-severity", "info,low,medium,high,critical",
            "-etags", EXCLUDED_TAGS,
            "-t", status.templates,
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True,
                timeout=max(30.0, float(timeout)), check=False,
            )
        except subprocess.TimeoutExpired:
            meta["note"] = f"nuclei timed out after {timeout:.0f}s"
            return [], meta
        except (OSError, subprocess.SubprocessError) as exc:
            meta["note"] = f"nuclei failed: {exc}"
            return [], meta
    finally:
        try:
            target_file.unlink()
        except OSError:
            pass

    findings = parse_jsonl(result.stdout, scopes)
    meta["matches"] = len(findings)
    if not findings and result.returncode != 0 and not meta.get("note"):
        detail = (result.stderr or "").strip().splitlines()
        meta["note"] = (
            "nuclei exited with "
            f"{result.returncode}" + (f": {detail[-1][:300]}" if detail else "")
        )
    return findings, meta
