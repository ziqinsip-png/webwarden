"""Compare two saved scans and report new, fixed, and persisting findings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .audit import finding_from_dict
from .models import Finding, SEVERITY_ORDER
from .util import iso_now


@dataclass
class DiffResult:
    old_target: str
    new_target: str
    generated_at: str
    new: list[Finding]
    fixed: list[Finding]
    persisting: list[Finding]
    severity_changed: list[tuple[Finding, Finding]]

    def to_dict(self) -> dict:
        return {
            "old_target": self.old_target,
            "new_target": self.new_target,
            "generated_at": self.generated_at,
            "counts": {
                "new": len(self.new),
                "fixed": len(self.fixed),
                "persisting": len(self.persisting),
                "severity_changed": len(self.severity_changed),
            },
            "new": [finding.to_dict() for finding in self.new],
            "fixed": [finding.to_dict() for finding in self.fixed],
            "persisting": [finding.to_dict() for finding in self.persisting],
            "severity_changed": [
                {"old": old.to_dict(), "new": new.to_dict()}
                for old, new in self.severity_changed
            ],
        }


def load_findings(path: str | Path) -> tuple[str, list[Finding]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("not a webwarden findings or scan file")
    raw = data.get("findings")
    if not isinstance(raw, list):
        raise ValueError("file has no findings array")
    findings = [
        finding_from_dict(item) for item in raw if isinstance(item, dict)
    ]
    return str(data.get("target") or "unknown"), findings


def _sort(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 9),
            finding.host,
            finding.title,
            finding.url,
        ),
    )


def compare(
    old_target: str,
    old_findings: list[Finding],
    new_target: str,
    new_findings: list[Finding],
) -> DiffResult:
    old_map = {finding.key(): finding for finding in old_findings}
    new_map = {finding.key(): finding for finding in new_findings}
    new_keys = [key for key in new_map if key not in old_map]
    fixed_keys = [key for key in old_map if key not in new_map]
    shared = [key for key in new_map if key in old_map]
    changed = [
        (old_map[key], new_map[key])
        for key in shared
        if old_map[key].severity != new_map[key].severity
    ]
    return DiffResult(
        old_target=old_target,
        new_target=new_target,
        generated_at=iso_now(),
        new=_sort([new_map[key] for key in new_keys]),
        fixed=_sort([old_map[key] for key in fixed_keys]),
        persisting=_sort([new_map[key] for key in shared]),
        severity_changed=sorted(
            changed,
            key=lambda pair: (
                SEVERITY_ORDER.get(pair[1].severity, 9),
                pair[1].host,
            ),
        ),
    )


def _cell(value: object) -> str:
    return str(value if value not in (None, "") else "-").replace("|", "\\|")


def _rows(findings: list[Finding]) -> list[str]:
    rows = ["| Severity | Issue | Host | URL |", "| --- | --- | --- | --- |"]
    for finding in findings:
        rows.append(
            f"| {finding.severity.upper()} | {_cell(finding.title)} | "
            f"{_cell(finding.host)} | {_cell(finding.url)} |"
        )
    return rows


def render_markdown(diff: DiffResult) -> str:
    lines = [
        f"# Webwarden diff — {diff.new_target}",
        "",
        f"- **Generated:** {diff.generated_at}",
        f"- **Old scan:** {diff.old_target}",
        f"- **New scan:** {diff.new_target}",
        "",
        "## Summary",
        "",
        "| Change | Count |",
        "| --- | --- |",
        f"| New | {len(diff.new)} |",
        f"| Fixed | {len(diff.fixed)} |",
        f"| Persisting | {len(diff.persisting)} |",
        f"| Severity changed | {len(diff.severity_changed)} |",
        "",
    ]
    if diff.new:
        lines.extend(["## New findings", ""])
        lines.extend(_rows(diff.new))
        lines.append("")
    if diff.severity_changed:
        lines.extend(["## Severity changes", ""])
        lines.extend([
            "| Issue | Host | Old | New |",
            "| --- | --- | --- | --- |",
        ])
        for old, new in diff.severity_changed:
            lines.append(
                f"| {_cell(new.title)} | {_cell(new.host)} | "
                f"{old.severity.upper()} | {new.severity.upper()} |"
            )
        lines.append("")
    if diff.fixed:
        lines.extend(["## Fixed findings", ""])
        lines.extend(_rows(diff.fixed))
        lines.append("")
    lines.extend([
        "## Persisting findings",
        "",
        f"{len(diff.persisting)} finding(s) have the same category, host, URL, "
        "and title in both scans.",
        "",
        "Findings are matched by category, host, URL, and title. A changed URL "
        "(for example HTTP to HTTPS) is reported as one fixed and one new item.",
        "",
        "---",
        "",
        "Generated by webwarden. Use only within an authorized scope.",
        "",
    ])
    return "\n".join(lines)


def write_diff(diff: DiffResult, outdir: Path) -> dict[str, Path]:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    markdown_path = outdir / "diff.md"
    json_path = outdir / "diff.json"
    markdown_path.write_text(render_markdown(diff), encoding="utf-8")
    json_path.write_text(json.dumps(diff.to_dict(), indent=2), encoding="utf-8")
    return {"markdown": markdown_path, "json": json_path}
