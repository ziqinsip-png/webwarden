"""SARIF 2.1.0 output for CI dashboards and code-scanning ingestors."""

from __future__ import annotations

from urllib.parse import urlsplit

from .models import ScanResult
from .util import in_scope

SARIF_VERSION = "2.1.0"
SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
HOMEPAGE = "https://github.com/ziqinsip-png/webwarden"

LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _location(finding, scopes: list[str]) -> dict | None:
    """Address an in-scope URL as a whole-file artifact location."""
    parts = urlsplit(finding.url or "")
    if parts.scheme not in ("http", "https"):
        return None
    if not in_scope(parts.netloc.lower(), scopes):
        return None
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.url},
            "region": {"startLine": 1},
        }
    }


def _result(finding: object, rule_index: dict[str, int], scopes: list[str]) -> dict:
    rule_id = finding.category or "general"
    props = {
        "severity": finding.severity,
        "confidence": finding.confidence,
        "verified": finding.verified,
        "reproductions": finding.reproductions,
        "host": finding.host,
    }
    if finding.evidence_sha256:
        props["evidenceSha256"] = finding.evidence_sha256
    if finding.evidence_files:
        props["evidenceFiles"] = list(finding.evidence_files)
    if finding.verification:
        props["verification"] = finding.verification
    if finding.cve_ids():
        props["cveCandidates"] = finding.cve_ids()
    if finding.chain_ids:
        props["chainIds"] = list(finding.chain_ids)

    message = finding.description or finding.title
    if finding.evidence:
        message = f"{message}\n\nEvidence:\n{finding.evidence}"
    out = {
        "ruleId": rule_id,
        "ruleIndex": rule_index.get(rule_id, 0),
        "level": LEVEL_BY_SEVERITY.get(finding.severity, "note"),
        "message": {"text": message},
        "kind": "fail" if finding.verified else "open",
        "properties": props,
    }
    if finding.remediation:
        out["fixes"] = [{"description": {"text": finding.remediation}}]
    location = _location(finding, scopes)
    if location:
        out["locations"] = [location]
    return out


def build_sarif(result: ScanResult, tool_version: str = "") -> dict:
    """Render a ScanResult as a SARIF 2.1.0 run.

    Locations are only addressed for in-scope URLs, and each result keeps
    webwarden's own verification vocabulary: ``kind`` is ``fail`` for
    reproduced findings and ``open`` for candidates, so an ingestor never
    reads a candidate as proven.
    """
    findings = result.sorted_findings()
    rule_ids: list[str] = []
    for finding in findings:
        if finding.category and finding.category not in rule_ids:
            rule_ids.append(finding.category)
    rule_index = {category: position for position, category in enumerate(rule_ids)}

    rules = [
        {
            "id": category,
            "name": category.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": category.replace("-", " ").capitalize()},
            "fullDescription": {
                "text": (
                    f"webwarden finding category: {category}. Findings are only "
                    "reported from observed responses; candidates are marked as "
                    "needing manual verification."
                )
            },
            "defaultConfiguration": {"level": "note"},
            "properties": {"tags": ["webwarden", "security"]},
        }
        for category in rule_ids
    ]

    results = [_result(finding, rule_index, result.scopes)
               for finding in findings]

    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "webwarden",
                        "version": tool_version or result.version,
                        "informationUri": HOMEPAGE,
                        "rules": rules,
                    }
                },
                "columnKind": "utf16CodeUnits",
                "originalUriBaseIds": {
                    "WEBROOT": {"uri": f"https://{result.target}/"}
                },
                "results": results,
            }
        ],
    }
