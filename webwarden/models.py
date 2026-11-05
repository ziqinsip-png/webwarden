"""Shared finding and report models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITIES = ("critical", "high", "medium", "low", "info")

CONFIDENCE_CONFIRMED = "confirmed"
CONFIDENCE_FIRM = "firm"
CONFIDENCE_MANUAL = "needs manual verification"

CVE_STATUS_TEMPLATE = "template match (detection)"
CVE_STATUS_CANDIDATE = "candidate (not verified)"


@dataclass
class CveRef:
    id: str
    source: str
    status: str
    score: float | None = None
    severity: str | None = None
    url: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    host: str
    url: str
    description: str
    remediation: str = ""
    evidence: str = ""
    confidence: str = CONFIDENCE_MANUAL
    references: list[str] = field(default_factory=list)
    verified: bool = False
    verification: str = ""
    poc: list[str] = field(default_factory=list)
    cves: list[CveRef] = field(default_factory=list)
    evidence_sha256: str = ""
    evidence_bytes: int = 0
    evidence_file: str = ""
    evidence_files: list[str] = field(default_factory=list)
    evidence_truncated: bool = False
    reproductions: int = 0
    stable: bool | None = None
    decoy_suspected: bool = False
    decoy_reason: str = ""
    chain_ids: list[str] = field(default_factory=list)

    def key(self) -> tuple[str, str, str, str]:
        return (
            self.category.lower(),
            self.host.lower(),
            self.url,
            self.title.lower(),
        )

    def cve_ids(self) -> list[str]:
        return [cve.id for cve in self.cves]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    scopes: list[str]
    version: str
    started_at: str
    finished_at: str | None = None
    authorized: bool = True
    stats: dict = field(default_factory=dict)
    recon: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    audit: dict = field(default_factory=dict)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity, 9),
                finding.host,
                finding.title,
            ),
        )

    def severity_counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "tool": "webwarden",
            "version": self.version,
            "target": self.target,
            "scopes": list(self.scopes),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "authorized": self.authorized,
            "stats": dict(self.stats),
            "warnings": list(self.warnings),
            "recon": self.recon,
            "findings": [finding.to_dict() for finding in self.findings],
            "audit": dict(self.audit),
        }
