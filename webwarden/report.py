"""Markdown and JSON report writers."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .audit import render_audit_section
from .evidence import write_evidence_index
from .html import render_html
from .models import Finding, ScanResult
from .poc import write_script
from .scenario import render_coverage, render_scenarios

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

REDACT_QUERY_PARAMS = {
    "password", "passwd", "pwd", "client_secret", "secret", "access_token",
    "refresh_token", "id_token", "token", "jwt", "session", "sessionid",
    "sid", "auth", "authorization", "api_key", "apikey", "private_key",
}

# Report scaffolding only. Finding titles/bodies stay in English because they
# carry the technical vocabulary reviewers expect.
LANG = {
    "en": {
        "title": "Webwarden report",
        "generated": "Generated",
        "finished": "Scan finished",
        "tool": "Tool",
        "license": "License",
        "scope": "Scope",
        "authorization": "Authorization",
        "auth_flag": "operator-supplied flag, not independently verified "
                     "(operator states written permission / bug bounty scope)",
        "auth_missing": "NOT CONFIRMED",
        "mode": "Testing mode",
        "mode_value": "non-destructive; core checks send GET/HEAD only",
        "poc": "PoC script",
        "summary": "Summary",
        "severity": "Severity",
        "count": "Count",
        "warnings": "Warnings",
        "exec": "Executive summary",
        "verified_high": "{n} critical/high finding(s) confirmed by reproduction.",
        "no_critical": "No critical or high findings were confirmed by the "
                       "automated checks.",
        "unverified_high": "{n} critical/high finding(s) still need manual "
                           "verification before they can be reported as confirmed.",
        "medium_low": "{medium} medium and {low} low finding(s); see the grouped "
                      "table below.",
        "readiness": "Submission readiness",
        "chains": "Evidence-linked exploit chains",
        "grouped": "Grouped findings",
        "findings": "Findings",
        "bypass": "Access-control bypass checks",
        "cves": "CVE references",
        "recon": "Recon",
        "limitations": "Limitations",
        "validation": "",
    },
    "id": {
        "title": "Laporan webwarden",
        "generated": "Dibuat",
        "finished": "Scan selesai",
        "tool": "Tool",
        "license": "Lisensi",
        "scope": "Scope",
        "authorization": "Otorisasi",
        "auth_flag": "flag dari operator, tidak diverifikasi independen "
                     "(operator menyatakan punya izin tertulis / scope bug bounty)",
        "auth_missing": "BELUM DIKONFIRMASI",
        "mode": "Mode pengujian",
        "mode_value": "non-destructive; core check hanya GET/HEAD",
        "poc": "Skrip PoC",
        "summary": "Ringkasan",
        "severity": "Severity",
        "count": "Jumlah",
        "warnings": "Peringatan",
        "exec": "Ringkasan eksekutif",
        "verified_high": "{n} temuan critical/high sudah dikonfirmasi lewat "
                         "reproduction.",
        "no_critical": "Tidak ada temuan critical/high yang terkonfirmasi oleh "
                       "check otomatis.",
        "unverified_high": "{n} temuan critical/high masih butuh verifikasi "
                           "manual sebelum bisa dilaporkan sebagai confirmed.",
        "medium_low": "{medium} temuan medium dan {low} low; lihat tabel "
                      "grouped di bawah.",
        "readiness": "Kesiapan submission",
        "chains": "Exploit chain berbasis evidence",
        "grouped": "Temuan (grouped)",
        "findings": "Temuan",
        "bypass": "Uji bypass access-control",
        "cves": "Referensi CVE",
        "recon": "Recon",
        "limitations": "Batasan",
        "validation": "Catatan validasi",
    },
}

VALIDATION_NOTE = {
    "en": (
        "Pattern matches are re-checked before they become findings: prose "
        "slugs, filenames, placeholders, and low-entropy strings shaped like "
        "`sk-...` are discarded, so a document named "
        "`sk-tugas-...-pokja.pdf` is never reported as an OpenAI API key. "
        "Every surviving claim still needs the listed reproduction."
    ),
    "id": (
        "Setiap pattern match divalidasi ulang sebelum jadi finding: slug "
        "prosa, nama file, placeholder, dan string low-entropy berawalan "
        "`sk-...` dibuang, jadi dokumen bernama `sk-tugas-...-pokja.pdf` "
        "tidak akan pernah dilaporkan sebagai OpenAI API key. Setiap klaim "
        "yang lolos tetap butuh reproduction seperti yang tertulis di "
        "finding."
    ),
}


def _lang(lang: str | None) -> dict:
    return LANG.get(lang or "en", LANG["en"])



def _redact_query(url: str) -> str:
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    if not parsed.query:
        return url
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    changed = False
    redacted = []
    for name, value in pairs:
        if name.lower() in REDACT_QUERY_PARAMS and value:
            redacted.append((name, "<redacted>"))
            changed = True
        else:
            redacted.append((name, value))
    if not changed:
        return url
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       urlencode(redacted), parsed.fragment))



def _cell(value: object) -> str:
    return str(value if value not in (None, "") else "-").replace("|", "\\|")


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {key: 0 for key in SEVERITY_LABEL}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _stability_label(stable: bool | None) -> str:
    if stable is True:
        return "stable"
    if stable is False:
        return "unstable"
    return "not re-checked"


def _render_finding(index: int, finding: Finding) -> list[str]:
    lines = [
        f"### {index}. [{SEVERITY_LABEL.get(finding.severity, finding.severity.upper())}] "
        f"{finding.title}",
        "",
        f"- **Host:** `{finding.host}`",
        f"- **URL:** `{finding.url}`",
        f"- **Category:** {finding.category}",
        f"- **Confidence:** {finding.confidence}",
        f"- **Verified by reproduction:** {'yes' if finding.verified else 'no'}",
        f"- **Validation:** reproduced {finding.reproductions}x on independent "
        f"requests; stability: {_stability_label(finding.stable)}",
    ]
    if finding.decoy_suspected:
        reason = str(finding.decoy_reason or "").strip() or \
            "decoy/canary marker observed"
        if reason[-1] not in ".!?":
            reason += "."
        lines.append(
            f"- **Decoy / canary suspected:** {reason} Excluded from the risk "
            "score and from priority ordering; treat as planted or test data "
            "until proven otherwise."
        )
    if finding.chain_ids:
        lines.append(
            "- **Exploit-chain links:** "
            + ", ".join(f"`{chain_id}`" for chain_id in finding.chain_ids)
        )
    if finding.verification:
        lines.append(
            "- **Verification:** "
            + finding.verification.replace("\n", " ").replace("`", "'")
        )
    if finding.evidence_sha256:
        lines.append(f"- **Evidence SHA-256:** `{finding.evidence_sha256}`")
    if finding.evidence_bytes:
        suffix = " (TRUNCATED at the configured evidence limit)" \
            if finding.evidence_truncated else " (complete)"
        lines.append(f"- **Evidence bytes:** {finding.evidence_bytes}{suffix}")
    if finding.evidence_file:
        lines.append(f"- **Raw body file:** `{finding.evidence_file}`")
    if len(finding.evidence_files) > 1:
        lines.append(
            "- **Raw evidence files:** "
            + ", ".join(f"`{name}`" for name in finding.evidence_files)
        )
    lines.extend(["", finding.description, ""])
    if finding.evidence:
        lines.extend([
            "**Evidence**",
            "",
            "```",
            finding.evidence.replace("```", "'''"),
            "```",
            "",
        ])
    if finding.cves:
        lines.extend(["**CVE references**", ""])
        for cve in finding.cves:
            score = f", CVSS {cve.score}" if cve.score is not None else ""
            lines.append(
                f"- `{cve.id}` — {cve.status}; source: {cve.source}{score}"
            )
        lines.append("")
    if finding.poc:
        lines.extend([
            "**PoC (authorized scope only)**",
            "",
        ])
        if any(command.strip().startswith("nuclei ")
               for command in finding.poc):
            lines.extend([
                "> Contains a nuclei template replay. Nuclei templates may send "
                "template-defined requests; run it only inside your scope.",
                "",
            ])
        lines.extend([
            "```bash",
            "\n".join(finding.poc).replace("```", "'''"),
            "```",
            "",
        ])
    if finding.remediation:
        lines.extend([f"**Remediation:** {finding.remediation}", ""])
    if finding.references:
        lines.append("**References**")
        lines.append("")
        for reference in finding.references:
            lines.append(f"- {reference}")
        lines.append("")
    return lines


def _readiness_lines(findings: list[Finding], recon: dict,
                     lang: str = "en") -> list[str]:
    tr = _lang(lang)
    actionable = [
        finding for finding in findings
        if finding.verified and finding.severity in ("critical", "high", "medium")
        and not finding.decoy_suspected
    ]
    informational = [
        finding for finding in findings
        if finding.severity in ("info", "low")
    ]
    lines = [
        f"## {tr['readiness']}",
        "",
        "This section is guidance, not a guarantee that a program will accept a "
        "report. Programs reject findings that are out of scope, duplicate, "
        "purely informational, or lack an impact statement.",
        "",
        f"- Verified critical/high/medium candidates: **{len(actionable)}**",
        f"- Informational/low items (usually not rewarded): **{len(informational)}**",
    ]
    for finding in actionable[:20]:
        lines.append(
            f"  - [{SEVERITY_LABEL.get(finding.severity, finding.severity.upper())}] "
            f"{finding.title} ({finding.host})"
        )
    lines.extend([
        "",
        "Checklist before submitting:",
        "",
        "1. Confirm every affected host is explicitly in the program's in-scope "
        "asset list; drop out-of-scope subdomains.",
        "2. Confirm the vulnerability class is not excluded (many programs exclude "
        "missing header, best-practice, version disclosure, and scanner output "
        "without demonstrated impact).",
        "3. Attach the reproduction command, the raw evidence, and a concrete "
        "impact statement: what an attacker gains, for whom, and under what "
        "preconditions.",
        "4. Treat tokens and secrets as inert evidence. Do not authenticate with "
        "harvested credentials for further requests; if the program needs proof, "
        "ask for a sanctioned test account or token.",
        "5. Search the program's disclosures and prior reports for duplicates "
        "before filing.",
        "6. If a finding is informational-only, submit it as an informational "
        "note rather than a vulnerability report.",
        "",
    ])
    client = recon.get("client") or {}
    if client.get("secrets"):
        lines.extend([
            "Client-side secret hits are reported with redacted values. "
            "A secret is only a valid finding when the credential belongs to the "
            "target, is live, and its privileges are demonstrated without "
            "exceeding the program's rules.",
            "",
        ])
    return lines


_CHAIN_ROLE_ID = {
    "precondition": "prasyarat",
    "exposure": "paparan",
    "injection": "injeksi",
    "execution": "eksekusi",
    "impact": "dampak",
    "excluded": "dikecualikan",
}


def _chain_lines(recon: dict, lang: str = "en") -> list[str]:
    tr = _lang(lang)
    chains = recon.get("chains") or {}
    if not chains.get("enabled"):
        return []
    items = chains.get("items") or []
    lines = [
        f"## {tr['chains']}",
        "",
        "A chain is assembled only from findings that were already observed on "
        "this scan. Each link points at a specific finding and inherits its "
        "reproduction status, so a chain cannot introduce a condition that was "
        "not seen. Statuses:",
        "",
        "- `observed` — every link reproduced on independent requests and none "
        "carries a decoy marker.",
        "- `partial` — at least one link is a single observation or still needs "
        "manual confirmation, or the chain needs a step that was deliberately "
        "not performed (such a chain says so in its limitations); severity is "
        "capped at medium.",
        "- `blocked` — a link carries a decoy/canary marker or the chain would "
        "need an action outside the read-only boundary; reported as info only.",
        "",
        "No chain was executed. No session was captured, no credential was "
        "replayed, and no request beyond read-only GET/HEAD was sent.",
        "",
    ]
    if not items:
        lines.extend([
            "No chain matched the findings from this scan. That does not mean "
            "no multi-step issue exists; it means the automated evidence did "
            "not connect any observed conditions.",
            "",
        ])
        return lines
    for item in items:
        status = str(item.get("status") or "partial")
        lines.extend([
            f"### `{item.get('id')}` [{status.upper()}] "
            f"{item.get('title')}",
            "",
            f"- **Status:** {status}",
            f"- **Severity:** "
            f"{SEVERITY_LABEL.get(str(item.get('severity')), str(item.get('severity')).upper())}",
            f"- **Summary:** {item.get('summary')}",
            "",
        ])
        if item.get("impact"):
            impact_label = ("Dampak bila dikonfirmasi" if lang == "id"
                            else "Impact if confirmed")
            lines.extend([f"**{impact_label}:** {item['impact']}", ""])
        links = item.get("links") or []
        if links:
            flow_parts = []
            for position, link in enumerate(links, start=1):
                role = _CHAIN_ROLE_ID.get(str(link.get("role")),
                                          str(link.get("role") or ""))
                flow_parts.append(
                    f"{position}. [{role}] {link.get('title')} "
                    f"({link.get('status')})")
            flow_label = "Alur exploit" if lang == "id" else "Exploit flow"
            lines.extend([f"**{flow_label}:** " + " → ".join(flow_parts), ""])
            lines.extend([
                "| # | Link | Host | Role | Status | Reproduced | Evidence |",
                "| --- | --- | --- | --- | --- | :-: | --- |",
            ])
            for position, link in enumerate(links, start=1):
                lines.append(
                    f"| {position} | {_cell(link.get('title'))} | "
                    f"{_cell(link.get('host'))} | {_cell(link.get('role'))} | "
                    f"{_cell(link.get('status'))} | "
                    f"{_cell(link.get('reproductions'))} | "
                    f"{_cell(link.get('evidence'))} |"
                )
            lines.append("")
        proof = item.get("proof") or []
        if proof:
            proof_label = ("Langkah bukti read-only" if lang == "id"
                           else "Read-only proof steps")
            lines.extend([f"**{proof_label}**", ""])
            for step in proof:
                lines.append(f"- {step}")
            lines.append("")
        limitations = item.get("limitations") or ""
        if limitations:
            limit_label = ("Batas chain" if lang == "id" else "Chain limitations")
            lines.extend([f"**{limit_label}:** {limitations}", ""])
    return lines


def _bundle_lines(recon: dict) -> list[str]:
    bundles = recon.get("bundles") or {}
    if not bundles.get("enabled"):
        return []
    hosts = bundles.get("hosts") or []
    lines = [
        "### Bundle / build drift",
        "",
        "Served HTML was compared read-only with the build artifacts it "
        "references (hashed chunks, framework manifests, service-worker "
        "precache, generator/`?ver=` values). Drift between what the page "
        "references and what the server actually serves usually means a stale "
        "deployment: the server can be patched while an older client bundle is "
        "still cached. Drift is a deployment signal, not a vulnerability.",
        "",
        f"- Hosts checked: **{bundles.get('hosts_checked', 0)}**",
        f"- Assets fetched: **{bundles.get('assets_fetched', 0)}**",
        f"- Manifests compared: **{bundles.get('manifests', 0)}**",
        f"- Drift signals: **{bundles.get('drift', 0)}**",
        f"- Missing referenced chunks: **{bundles.get('missing_chunks', 0)}**",
        f"- Truncated asset reads: **{bundles.get('truncated_assets', 0)}**",
        "",
    ]
    if not hosts:
        lines.extend([
            "No bundle artifacts were reachable within the read-only budget.",
            "",
        ])
        return lines
    lines.extend([
        "| Host | Frameworks | Build IDs | Assets | Drift | Missing |",
        "| --- | --- | --- | :-: | :-: | :-: |",
    ])
    for host in hosts:
        lines.append(
            f"| {_cell(host.get('host'))} | "
            f"{_cell(', '.join(host.get('frameworks') or []))} | "
            f"{_cell(', '.join(host.get('build_ids') or []))} | "
            f"{len(host.get('assets') or [])} | {len(host.get('drift') or [])} | "
            f"{len(host.get('missing') or [])} |"
        )
    lines.append("")

    drift_rows = [
        (host.get("host"), entry)
        for host in hosts for entry in (host.get("drift") or [])
    ]
    if drift_rows:
        lines.extend([
            "| Host | Signal | Detail |",
            "| --- | --- | --- |",
        ])
        for host_name, entry in drift_rows[:40]:
            signal = entry.get("type") or entry.get("signal") or "drift"
            if entry.get("logical_name"):
                detail = (
                    f"{entry['logical_name']}: page "
                    f"{', '.join(entry.get('page_hashes') or [])} vs manifest "
                    f"{', '.join(entry.get('manifest_hashes') or [])}"
                )
            elif entry.get("ids"):
                detail = "build IDs: " + ", ".join(entry["ids"])
            elif entry.get("generator"):
                detail = (
                    f"generator {entry['generator']} vs assets "
                    f"{', '.join(entry.get('asset_versions') or [])}"
                )
            elif entry.get("library"):
                detail = (
                    f"{entry['library']} vs ?ver={entry.get('asset_version')}"
                )
            else:
                detail = str(entry)[:200]
            lines.append(
                f"| {_cell(host_name)} | {_cell(signal)} | {_cell(detail)} |"
            )
        lines.append("")

    missing_rows = [
        (host.get("host"), entry)
        for host in hosts for entry in (host.get("missing") or [])
    ]
    if missing_rows:
        lines.extend([
            "Missing referenced chunks (HTTP 404/410 confirmed on a second "
            "request):",
            "",
            "| Host | Referenced chunk | Status | Control asset still served |",
            "| --- | --- | :-: | --- |",
        ])
        for host_name, entry in missing_rows[:20]:
            lines.append(
                f"| {_cell(host_name)} | {_cell(entry.get('url'))} | "
                f"{_cell(entry.get('status'))} | "
                f"{_cell(entry.get('control'))} "
                f"(HTTP {_cell(entry.get('control_status'))}) |"
            )
        lines.append("")

    assets = [
        (host.get("host"), asset)
        for host in hosts for asset in (host.get("assets") or [])
    ]
    if assets:
        lines.extend([
            "| Host | Asset | Role | HTTP | Bytes | Build hash | Libraries |",
            "| --- | --- | --- | :-: | :-: | --- | --- |",
        ])
        for host_name, asset in assets[:40]:
            libraries = ", ".join(
                f"{name} {', '.join(versions)}"
                for name, versions in (asset.get("libraries") or {}).items()
            )
            digest = str(asset.get("sha256") or "")[:16]
            bytes_cell = str(asset.get("bytes"))
            if asset.get("truncated"):
                declared = asset.get("content_length")
                bytes_cell += (
                    f" (truncated of {declared})" if declared
                    else " (truncated)")
            lines.append(
                f"| {_cell(host_name)} | {_cell(asset.get('url'))} | "
                f"{_cell(asset.get('role'))} | {_cell(asset.get('status'))} | "
                f"{_cell(bytes_cell)} | "
                f"{_cell(asset.get('build_hash') or digest)} | "
                f"{_cell(libraries)} |"
            )
        lines.append("")

    truncated_rows = [
        (host.get("host"), entry)
        for host in hosts for entry in (host.get("truncated") or [])
    ]
    if truncated_rows:
        lines.extend([
            "Truncated asset reads (the server declared more bytes than the "
            "read cap, so version and secret analysis covered only the "
            "captured prefix):",
            "",
            "| Host | Asset | Captured bytes | Content-Length |",
            "| --- | --- | :-: | :-: |",
        ])
        for host_name, entry in truncated_rows[:20]:
            lines.append(
                f"| {_cell(host_name)} | {_cell(entry.get('url'))} | "
                f"{_cell(entry.get('captured_bytes'))} | "
                f"{_cell(entry.get('declared_bytes'))} |"
            )
        lines.append("")

    libraries = bundles.get("libraries") or {}
    if libraries:
        lines.extend([
            "Client-side library versions observed in served bundles:",
            "",
            "| Library | Versions observed |",
            "| --- | --- |",
        ])
        for name, versions in libraries.items():
            lines.append(f"| {_cell(name)} | {_cell(', '.join(versions))} |")
        lines.extend([
            "",
            "Version strings are observations only. A distributor backport can "
            "make an old-looking version patched, and a stale string can hide a "
            "newer runtime.",
            "",
        ])
    warnings = bundles.get("warnings") or []
    if warnings:
        lines.extend(["Bundle recon warnings:", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")
    return lines


def render_markdown(result: ScanResult, lang: str = "en") -> str:
    tr = _lang(lang)
    findings = result.sorted_findings()
    counts = _severity_counts(findings)
    verified_count = sum(1 for finding in findings if finding.verified)
    evidence_count = sum(1 for finding in findings if finding.evidence_files)
    all_cves = [cve for finding in findings for cve in finding.cves]
    template_cves = sum(
        1 for cve in all_cves if cve.status.startswith("template")
    )
    candidate_cves = sum(
        1 for cve in all_cves if cve.status.startswith("candidate")
    )
    recon = result.recon or {}
    stats = result.stats or {}
    license_info = recon.get("license") or {}
    license_lines = (
        [
            f"- **{tr['license']}:** {license_info.get('watermark', '')}",
            "",
        ]
        if license_info
        else []
    )
    audit = result.audit if isinstance(result.audit, dict) else {}
    bypass = recon.get("bypass") or {}
    takeover_info = recon.get("takeover") or {}
    generated_at = (
        audit.get("generated_at") or result.finished_at or result.started_at
    )
    lines = [
        f"# {tr['title']} — {result.target}",
        "",
        f"- **{tr['generated']}:** {generated_at}",
        f"- **{tr['finished']}:** {result.finished_at or result.started_at}",
        f"- **{tr['tool']}:** webwarden {result.version}",
        f"- **{tr['scope']}:** {', '.join(result.scopes)}",
        f"- **{tr['authorization']}:** "
        f"{tr['auth_flag'] if result.authorized else tr['auth_missing']}",
        f"- **{tr['mode']}:** {tr['mode_value']}",
        f"- **{tr['poc']}:** `poc.sh` (read-only reproduction commands)",
        *license_lines,
        "",
        "> **PRIVATE — VERBATIM EVIDENCE.** The `evidence/` directory and the "
        "evidence blocks below are exact server responses. They are not "
        "truncated or redacted and may contain live passwords, API keys, "
        "cookies, tokens, and personal data. Keep this report owner-only "
        "(mode 600) and redact third-party secrets only if the program's "
        "disclosure policy requires it. The optional AI audit receives only "
        "scrubbed excerpts; the local evidence does not.",
        "",
        "## " + tr["summary"],
        "",
        f"| {tr['severity']} | {tr['count']} |",
        "| --- | --- |",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {SEVERITY_LABEL[severity]} | {counts.get(severity, 0)} |")
    lines.extend([
        "",
        f"- Subdomains / hosts discovered: **{stats.get('subdomains', 0)}**",
        f"- Live HTTP hosts: **{stats.get('live_hosts', 0)}**",
        f"- Open ports: **{stats.get('open_ports', 0)}**",
        f"- Discovered URLs: **{stats.get('urls', 0)}**",
        f"- HTTP requests issued: **{stats.get('requests', 0)}**",
        f"- Findings verified by reproduction: **{verified_count} / {len(findings)}**",
        f"- Findings with raw evidence files: **{evidence_count}** "
        f"(see `evidence/index.json`)",
        f"- CVE references: **{len(all_cves)}** "
        f"(template matches: {template_cves}, NVD candidates: {candidate_cves})",
        "",
    ])
    chains_meta = recon.get("chains") or {}
    if chains_meta.get("enabled"):
        lines.extend([
            f"- Evidence-linked exploit chains: **{chains_meta.get('total', 0)}** "
            f"(observed: {chains_meta.get('observed', 0)}, "
            f"partial: {chains_meta.get('partial', 0)}, "
            f"blocked: {chains_meta.get('blocked', 0)})",
            "",
        ])
    bundle_info = recon.get("bundles") or {}
    if bundle_info.get("enabled"):
        lines.extend([
            f"- Bundle assets inspected: **{bundle_info.get('assets_fetched', 0)}** "
            f"across {bundle_info.get('hosts_checked', 0)} host(s); build drift "
            f"signals: **{bundle_info.get('drift', 0)}**, missing referenced "
            f"chunks: **{bundle_info.get('missing_chunks', 0)}**",
            "",
        ])
    decoys = [finding for finding in findings if finding.decoy_suspected]
    if decoys:
        lines.extend([
            f"- Decoy/canary markers: **{len(decoys)}** finding(s) excluded from "
            "the risk score because a response advertised itself as a honeypot, "
            "decoy, or test credential.",
            "",
        ])
    if bypass.get("enabled"):
        lines.extend([
            f"- Access-control bypass checks: "
            f"**{stats.get('bypass_attempts', 0)}** paths, "
            f"**{stats.get('bypasses', 0)}** verified",
            "",
        ])
    if result.warnings:
        lines.extend([f"## {tr['warnings']}", ""])
        for warning in result.warnings:
            lines.append(f"- {warning}")
        lines.append("")

    verified_high = sum(
        1 for finding in findings
        if finding.severity in ("critical", "high") and finding.verified
        and not finding.decoy_suspected
    )
    unverified_high = sum(
        1 for finding in findings
        if finding.severity in ("critical", "high") and not finding.verified
        and not finding.decoy_suspected
    )
    lines.extend([f"## {tr['exec']}", ""])
    if verified_high:
        lines.append("- **" + tr["verified_high"].format(n=verified_high) + "**")
    else:
        lines.append(f"- **{tr['no_critical']}**")
    if unverified_high:
        lines.append(
            f"- {tr['unverified_high'].format(n=unverified_high)}"
        )
    lines.append(
        f"- {tr['medium_low'].format(medium=counts.get('medium', 0), low=counts.get('low', 0))}"
    )
    if audit:
        lines.append(
            f"- AI-assisted risk score: **{audit.get('risk_score', 0)}/100** "
            f"({audit.get('risk_band', 'unknown')}); provider "
            f"`{audit.get('provider', 'local')}`."
        )
    if bypass.get("enabled"):
        lines.append(
            f"- 401/403 bypass: **{bypass.get('bypasses', 0)}** verified out of "
            f"{len(bypass.get('attempts') or [])} tested path(s)."
        )
    else:
        lines.append("- 401/403 bypass checks were not requested (`--bypass`).")
    if takeover_info.get("enabled"):
        lines.append(
            f"- Subdomain takeover: **{takeover_info.get('takeovers', 0)}** "
            f"candidate(s) out of {takeover_info.get('hosts_checked', 0)} "
            "host(s) checked; claimability needs manual confirmation."
        )
    injection_info = recon.get("injection") or {}
    if injection_info.get("enabled"):
        probe_checks = injection_info.get("checks") or {}
        lines.append(
            f"- Injection probes: **{injection_info.get('parameters', 0)}** "
            f"parameter(s) tested; "
            f"**{stats.get('injection_findings', 0)}** finding(s) "
            f"(SQL error {probe_checks.get('sql_error', 0)}, "
            f"SQL boolean {probe_checks.get('sql_boolean', 0)}, "
            f"SSTI {probe_checks.get('ssti', 0)}, "
            f"XSS {probe_checks.get('xss', 0)}, "
            f"LFI {probe_checks.get('lfi', 0)}, "
            f"SSRF {probe_checks.get('ssrf', 0)}, "
            f"CRLF {probe_checks.get('crlf', 0)})."
        )
    else:
        lines.append("- Injection probes were not run.")
    backdoor_info = recon.get("backdoors") or {}
    if backdoor_info.get("enabled"):
        lines.append(
            f"- Backdoor path checks: **{backdoor_info.get('paths_tested', 0)}** "
            f"path(s) across {backdoor_info.get('hosts', 0)} host(s); "
            f"**{stats.get('backdoor_findings', 0)}** reachable shell(s)."
        )
    waf_info = recon.get("waf") or {}
    waf_providers = waf_info.get("providers") or []
    if waf_providers:
        listed = ", ".join(
            f"{item.get('provider')} ({item.get('evidence')}; "
            f"{len(item.get('hosts') or [])} host(s))"
            for item in waf_providers[:3]
        )
        lines.append(
            f"- CDN/WAF fingerprint: **{listed}**. Passive header match used to "
            "explain blocks and caching, not a vulnerability."
        )
    if all_cves:
        lines.append(
            f"- {len(all_cves)} CVE reference(s): {template_cves} template "
            f"match(es), {candidate_cves} NVD candidate(s)."
        )
    else:
        lines.append(
            "- No CVE references were produced. This is not proof that the target "
            "has no vulnerabilities."
        )
    lines.append("")

    if tr["validation"]:
        lines.extend([
            f"## {tr['validation']}",
            "",
            VALIDATION_NOTE.get(lang, VALIDATION_NOTE["en"]),
            "",
        ])
        if lang == "id":
            coverage = render_coverage(recon, stats, findings)
            if coverage:
                lines.extend(coverage)
            scenarios = render_scenarios(findings)
            if scenarios:
                lines.extend(scenarios)

    lines.extend(_readiness_lines(findings, recon, lang))
    lines.append("")

    if audit:
        lines.extend([render_audit_section(audit, result.target, lang=lang), ""])

    chain_section = _chain_lines(recon, lang)
    if chain_section:
        lines.extend(chain_section)
        lines.append("")

    groups: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in findings:
        groups.setdefault(
            (finding.title, finding.severity, finding.category), []
        ).append(finding)
    if groups:
        rank = {name: index for index, name in enumerate(
            ("critical", "high", "medium", "low", "info"))}
        lines.extend([
            f"## {tr['grouped']}",
            "",
            "| Issue | Severity | Category | Affected hosts | Count |",
            "| --- | --- | --- | --- | --- |",
        ])
        for (title, severity, category), items in sorted(
            groups.items(),
            key=lambda pair: (
                rank.get(pair[0][1], 9),
                -len(pair[1]),
                pair[0][0],
            ),
        ):
            hosts = sorted({item.host for item in items})
            shown = ", ".join(hosts[:6])
            if len(hosts) > 6:
                shown += f" (+{len(hosts) - 6} more)"
            lines.append(
                f"| {_cell(title)} | "
                f"{SEVERITY_LABEL.get(severity, severity.upper())} | "
                f"{_cell(category)} | {_cell(shown)} | {len(items)} |"
            )
        lines.append("")

    lines.extend([f"## {tr['findings']}", ""])
    if not findings:
        lines.extend([
            "No findings were produced by the automated, non-destructive checks. "
            "This does not prove the target is secure; manual testing is still required.",
            "",
        ])
    for index, finding in enumerate(findings, start=1):
        lines.extend(_render_finding(index, finding))

    if bypass.get("enabled"):
        attempts = bypass.get("attempts") or []
        lines.extend([f"## {tr['bypass']}", ""])
        if attempts:
            lines.extend([
                "| Host | Path | Baseline | Variants | Result |",
                "| --- | --- | --- | --- | --- |",
            ])
            for attempt in attempts:
                if attempt.get("bypass"):
                    result_text = (
                        f"BYPASS via {attempt.get('technique')} "
                        f"(HTTP {attempt.get('bypass_status')})"
                    )
                else:
                    result_text = "no bypass"
                lines.append(
                    f"| {_cell(attempt.get('host'))} | "
                    f"{_cell(attempt.get('path'))} | "
                    f"{_cell(attempt.get('baseline'))} | "
                    f"{_cell(attempt.get('variants'))} | "
                    f"{_cell(result_text)} |"
                )
            lines.append("")
        else:
            lines.extend([
                "No sensitive path returned HTTP 401/403, so no bypass "
                "variants were attempted.",
                "",
            ])
        lines.extend([
            "- The variant set is fixed and read-only: path normalization/case "
            "changes and proxy/rewrite headers.",
            "- A bypass is reported only when it reproduces twice, matches the "
            "expected content, and the original URL still returns 401/403.",
            "- This is not an authentication bypass; login pages and catch-all "
            "pages are rejected.",
            "",
        ])

    if all_cves:
        rows: list[tuple[str, object, Finding]] = []
        seen: set[tuple[str, str, str]] = set()
        for finding in findings:
            for cve in finding.cves:
                key = (cve.id, cve.status, cve.source)
                if key in seen:
                    continue
                seen.add(key)
                rows.append((cve.id, cve, finding))
        rows.sort(key=lambda row: (
            0 if row[1].status.startswith("template") else 1,
            -(row[1].score or 0.0),
            row[0],
        ))
        lines.extend([
            f"## {tr['cves']}",
            "",
            "| CVE | Status | Source | CVSS | Finding |",
            "| --- | --- | --- | --- | --- |",
        ])
        for cve_id, cve, finding in rows:
            lines.append(
                f"| {cve_id} | {_cell(cve.status)} | {_cell(cve.source)} | "
                f"{_cell(cve.score)} | {_cell(finding.title)} |"
            )
        lines.extend([
            "",
            "- `template match (detection)`: a nuclei template associated with the "
            "CVE matched the live response. Confirm exploitability and affected build.",
            "- `candidate (not verified)`: NVD matched the observed component version "
            "by CPE. This is not proof that the target is vulnerable; check the exact "
            "build, distribution patches, and configuration.",
            "",
        ])

    addresses = recon.get("addresses", {})
    dns_records = recon.get("dns", {})
    whois = recon.get("whois", {})
    lines.extend([
        f"## {tr['recon']}",
        "",
        "### DNS",
        "",
        "| Record | Values |",
        "| --- | --- |",
        f"| A | {_cell(', '.join(addresses.get('A', [])))} |",
        f"| AAAA | {_cell(', '.join(addresses.get('AAAA', [])))} |",
    ])
    for record in ("NS", "MX", "TXT", "CNAME", "SOA", "CAA"):
        values = dns_records.get(record) or []
        if values:
            lines.append(f"| {record} | {_cell(', '.join(values[:10]))} |")
    lines.extend(["", "### WHOIS", "", "| Field | Value |", "| --- | --- |"])
    for label, key in (
        ("Registrar", "registrar"),
        ("Created", "created"),
        ("Updated", "updated"),
        ("Expires", "expires"),
        ("Organization", "org"),
        ("Country", "country"),
    ):
        lines.append(f"| {label} | {_cell(whois.get(key))} |")
    lines.append(
        f"| Name servers | {_cell(', '.join(whois.get('name_servers', [])[:8]))} |"
    )
    if whois.get("error"):
        lines.append(f"| WHOIS error | {_cell(whois['error'])} |")
    lines.append("")

    subdomains = recon.get("subdomains", {})
    total_subs = subdomains.get("total", [])
    lines.extend([
        "### Subdomains",
        "",
        f"Passive (crt.sh): {len(subdomains.get('crtsh', []))} · "
        f"subfinder: {len(subdomains.get('subfinder', []))} · "
        f"DNS brute: {len(subdomains.get('brute', []))} · "
        f"certificate SAN: {len(subdomains.get('san', []))} · "
        f"total unique: {len(total_subs)}",
        "",
    ])
    if total_subs:
        lines.extend(["| Host |", "| --- |"])
        for host in total_subs[:200]:
            lines.append(f"| {_cell(host)} |")
        lines.append("")

    hosts = recon.get("hosts", [])
    lines.extend([
        "### Live HTTP hosts",
        "",
        "| Host | URL | Status | Title | Server | Tech |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for host in hosts:
        lines.append(
            f"| {_cell(host.get('host'))} | {_cell(host.get('url'))} | "
            f"{_cell(host.get('status'))} | {_cell(host.get('title'))} | "
            f"{_cell(host.get('server'))} | {_cell(', '.join(host.get('tech') or []))} |"
        )
    lines.append("")

    lines.append("")

    header_info = recon.get("headers") or {}
    matrix = header_info.get("matrix") or []
    if matrix:
        lines.extend([
            "### Security header coverage",
            "",
            "Presence is evaluated per endpoint; HSTS only applies to HTTPS "
            "responses, so plain HTTP rows are not penalised for lacking it.",
            "",
            "| Endpoint | HTTP | HSTS | CSP | XCTO | XFO | Referrer | Permissions |",
            "| --- | --- | :-: | :-: | :-: | :-: | :-: | :-: |",
        ])
        for entry in matrix[:100]:
            present = entry.get("present") or {}
            mark = lambda label: "yes" if present.get(label) else "no"
            lines.append(
                f"| {_cell(entry.get('url'))} | {_cell(entry.get('status'))} | "
                f"{mark('Strict-Transport-Security')} | "
                f"{mark('Content-Security-Policy')} | "
                f"{mark('X-Content-Type-Options')} | "
                f"{mark('X-Frame-Options')} | "
                f"{mark('Referrer-Policy')} | "
                f"{mark('Permissions-Policy')} |"
            )
        lines.append("")
    security = header_info.get("security_txt") or {}
    if security:
        lines.extend([
            "### security.txt",
            "",
            "| Host | Status | Contact | Expires |",
            "| --- | --- | --- | --- |",
        ])
        for host, entry in sorted(security.items()):
            contacts = ", ".join(entry.get("contacts") or [])
            status = "valid" if entry.get("valid") else (
                entry.get("reason") or f"HTTP {entry.get('status')}")
            if entry.get("expired"):
                status += " (expired)"
            lines.append(
                f"| {_cell(host)} | {_cell(status)} | {_cell(contacts)} | "
                f"{_cell(entry.get('expires'))} |"
            )
        lines.append("")

    client = recon.get("client") or {}
    if client:
        lines.extend([
            "### Client-side exposure",
            "",
            f"- Files scanned (HTML/JS): **{client.get('files_scanned', 0)}**",
            f"- Secret hits: **{client.get('secrets', 0)}** "
            "(values redacted; raw responses in private evidence)",
            f"- Source maps published: **{len(client.get('source_maps') or [])}**",
            f"- Credential-like URL parameters: **{client.get('url_tokens', 0)}**",
            f"- robots.txt path probing: "
            f"{'enabled' if client.get('robots_paths') else 'not requested'}",
            "",
        ])
        hits = client.get("secret_hits") or []
        if hits:
            lines.extend([
                "| Host | Kind | Severity | Redacted value | Files |",
                "| --- | --- | --- | --- | --- |",
            ])
            for hit in hits[:30]:
                files = hit.get("files") or []
                lines.append(
                    f"| {_cell(hit.get('host'))} | {_cell(hit.get('kind'))} | "
                    f"{SEVERITY_LABEL.get(hit.get('severity'), hit.get('severity'))} | "
                    f"{_cell(hit.get('redacted'))} | {len(files)} |"
                )
            lines.append("")
        maps = client.get("source_maps") or []
        if maps:
            lines.extend([
                "| Source map | Referenced by | Sources listed |",
                "| --- | --- | --- |",
            ])
            for entry in maps[:20]:
                lines.append(
                    f"| {_cell(entry.get('url'))} | {_cell(entry.get('script'))} | "
                    f"{_cell(entry.get('sources'))} |"
                )
            lines.append("")

    bundle_section = _bundle_lines(recon)
    if bundle_section:
        lines.extend(bundle_section)

    components = recon.get("components") or {}
    if components:
        lines.extend([
            "### Component versions",
            "",
            "| Component | Version | Evidence | Hosts |",
            "| --- | --- | --- | --- |",
        ])
        for name, info in components.items():
            if not isinstance(info, dict):
                continue
            lines.append(
                f"| {_cell(name)} | {_cell(info.get('version'))} | "
                f"{_cell(info.get('evidence'))} | "
                f"{_cell(', '.join(info.get('hosts') or []))} |"
            )
        lines.append("")

    nuclei = recon.get("nuclei")
    if isinstance(nuclei, dict):
        lines.extend([
            "### Nuclei template matching",
            "",
            f"- Status: {'ran' if nuclei.get('enabled') else 'skipped'}",
            f"- Engine: {_cell(nuclei.get('engine'))}",
            f"- Templates: {_cell(nuclei.get('templates'))}",
            f"- Targets: {nuclei.get('targets', 0)}",
            f"- Matches: {nuclei.get('matches', 0)}",
        ])
        if nuclei.get("note"):
            lines.append(f"- Note: {nuclei['note']}")
        lines.append("")

    takeover = recon.get("takeover") or {}
    if takeover.get("enabled"):
        lines.extend(["### Subdomain takeover candidates", ""])
        candidates = takeover.get("candidates") or []
        if candidates:
            lines.extend([
                "| Host | CNAME | Provider | HTTP | Result |",
                "| --- | --- | --- | --- | --- |",
            ])
            for item in candidates:
                lines.append(
                    f"| {_cell(item.get('host'))} | {_cell(item.get('cname'))} | "
                    f"{_cell(item.get('provider'))} | "
                    f"{_cell(item.get('http_status'))} | "
                    f"{'candidate' if item.get('takeover') else 'no marker'} |"
                )
            lines.append("")
        else:
            lines.extend([
                "No host matched a third-party CNAME plus an unclaimed-resource "
                "page.",
                "",
            ])
        if takeover.get("note"):
            lines.extend([f"Note: {takeover['note']}", ""])

    injection_info = recon.get("injection") or {}
    backdoor_info = recon.get("backdoors") or {}
    if injection_info.get("enabled") or backdoor_info.get("enabled"):
        lines.extend(["### Injection and backdoor probes", ""])
        if injection_info.get("enabled"):
            probe_checks = injection_info.get("checks") or {}
            lines.extend([
                f"Query parameters probed over GET: "
                f"**{injection_info.get('candidate_urls', 0)}** candidate URL(s), "
                f"**{injection_info.get('parameters', 0)}** parameter(s), "
                f"**{injection_info.get('requests', 0)}** request(s).",
                "",
                "| Probe | Detections |",
                "| --- | --- |",
                f"| SQL error signature | {probe_checks.get('sql_error', 0)} |",
                f"| SQL boolean differential | {probe_checks.get('sql_boolean', 0)} |",
                f"| Server-side template injection | {probe_checks.get('ssti', 0)} |",
                f"| Reflected HTML injection | {probe_checks.get('xss', 0)} |",
                f"| Local file inclusion | {probe_checks.get('lfi', 0)} |",
                f"| Server-side request fetch (SSRF) "
                f"| {probe_checks.get('ssrf', 0)} |",
                f"| CRLF/header injection | {probe_checks.get('crlf', 0)} |",
                "",
            ])
            if injection_info.get("note"):
                lines.extend([f"Note: {injection_info['note']}", ""])
        if backdoor_info.get("enabled"):
            lines.extend([
                f"Web shell paths requested: "
                f"**{backdoor_info.get('paths_tested', 0)}** path(s) across "
                f"**{backdoor_info.get('hosts', 0)}** host(s); "
                f"**{backdoor_info.get('findings', 0)}** reachable shell(s).",
                "",
            ])
            if backdoor_info.get("note"):
                lines.extend([f"Note: {backdoor_info['note']}", ""])
        for warning in (injection_info.get("warnings") or []) \
                + (backdoor_info.get("warnings") or []):
            lines.append(f"- {warning}")
        if (injection_info.get("warnings") or []) \
                or (backdoor_info.get("warnings") or []):
            lines.append("")

    ports = recon.get("ports", {})
    lines.extend(["### Ports", ""])
    if ports.get("skipped"):
        lines.extend([f"Skipped: {ports['skipped']}", ""])
    elif ports.get("note"):
        lines.extend([f"Note: {ports['note']}", ""])
    port_items = ports.get("ports", [])
    if port_items:
        lines.extend(["| IP | Port | Service |", "| --- | --- | --- |"])
        for item in port_items:
            lines.append(
                f"| {_cell(item.get('ip'))} | {_cell(item.get('port'))} | "
                f"{_cell(item.get('service'))} |"
            )
        lines.append("")
    elif not ports.get("skipped"):
        lines.extend(["No open ports were detected in the scanned set.", ""])

    urls = recon.get("urls", [])
    if urls:
        lines.extend(["### Discovered URLs (sample)", ""])
        for url in urls[:40]:
            lines.append(f"- `{_redact_query(url)}`")
        lines.append("")

    lines.extend([
        f"## {tr['limitations']}",
        "",
        "- Automated checks are read-only (GET/HEAD). Findings marked "
        "`needs manual verification` must be confirmed before reporting.",
        "- Authorization checks compare responses; they do not prove exploitability "
        "and never modify data.",
        "- Nuclei template matching is opt-in (`--nuclei`). It excludes "
        "intrusive/dos/fuzz/brute-force/default-login/headless/code/file/ssrf/oob "
        "tags and disables interactsh, but templates may still send "
        "template-defined requests. Review every match before reporting it.",
        "- NVD CVE candidates are version/CPE matches only. They are not proof of "
        "vulnerability; confirm the exact build and backports.",
        "- Evidence bodies are stored verbatim, unredacted, up to "
        "`--evidence-bytes` (default 5 MiB, hard ceiling 64 MiB). When a body "
        "hits that limit the finding says so and `poc.sh` can retrieve the "
        "complete response. Only the optional AI audit payload is scrubbed.",
        "- 401/403 bypass checks are opt-in (`--bypass`) and limited to a fixed, "
        "read-only variant set. They do not attack authentication or modify state; "
        "a negative result does not prove that no bypass exists.",
        "- Subdomain-takeover detection only flags a third-party CNAME combined "
        "with that provider's unclaimed-resource page. Claimability is never "
        "tested; verify manually and do not claim the resource yourself.",
        "- Client-side secret detection is pattern-based. A match is a candidate, "
        "not proof that the credential is live; it is never used, replayed, or "
        "validated. Report text redacts the value and the raw response stays in "
        "the private evidence directory.",
        "- Credential-like URL parameters are flagged from crawl output without "
        "being requested. Confirm the value is live before reporting it.",
        "- Injection probes append a benign signature, arithmetic expression, or "
        "traversal to one query parameter over GET only. They never extract data, "
        "write, upload, authenticate, or submit a shell command. A candidate is "
        "reported only when the signal is absent from the untouched baseline and "
        "reproduces on an independent request; parameters that look like "
        "credentials are skipped. The SSRF probe points the server at a random "
        "`.invalid` hostname so it can only fail at DNS resolution, and the CRLF "
        "probe injects a custom `X-WW-*` header name: no internal address and no "
        "header of consequence is ever requested.",
        "- Backdoor detection requests a fixed list of common web shell paths and "
        "matches known signatures. A hit is a reachable file, not proof that it "
        "was used; review logs and do not send it any command.",
        "- Evidence-linked chains connect only conditions this scan observed. "
        "`observed` means every link reproduced on independent requests; "
        "`partial` means at least one link needs manual confirmation or the "
        "chain depends on a step that was deliberately not performed (it is "
        "then a hypothesis, not an exploit); `blocked` means a link carries a "
        "decoy marker or the chain would need an action outside the read-only "
        "boundary. No chain was executed: no session was hijacked, no "
        "credential replayed, and no resource claimed.",
        "- Decoy/canary markers (honeypots, planted credentials, \"do not "
        "report\" pages) are detected from the response text. A match is a "
        "warning that the finding may be intentional, not proof; decoy findings "
        "are excluded from the risk score and priority ordering.",
        "- Bundle/build-drift recon compares served HTML with served artifacts. "
        "Drift means the deployment is inconsistent (for example, patched "
        "server but stale cached bundle); it is a deployment signal, not an "
        "exploitable condition. Version strings can be stale or backported.",
        "- The AI-assisted audit re-ranks and explains observed findings only. "
        "The local provider performs no network calls; the Ollama provider talks "
        "to a loopback endpoint by default and never receives evidence with "
        "obvious secrets. It is not an independent scanner.",
        "- Shared CDN/hosting addresses are not port-scanned to avoid affecting "
        "third parties.",
        "- No login attempts, password brute force, file uploads, writes, or "
        "backdoor/persistence actions are performed.",
        "",
        "---",
        "",
        "Generated by webwarden. Use only within an authorized scope.",
        "",
    ])
    return "\n".join(lines)


def write_report(result: ScanResult, outdir: Path,
                 lang: str = "en") -> dict[str, Path]:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(outdir, 0o700)
    except OSError:
        pass
    markdown_path = outdir / "report.md"
    html_path = outdir / "report.html"
    findings_path = outdir / "findings.json"
    scan_path = outdir / "scan.json"
    poc_path = outdir / "poc.sh"
    audit_md_path = outdir / "audit.md"
    audit_json_path = outdir / "audit.json"
    findings = result.sorted_findings()
    has_auth_a = any("$SESSION_A" in command
                     for finding in findings for command in finding.poc)
    has_auth_b = any("$SESSION_B" in command
                     for finding in findings for command in finding.poc)

    markdown_path.write_text(
        render_markdown(result, lang), encoding="utf-8")
    html_path.write_text(render_html(result, lang), encoding="utf-8")
    if result.audit:
        audit_heading = ("# Audit berbantuan AI — " if lang == "id"
                         else "# AI-assisted audit — ")
        audit_footer = (
            "Dibuat oleh webwarden. Gunakan hanya di dalam scope yang diizinkan."
            if lang == "id"
            else "Generated by webwarden. Use only within an authorized scope."
        )
        audit_md_path.write_text(
            "\n".join([
                f"{audit_heading}{result.target}",
                "",
                render_audit_section(result.audit, result.target,
                                     heading="", lang=lang),
                "",
                audit_footer,
                "",
            ]),
            encoding="utf-8",
        )
        audit_json_path.write_text(
            json.dumps(result.audit, indent=2), encoding="utf-8"
        )
    findings_path.write_text(
        json.dumps(
            {
                "target": result.target,
                "scopes": result.scopes,
                "generated": result.finished_at,
                "findings": [finding.to_dict() for finding in findings],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    scan_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    evidence_index = write_evidence_index(outdir, findings)
    secured = [markdown_path, html_path, findings_path, scan_path]
    if result.audit:
        secured.extend([audit_md_path, audit_json_path])
    if evidence_index:
        secured.append(evidence_index)
    for path in secured:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    write_script(
        poc_path,
        findings,
        result.target,
        generated_at=result.finished_at or result.started_at,
        has_auth_a=has_auth_a,
        has_auth_b=has_auth_b,
    )
    paths = {
        "markdown": markdown_path,
        "html": html_path,
        "findings": findings_path,
        "scan": scan_path,
        "poc": poc_path,
    }
    if result.audit:
        paths["audit"] = audit_md_path
        paths["audit_json"] = audit_json_path
    if evidence_index:
        paths["evidence_index"] = evidence_index
    return paths
