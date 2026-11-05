"""Component/version extraction and conservative NVD candidate lookup.

NVD results are version/CPE matches only. They are labelled as candidates and
must never be reported as confirmed until the exact build and backports have
been checked.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from collections import Counter
from typing import Iterable

from .models import (
    CONFIDENCE_MANUAL,
    CVE_STATUS_CANDIDATE,
    CveRef,
    Finding,
)
from .poc import for_finding
from .recon import Probe, external_get

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

COMPONENTS: dict[str, dict[str, object]] = {
    "nginx": {
        "regex": r"\bnginx/(\d+(?:\.\d+){1,3})",
        "cpes": (("f5", "nginx"), ("nginx", "nginx")),
    },
    "openresty": {
        "regex": r"\bopenresty/(\d+(?:\.\d+){1,4})",
        "cpes": (("openresty", "openresty"),),
    },
    "apache": {
        "regex": r"\bApache/(\d+(?:\.\d+){1,3})",
        "cpes": (("apache", "http_server"),),
    },
    "iis": {
        "regex": r"Microsoft-IIS/(\d+(?:\.\d+){1,3})",
        "cpes": (("microsoft", "internet_information_services"),),
    },
    "php": {
        "regex": r"\bPHP/(\d+(?:\.\d+){1,3})",
        "cpes": (("php", "php"),),
    },
    "wordpress": {
        "regex": r"WordPress[ /](\d+(?:\.\d+){1,3})",
        "cpes": (("wordpress", "wordpress"),),
    },
    "joomla": {
        "regex": r"Joomla!?[ /](\d+(?:\.\d+){1,3})",
        "cpes": (("joomla", "joomla!"),),
    },
    "drupal": {
        "regex": r"Drupal[ /](\d+(?:\.\d+){1,3})",
        "cpes": (("drupal", "drupal"),),
    },
    "jquery": {
        "regex": r"jquery(?:\.min)?\.js[^\"'<>]{0,80}?[?&]ver=(\d+(?:\.\d+){1,3})",
        "cpes": (("jquery", "jquery"),),
    },
    "openssl": {
        "regex": r"OpenSSL/(\d+\.\d+\.\d+[a-z]?)",
        "cpes": (("openssl", "openssl"),),
    },
}

PRIORITY = (
    "nginx", "apache", "php", "iis", "wordpress", "drupal", "joomla",
    "openresty", "jquery", "openssl",
)


def _pattern(component: str) -> re.Pattern[str]:
    return re.compile(str(COMPONENTS[component]["regex"]), re.IGNORECASE)


def _clean(value: object, limit: int = 300) -> str:
    text = CONTROL_RE.sub(" ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _sources(probe: Probe) -> list[tuple[str, str]]:
    result = probe.result
    if not result:
        return []
    headers = result.headers
    sources = [
        ("Server", headers.get("server", "")),
        ("X-Powered-By", headers.get("x-powered-by", "")),
        ("X-Generator", headers.get("x-generator", "")),
    ]
    if result.text:
        sources.append(("body", result.text[:200000]))
    return [(label, value) for label, value in sources if value]


def extract_versions(probes: Iterable[Probe]) -> dict[str, dict]:
    """Find credible component versions from headers and page metadata."""
    observations: dict[str, Counter] = {
        component: Counter() for component in COMPONENTS
    }
    evidence: dict[str, dict[str, str]] = {
        component: {} for component in COMPONENTS
    }
    urls: dict[str, str] = {}
    hosts: dict[str, set[str]] = {component: set() for component in COMPONENTS}

    for probe in probes:
        if not probe.live:
            continue
        for label, value in _sources(probe):
            for component in COMPONENTS:
                match = _pattern(component).search(value)
                if not match:
                    continue
                version = match.group(1).strip().lower()
                if not version:
                    continue
                observations[component][version] += 1
                evidence[component].setdefault(
                    version, f"{label}: {_clean(match.group(0), 120)}"
                )
                hosts[component].add(probe.host)
                if probe.url:
                    urls.setdefault(component, probe.url)

    found: dict[str, dict] = {}
    for component in PRIORITY:
        counter = observations[component]
        if not counter:
            continue
        version, count = counter.most_common(1)[0]
        found[component] = {
            "version": version,
            "count": count,
            "hosts": sorted(hosts[component])[:8],
            "url": urls.get(component, ""),
            "evidence": evidence[component].get(version, ""),
        }
    return found


def cpe_variants(component: str, version: str) -> list[str]:
    spec = COMPONENTS.get(component)
    if not spec:
        return []
    cpes = []
    for vendor, product in spec["cpes"]:  # type: ignore[index]
        cpes.append(
            f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        )
    return cpes


def _metrics(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        try:
            score_value = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_value = None
        return score_value, (_clean(severity, 20).lower() or None)
    return None, None


def parse_nvd(payload: object) -> list[CveRef]:
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", "replace")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return []
    if not isinstance(payload, dict):
        return []

    refs: list[CveRef] = []
    for item in payload.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve") or {}
        cve_id = str(cve.get("id") or "").upper()
        if not CVE_RE.fullmatch(cve_id):
            continue
        score, severity = _metrics(cve)
        references = cve.get("references") or []
        url = None
        for reference in references:
            value = reference.get("url") if isinstance(reference, dict) else None
            if value and str(value).startswith(("http://", "https://")):
                url = str(value)
                break
        refs.append(CveRef(
            id=cve_id,
            source="nvd",
            status=CVE_STATUS_CANDIDATE,
            score=score,
            severity=severity,
            url=url or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        ))
    refs.sort(key=lambda item: (-(item.score or 0.0), item.id))
    return refs


def lookup_cpe(cpe: str, *, timeout: float = 20.0,
               api_key: str | None = None) -> tuple[list[CveRef], str | None]:
    query = urllib.parse.urlencode({
        "virtualMatchString": cpe,
        "resultsPerPage": 50,
    })
    headers = {"apiKey": api_key} if api_key else None
    try:
        payload = external_get(
            f"{NVD_API}?{query}", timeout=timeout, headers=headers
        )
    except Exception as exc:  # urllib and socket errors vary
        return [], f"NVD query failed: {exc}"
    return parse_nvd(payload), None


def _rate_limiter(api_key: str | None):
    state = {"last": 0.0, "count": 0}
    delay = 0.7 if api_key else 6.3

    def wait() -> None:
        now = time.monotonic()
        if state["count"]:
            remaining = delay - (now - state["last"])
            if remaining > 0:
                time.sleep(remaining)
        state["count"] += 1
        state["last"] = time.monotonic()

    return wait


def candidate_finding(component: str, info: dict,
                      cves: list[CveRef]) -> Finding:
    version = str(info.get("version") or "")
    hosts = list(info.get("hosts") or [])
    host = hosts[0] if hosts else ""
    url = str(info.get("url") or (f"https://{host}/" if host else ""))
    observed = _clean(info.get("evidence"), 200)
    cpe_lines = ", ".join(cpe_variants(component, version))
    listing = ", ".join(
        f"{cve.id} (CVSS {cve.score or 'n/a'})" for cve in cves[:12]
    )
    description = (
        f"Webwarden extracted {component} {version} from the response and NVD "
        f"returns {len(cves)} CVE(s) matching the corresponding CPE. These are "
        "candidates only: NVD matches by version, not by the exact build, "
        "distribution patches, or configuration. Confirm the installed build "
        "and vendor advisories before reporting any of them."
    )
    finding = Finding(
        title=f"CVE candidates for {component} {version} (unverified)",
        severity="info",
        category="cve-candidate",
        host=host,
        url=url,
        description=description,
        remediation=(
            "Verify the exact build and backported patches, then apply the "
            "vendor advisories that actually affect this installation."
        ),
        evidence=(
            f"Observed: {observed or f'{component} {version}'}\n"
            f"Hosts: {', '.join(hosts) or '-'}\n"
            f"CPE: {cpe_lines}\n"
            f"CVEs: {listing}"
        ),
        confidence=CONFIDENCE_MANUAL,
        references=[cve.url for cve in cves if cve.url][:12],
        verified=False,
        verification="version-based NVD candidate; not tested on the target",
        cves=list(cves),
    )
    finding.poc = for_finding(finding)
    return finding


def lookup_versions(
    versions: dict[str, dict],
    *,
    timeout: float = 20.0,
    api_key: str | None = None,
    max_components: int = 3,
    max_queries: int = 4,
) -> tuple[list[Finding], list[str], dict]:
    """Resolve observed component versions to candidate CVEs via NVD."""
    warnings: list[str] = []
    findings: list[Finding] = []
    meta: dict = {"components": {}, "queries": 0, "candidates": 0}
    wait = _rate_limiter(api_key)
    queries = 0
    checked = 0

    for component in PRIORITY:
        if component not in versions or checked >= max_components:
            continue
        info = versions[component]
        version = str(info.get("version") or "")
        if not version:
            continue
        checked += 1
        collected: list[CveRef] = []
        for cpe in cpe_variants(component, version):
            if queries >= max_queries:
                warnings.append(
                    "NVD lookup stopped at the query limit; some components "
                    "were not checked"
                )
                break
            wait()
            queries += 1
            refs, error = lookup_cpe(cpe, timeout=timeout, api_key=api_key)
            if error:
                warnings.append(f"{component} {version}: {error}")
                break
            collected.extend(refs)
            if refs:
                break
        unique: dict[str, CveRef] = {}
        for ref in collected:
            unique.setdefault(ref.id, ref)
        cves = sorted(
            unique.values(), key=lambda item: (-(item.score or 0.0), item.id)
        )[:15]
        meta["components"][component] = {
            "version": version,
            "cpes": cpe_variants(component, version),
            "cves": len(cves),
        }
        if cves:
            findings.append(candidate_finding(component, info, cves))
        if queries >= max_queries:
            break

    meta["queries"] = queries
    meta["candidates"] = sum(len(finding.cves) for finding in findings)
    return findings, warnings, meta
