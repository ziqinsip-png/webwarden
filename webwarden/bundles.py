"""Read-only JavaScript bundle and build-artifact reconnaissance.

Single-page frameworks serve compiled bundles. A server can be patched while
the HTML still references an older build: a hashed chunk listed by the page is
gone, the page and its build manifest disagree, or the page generator version
and the served core assets diverge. This module records what the served
artifacts say about themselves and reports that drift as an observation.

It never executes a bundle, never calls an API from inside one, and never
treats a version string as proof of a vulnerability.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .models import CONFIDENCE_CONFIRMED, CONFIDENCE_FIRM, Finding
from .util import in_scope

MAX_HTML = 800_000
MAX_ASSET = 1_048_576

TAG_RE = re.compile(r"<(script|link)\b[^>]*>", re.IGNORECASE)
SRC_RE = re.compile(r"""\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
HREF_RE = re.compile(r"""\bhref\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
REL_RE = re.compile(r"""\brel\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
SW_RE = re.compile(
    r"""serviceWorker\.register\(\s*["']([^"']+)["']""", re.IGNORECASE)

HEX_HASH_RE = re.compile(
    r"[.\-]([0-9a-f]{8,40})(?=\.(?:chunk\.)?(?:m?js|css))", re.IGNORECASE)
ALT_HASH_RE = re.compile(
    r"[.\-]([A-Za-z0-9_-]{8,40})(?=\.(?:chunk\.)?(?:m?js|css))")

BUILD_ID_RES = (
    re.compile(r'"buildId"\s*:\s*"([^"]{3,120})"'),
    re.compile(r"""__BUILD_ID__\s*=\s*["']([^"']{3,120})["']"""),
)
NEXT_BUILD_PATH_RE = re.compile(
    r"/_next/static/([^/\"'?]+)/_buildManifest\.js", re.IGNORECASE)
NUXT_BUILD_PATH_RE = re.compile(r"/_nuxt/([^/\"'?]+)/", re.IGNORECASE)

GENERATOR_RE = re.compile(
    r"""<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
GENERATOR_VALUE_RE = re.compile(
    r"^\s*([A-Za-z][\w .+-]{1,40}?)\s+v?(\d+(?:\.\d+){1,3})")
VER_PARAM_RE = re.compile(r"[?&]ver=(\d+(?:\.\d+){1,3})")
WP_CORE_VER_RE = re.compile(
    r"/wp-includes/[^\"'?\s]+\?ver=(\d+(?:\.\d+){1,3})", re.IGNORECASE)
JQUERY_VER_RE = re.compile(
    r"/jquery(?:\.min|\.slim|\.slim\.min)?\.js\?ver=(\d+(?:\.\d+){1,3})",
    re.IGNORECASE)

FRAMEWORK_RULES = (
    ("Next.js", re.compile(
        r"__NEXT_DATA__|/_next/static/|x-powered-by:\s*next\.js", re.IGNORECASE)),
    ("Nuxt", re.compile(r"__NUXT__|/_nuxt/")),
    ("Create React App", re.compile(
        r"/static/js/(?:main|runtime-main|2)\.[0-9a-f]{6,}\.(?:chunk\.)?js",
        re.IGNORECASE)),
    ("Vite", re.compile(r"/assets/(?:index|vendor|main)-[A-Za-z0-9_-]{8,}\.js")),
    ("Angular", re.compile(r"ng-version=|(?:main|runtime)-es20\d\d")),
    ("SvelteKit", re.compile(r"__sveltekit|/_app/immutable/")),
    ("Gatsby", re.compile(r"___gatsby|/page-data/")),
    ("WordPress", re.compile(r"wp-content/|wp-includes/")),
    ("Drupal", re.compile(r"drupal-settings-json|/sites/default/files/")),
    ("Ember", re.compile(r"ember-view|ember-cli")),
    ("Adobe Experience Manager", re.compile(r"/etc\.clientlibs/|clientlib-")),
    ("Vue", re.compile(r"__VUE__|data-v-[0-9a-f]{6,}")),
)

LIBRARY_RES = (
    ("jQuery", re.compile(r"jQuery (?:JavaScript Library )?v?(\d+\.\d+\.\d+)",
                          re.IGNORECASE)),
    ("jQuery", re.compile(r"jquery[.\-](\d+\.\d+\.\d+)(?:\.slim)?(?:\.min)?\.js",
                          re.IGNORECASE)),
    ("Vue", re.compile(r"Vue\.js v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Vue", re.compile(r"vue[.\-]v?(\d+\.\d+\.\d+)\.(?:min\.)?js", re.IGNORECASE)),
    ("Angular", re.compile(r"""ng-version=["'](\d+\.\d+\.\d+)""", re.IGNORECASE)),
    ("Angular", re.compile(r"""Version\("(\d+\.\d+\.\d+)"\)""")),
    ("React", re.compile(r"""react(?:-dom)?[.\-]v?(\d+\.\d+\.\d+)""",
                         re.IGNORECASE)),
    ("React", re.compile(r"React v(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Bootstrap", re.compile(r"Bootstrap v(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Bootstrap", re.compile(r"""bootstrap[.\-](\d+\.\d+\.\d+)""", re.IGNORECASE)),
    ("Lodash", re.compile(r"Lodash[ /]v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Lodash", re.compile(r"""\.VERSION\s*=\s*["'](\d+\.\d+\.\d+)["']""")),
    ("Moment.js", re.compile(r"moment\.js[ /]v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Moment.js", re.compile(r"""moment[.\-]v?(\d+\.\d+\.\d+)\.min\.js""",
                             re.IGNORECASE)),
    ("htmx", re.compile(r"htmx(?:\.org)?[ /]v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Alpine.js", re.compile(r"Alpine\.js v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Ember", re.compile(r"Ember[ /]v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Svelte", re.compile(r"svelte[.\-]v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("DOMPurify", re.compile(r"DOMPurify[ /]v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("Prototype", re.compile(r"Prototype[ /]v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
)

# Libraries whose versions can be fed to the NVD candidate lookup.
NVD_LIBRARY_MAP = {"jQuery": "jquery", "WordPress": "wordpress"}


@dataclass
class BundleAsset:
    url: str
    role: str
    status: int | None = None
    size: int = 0
    sha256: str = ""
    build_hash: str | None = None
    libraries: dict[str, list[str]] = field(default_factory=dict)
    content_length: int | None = None
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "role": self.role,
            "status": self.status,
            "bytes": self.size,
            "content_length": self.content_length,
            "truncated": self.truncated,
            "sha256": self.sha256,
            "build_hash": self.build_hash,
            "libraries": {name: list(values)
                          for name, values in self.libraries.items()},
        }


@dataclass
class HostBundleReport:
    host: str
    url: str = ""
    frameworks: list[str] = field(default_factory=list)
    build_ids: list[str] = field(default_factory=list)
    assets: list[BundleAsset] = field(default_factory=list)
    manifests: list[dict] = field(default_factory=list)
    library_sources: dict[str, dict[str, list[str]]] = field(
        default_factory=dict)
    drift: list[dict] = field(default_factory=list)
    missing: list[dict] = field(default_factory=list)
    truncated: list[dict] = field(default_factory=list)
    skipped: int = 0

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "url": self.url,
            "frameworks": list(self.frameworks),
            "build_ids": list(self.build_ids),
            "assets": [asset.to_dict() for asset in self.assets],
            "manifests": list(self.manifests),
            "libraries": {
                name: {version: list(urls) for version, urls in versions.items()}
                for name, versions in self.library_sources.items()
            },
            "drift": list(self.drift),
            "missing": list(self.missing),
            "truncated": list(self.truncated),
            "skipped": self.skipped,
        }


def asset_hash(url: str) -> str | None:
    path = urlsplit(url).path
    match = HEX_HASH_RE.search(path) or ALT_HASH_RE.search(path)
    if not match:
        return None
    value = match.group(1)
    mixed = (any(ch.isupper() for ch in value)
             and any(ch.islower() for ch in value))
    if not any(ch.isdigit() for ch in value) and not mixed:
        return None
    return value.lower()


def logical_name(url: str) -> str:
    name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
    if not name:
        return ""
    name = re.sub(r"\.(?:chunk|min)\.(m?js|css)$", r".\1", name)
    name = re.sub(
        r"[.\-][0-9a-zA-Z_-]{8,40}(?=\.(?:chunk\.)?(?:m?js|css)$)", "", name)
    return name


def extract_assets(html: str, base_url: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in TAG_RE.finditer(html[:MAX_HTML]):
        tag = match.group(0)
        kind = match.group(1).lower()
        src = SRC_RE.search(tag)
        href = HREF_RE.search(tag)
        rel = REL_RE.search(tag)
        rel_value = rel.group(1).lower() if rel else ""
        raw = None
        role = None
        if kind == "script" and src:
            raw, role = src.group(1), "script"
        elif kind == "link" and href:
            path = urlsplit(urljoin(base_url, href.group(1))).path.lower()
            if "modulepreload" in rel_value:
                raw, role = href.group(1), "modulepreload"
            elif "manifest" in rel_value:
                raw, role = href.group(1), "manifest"
            elif "preload" in rel_value and path.endswith((".js", ".mjs")):
                raw, role = href.group(1), "modulepreload"
        if not raw:
            continue
        url = urljoin(base_url, raw.strip())
        if not url.lower().startswith(("http://", "https://")):
            continue
        found.append((url, role))
    for match in SW_RE.finditer(html[:MAX_HTML]):
        url = urljoin(base_url, match.group(1))
        if url.lower().startswith(("http://", "https://")):
            found.append((url, "service-worker"))
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for url, role in found:
        if url in seen:
            continue
        seen.add(url)
        unique.append((url, role))
    return unique


def detect_frameworks(html: str, headers: dict[str, str] | None = None) -> list[str]:
    header_text = "\n".join(
        f"{key}: {value}" for key, value in (headers or {}).items())
    haystack = html[:MAX_HTML] + "\n" + header_text
    found: list[str] = []
    for name, rule in FRAMEWORK_RULES:
        if rule.search(haystack):
            found.append(name)
    return found[:6]


def extract_build_ids(html: str) -> list[str]:
    ids: list[str] = []
    for rule in BUILD_ID_RES:
        for match in rule.finditer(html[:MAX_HTML]):
            value = match.group(1).strip()
            if value and value not in ids:
                ids.append(value)
    for match in NEXT_BUILD_PATH_RE.finditer(html[:MAX_HTML]):
        value = match.group(1).strip()
        if value and value not in ids:
            ids.append(value)
    return ids[:6]


def _add_library(found: dict[str, set[str]], name: str, version: str) -> None:
    found.setdefault(name, set()).add(version)


def extract_libraries(text: str, url_hint: str = "") -> dict[str, list[str]]:
    sample = (text or "")[:MAX_ASSET]
    haystacks = [sample]
    if url_hint:
        haystacks.append(url_hint)
    found: dict[str, set[str]] = {}
    for name, rule in LIBRARY_RES:
        for haystack in haystacks:
            for match in rule.finditer(haystack):
                _add_library(found, name, match.group(1))
    return {name: sorted(versions) for name, versions in found.items()}


def generator_version(html: str) -> tuple[str, str] | None:
    match = GENERATOR_RE.search(html[:MAX_HTML])
    if not match:
        return None
    parsed = GENERATOR_VALUE_RE.match(match.group(1))
    if not parsed:
        return None
    return parsed.group(1).strip(), parsed.group(2)


def looks_like_manifest(text: str) -> bool:
    head = (text or "").lstrip()[:4096]
    if head.startswith(("{", "[")):
        return True
    return "__BUILD_MANIFEST" in head or "precacheAndRoute" in head


def manifest_assets(text: str) -> list[str]:
    sample = (text or "")[:MAX_HTML]
    found = set(re.findall(
        r"""["'](/[^"']+\.(?:m?js|css))["']""", sample, re.IGNORECASE))
    found |= set(re.findall(
        r"""["']((?:\./)?(?:static|assets|_next|_nuxt|js)/[^"']+\.(?:m?js|css))["']""",
        sample, re.IGNORECASE))
    return sorted(found)


def _asset_map(paths: list[str]) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for path in paths:
        name = logical_name(path)
        if not name:
            continue
        digest = asset_hash(path)
        if not digest:
            continue
        mapping.setdefault(name, set()).add(digest)
    return mapping


def compare_deployments(
    html_urls: list[str],
    manifest_text: str,
) -> tuple[list[dict], list[str]]:
    """Compare hashed assets referenced by a page with those a manifest lists."""
    manifest_list = manifest_assets(manifest_text)
    if not manifest_list:
        return [], []
    html_map = _asset_map(html_urls)
    manifest_map = _asset_map(manifest_list)
    drift: list[dict] = []
    for name, html_hashes in sorted(html_map.items()):
        manifest_hashes = manifest_map.get(name)
        if not manifest_hashes:
            continue
        if html_hashes & manifest_hashes:
            continue
        drift.append({
            "type": "asset-hash-mismatch",
            "logical_name": name,
            "page_hashes": sorted(html_hashes),
            "manifest_hashes": sorted(manifest_hashes),
        })
    return drift[:12], manifest_list


def version_drift(html: str, library_sources: dict[str, dict[str, list[str]]],
                  assets: list[BundleAsset]) -> list[dict]:
    """Compare the page generator with the core asset versions it references."""
    drift: list[dict] = []
    generator = generator_version(html)
    if not generator:
        return drift
    name, version = generator
    if name.lower() == "wordpress":
        core_versions = sorted(set(WP_CORE_VER_RE.findall(html[:MAX_HTML])))
        conflicting = [
            item for item in core_versions
            if item != version
            and not item.startswith(version + ".")
            and not version.startswith(item + ".")
        ]
        if conflicting:
            drift.append({
                "type": "generator-vs-core-asset",
                "generator": f"{name} {version}",
                "asset_versions": conflicting[:6],
                "sources": [
                    asset.url for asset in assets
                    if WP_CORE_VER_RE.search(asset.url)
                ][:6],
            })
    jquery_versions = library_sources.get("jQuery", {})
    if jquery_versions:
        for version_key in sorted(jquery_versions):
            for asset in assets:
                match = JQUERY_VER_RE.search(asset.url)
                if not match:
                    continue
                asset_version = match.group(1)
                if asset_version == version_key \
                        or asset_version.startswith(version_key + ".") \
                        or version_key.startswith(asset_version + "."):
                    continue
                drift.append({
                    "type": "library-vs-asset-version",
                    "library": f"jQuery {version_key}",
                    "asset_version": asset_version,
                    "source": asset.url,
                })
    return drift[:6]


def manifest_candidates(
    html: str,
    base_url: str,
    frameworks: list[str],
) -> list[str]:
    candidates: list[str] = []
    for match in TAG_RE.finditer(html[:MAX_HTML]):
        tag = match.group(0)
        href = HREF_RE.search(tag)
        rel = REL_RE.search(tag)
        if href and rel and "manifest" in rel.group(1).lower():
            candidates.append(urljoin(base_url, href.group(1)))
    lowered = html[:MAX_HTML]
    if "Create React App" in frameworks \
            or re.search(r"/static/js/main\.[^/\"']+\.js", lowered):
        candidates.append(urljoin(base_url, "/asset-manifest.json"))
    next_match = NEXT_BUILD_PATH_RE.search(lowered)
    if next_match:
        candidates.append(urljoin(
            base_url,
            f"/_next/static/{next_match.group(1)}/_buildManifest.js"))
    if "Nuxt" in frameworks:
        build_match = re.search(r'"buildId"\s*:\s*"([^"]+)"', lowered)
        if build_match:
            candidates.append(urljoin(
                base_url, f"/_nuxt/builds/meta/{build_match.group(1)}.json"))
    if "Vite" in frameworks:
        candidates.append(urljoin(base_url, "/.vite/manifest.json"))
    seen: set[str] = set()
    unique: list[str] = []
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        unique.append(url)
    return unique[:4]


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _declared_bytes(result) -> int | None:
    headers = getattr(result, "headers", None) or {}
    raw = headers.get("content-length")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _record_manifest_entries(
    report: HostBundleReport,
    library_sources: dict[str, dict[str, list[str]]],
    libraries: dict[str, list[str]],
    url: str,
) -> None:
    for name, versions in libraries.items():
        for version in versions:
            bucket = library_sources.setdefault(name, {}).setdefault(version, [])
            if url not in bucket and len(bucket) < 3:
                bucket.append(url)
            report.library_sources = library_sources


def analyze(
    probes,
    fetch,
    scopes: list[str],
    *,
    cache: dict | None = None,
    max_hosts: int = 4,
    max_assets: int = 10,
    max_requests: int = 60,
) -> tuple[list[tuple[Finding, object]], list[HostBundleReport], dict]:
    """Inspect served bundles and build artifacts for one scan.

    ``fetch`` must return an HttpResult-like object for a URL. ``cache`` lets
    the caller share already-downloaded responses (for example the scripts the
    secret scanner fetched) so nothing is requested twice.
    """
    cache = cache if cache is not None else {}
    findings: list[tuple[Finding, object]] = []
    reports: list[HostBundleReport] = []
    warnings: list[str] = []
    requests = 0
    hosts_done = 0

    def load(url: str, force: bool = False):
        nonlocal requests
        if not force and url in cache:
            return cache[url]
        if requests >= max_requests:
            warnings.append(
                "bundle request budget reached; some artifacts were not fetched")
            return None
        requests += 1
        result = fetch(url)
        if not force:
            cache[url] = result
        return result

    for probe in probes:
        if hosts_done >= max_hosts:
            break
        if not getattr(probe, "live", False) or not probe.result or not probe.url:
            continue
        host = (probe.host or "").lower().rstrip(".")
        if not host or not in_scope(host, scopes):
            continue
        hosts_done += 1
        html = probe.result.text or ""
        base = probe.result.final_url or probe.url
        report = HostBundleReport(host=host, url=base)
        report.frameworks = detect_frameworks(html, probe.result.headers)
        report.build_ids = extract_build_ids(html)
        library_sources: dict[str, dict[str, list[str]]] = {}

        manifest_urls: list[str] = []
        for url, role in extract_assets(html, base):
            asset_host = _host_of(url)
            if asset_host and not in_scope(asset_host, scopes):
                report.skipped += 1
                continue
            if role == "manifest":
                manifest_urls.append(url)
                continue
            if len(report.assets) >= max_assets:
                continue
            result = load(url)
            if result is None:
                break
            digest = hashlib.sha256(result.body).hexdigest() if result.body else ""
            declared = _declared_bytes(result)
            truncated = bool(getattr(result, "truncated", False)) or (
                declared is not None and len(result.body) < declared)
            asset = BundleAsset(
                url=url,
                role=role,
                status=result.status,
                size=len(result.body),
                sha256=digest,
                build_hash=asset_hash(url),
                content_length=declared,
                truncated=truncated,
            )
            if truncated:
                report.truncated.append({
                    "url": url,
                    "captured_bytes": len(result.body),
                    "declared_bytes": declared,
                })
                if len(report.truncated) <= 3:
                    warnings.append(
                        f"{url}: read {len(result.body)} of "
                        f"{declared if declared is not None else 'unknown'} "
                        "bytes; version and secret conclusions cover only the "
                        "captured prefix")
            if result.ok and result.status == 200 and result.body:
                asset.libraries = extract_libraries(result.text, url)
                _record_manifest_entries(
                    report, library_sources, asset.libraries, url)
                if role == "service-worker":
                    manifest_urls.append(url)
            report.assets.append(asset)

        generator = generator_version(html)
        if generator:
            name, version = generator
            if name.lower() in ("wordpress", "drupal", "joomla"):
                _record_manifest_entries(
                    report, library_sources, {name: [version]}, base)

        raw_manifests: list[tuple[str, str, object]] = []
        candidates = manifest_candidates(html, base, report.frameworks) \
            + manifest_urls
        for manifest_url in candidates[:4]:
            manifest_host = _host_of(manifest_url)
            if manifest_host and not in_scope(manifest_host, scopes):
                continue
            result = load(manifest_url)
            if result is None:
                break
            if not result.ok or result.status != 200 or not result.body:
                continue
            text = result.text
            if not looks_like_manifest(text):
                continue
            listed = manifest_assets(text)
            report.manifests.append({
                "url": manifest_url,
                "status": result.status,
                "bytes": len(result.body),
                "assets": len(listed),
            })
            raw_manifests.append((manifest_url, text, result))

        html_urls = [asset.url for asset in report.assets]
        for manifest_url, text, manifest_result in raw_manifests:
            drift, _listed = compare_deployments(html_urls, text)
            for entry in drift:
                entry["manifest"] = manifest_url
                report.drift.append(entry)
                finding = Finding(
                    title=(
                        "Build artifact drift: "
                        f"{entry['logical_name']} hash differs between page "
                        "and build manifest"
                    ),
                    severity="info",
                    category="bundle-drift",
                    host=host,
                    url=manifest_url,
                    description=(
                        "The page references one build hash for "
                        f"{entry['logical_name']} while the build manifest "
                        "lists another. This usually means the HTML cache and "
                        "the deployed bundle come from different builds. A "
                        "patched server can still serve an older client bundle, "
                        "so verify the served artifact before judging whether "
                        "any code issue is actually present."
                    ),
                    remediation=(
                        "Rebuild and redeploy the front end so the HTML, "
                        "manifest, and every referenced chunk come from the "
                        "same build, then purge stale HTML caches."
                    ),
                    evidence=(
                        f"Page hashes: {', '.join(entry['page_hashes'])}\n"
                        f"Manifest hashes: "
                        f"{', '.join(entry['manifest_hashes'])}\n"
                        f"Manifest: {manifest_url}\n"
                        "Source: HTML asset references compared with the "
                        "manifest fetched read-only."
                    ),
                    confidence=CONFIDENCE_FIRM,
                    verified=True,
                    verification=(
                        "page and manifest both fetched directly and disagree "
                        f"on {entry['logical_name']}"
                    ),
                    poc=[
                        f"curl -sS {manifest_url} | head -c 400",
                        "# Compare the hash above with the script src in the "
                        "page HTML.",
                    ],
                )
                finding.reproductions = 1
                finding.stable = True
                findings.append((finding, manifest_result))

        build_drift = _build_id_drift(report)
        if build_drift:
            report.drift.append(build_drift)
            finding = Finding(
                title="Build identifiers disagree within the served page",
                severity="info",
                category="bundle-drift",
                host=host,
                url=base,
                description=(
                    "The page embeds more than one framework build identifier. "
                    "This suggests cached HTML from an older build is being "
                    "served next to assets from a newer one, or the reverse. "
                    "It is a deployment-consistency signal, not a "
                    "vulnerability by itself."
                ),
                remediation=(
                    "Serve HTML and its assets from the same build and purge "
                    "cached index pages."
                ),
                evidence="Build identifiers observed:\n"
                         + "\n".join(f"- {value}"
                                     for value in build_drift["ids"]),
                confidence=CONFIDENCE_FIRM,
                verified=True,
                verification="multiple build identifiers matched in one response",
            )
            finding.reproductions = 1
            finding.stable = True
            findings.append((finding, probe.result))

        # Version drift is computed after every asset has been loaded.
        drift_versions = version_drift(html, library_sources, report.assets)
        for entry in drift_versions:
            report.drift.append(entry)
            if entry["type"] == "generator-vs-core-asset":
                title = (
                    "Page generator version differs from served core assets")
                evidence = (
                    f"Generator: {entry['generator']}\n"
                    f"Core asset ?ver= values: "
                    f"{', '.join(entry['asset_versions'])}\n"
                    "Sources:\n"
                    + "\n".join(f"- {url}" for url in entry["sources"])
                )
                description = (
                    "The generator meta tag and the core assets under "
                    "/wp-includes/ report different versions. That can mean "
                    "the core was updated while cached assets or a reverse "
                    "proxy copy still serve the old build. Confirm which "
                    "version the server actually executes before reporting "
                    "anything."
                )
            else:
                title = (
                    "jQuery asset cache version differs from the served build")
                evidence = (
                    f"Library string: {entry['library']}\n"
                    f"Asset ?ver= value: {entry['asset_version']}\n"
                    f"Asset: {entry['source']}"
                )
                description = (
                    "The jQuery version string inside the served JavaScript "
                    "and the ?ver= cache-busting value on its URL disagree. "
                    "This is a caching/deployment signal; the loaded code is "
                    "whichever one the browser actually executes."
                )
            finding = Finding(
                title=title,
                severity="info",
                category="bundle-drift",
                host=host,
                url=base,
                description=description,
                remediation=(
                    "Purge the asset cache and redeploy so the page, its "
                    "asset URLs, and the served files come from one build."
                ),
                evidence=evidence,
                confidence=CONFIDENCE_FIRM,
                verified=True,
                verification="both version values observed in served content",
            )
            finding.reproductions = 1
            finding.stable = True
            findings.append((finding, probe.result))

        missing = [
            asset for asset in report.assets
            if asset.status in (404, 410)
        ]
        served = [
            asset for asset in report.assets
            if asset.status == 200 and asset.role in ("script", "modulepreload")
        ]
        if missing and served:
            target = missing[0]
            confirmation = load(target.url, force=True)
            confirmed_status = getattr(confirmation, "status", None)
            if confirmed_status in (404, 410):
                entry = {
                    "url": target.url,
                    "status": confirmed_status,
                    "control": served[0].url,
                    "control_status": served[0].status,
                }
                report.missing.append(entry)
                finding = Finding(
                    title=(
                        "Referenced JavaScript chunk missing from the "
                        "deployed build"
                    ),
                    severity="info",
                    category="bundle-drift",
                    host=host,
                    url=target.url,
                    description=(
                        "The page references a hashed chunk that the server no "
                        "longer serves, while other referenced chunks still "
                        "return HTTP 200. This usually means the index page is "
                        "from an older build than the deployed assets (or the "
                        "reverse). It is a deployment-consistency signal; it "
                        "does not prove an exploitable condition."
                    ),
                    remediation=(
                        "Rebuild and redeploy so every referenced chunk comes "
                        "from the same build, and purge cached HTML."
                    ),
                    evidence=(
                        f"Referenced: {target.url}\n"
                        f"First response: HTTP {target.status}\n"
                        f"Second response: HTTP {confirmed_status}\n"
                        f"Control asset still served: {served[0].url} "
                        f"(HTTP {served[0].status})"
                    ),
                    confidence=CONFIDENCE_FIRM,
                    verified=True,
                    verification=(
                        f"HTTP {confirmed_status} reproduced on a second "
                        f"request; control {served[0].url} still HTTP "
                        f"{served[0].status}"
                    ),
                    poc=[
                        f"curl -sS -o /dev/null -w '%{{http_code}}\\n' "
                        f"{target.url}",
                        f"curl -sS -o /dev/null -w '%{{http_code}}\\n' "
                        f"{served[0].url}",
                        "# Read-only: only the declared asset URLs are fetched.",
                    ],
                )
                finding.reproductions = 2
                finding.stable = True
                findings.append((finding, confirmation))

        if library_sources:
            lines: list[str] = []
            for name in sorted(library_sources):
                for version in sorted(library_sources[name]):
                    urls = library_sources[name][version]
                    lines.append(f"{name} {version}")
                    lines.extend(f"  - {url}" for url in urls)
            truncated = [asset for asset in report.assets if asset.truncated]
            if truncated:
                lines.extend([
                    "",
                    "Truncated reads (version extraction covered only the "
                    "captured prefix):",
                ])
                for asset in truncated[:6]:
                    declared = asset.content_length
                    lines.append(
                        f"  - {asset.url}: captured {asset.size} of "
                        f"{declared if declared is not None else 'unknown'} "
                        "bytes")
            poc: list[str] = []
            for asset in truncated[:2]:
                poc.extend([
                    f"curl -sSI {shlex.quote(asset.url)} "
                    "| grep -i '^content-length:'",
                    f"curl -sS {shlex.quote(asset.url)} | wc -c",
                ])
            if poc:
                poc.append(
                    "# Read-only: when Content-Length exceeds the captured "
                    "byte count the scanner read only a prefix.")
            finding = Finding(
                title="Client-side library versions observed in served bundles",
                severity="info",
                category="client-version",
                host=host,
                url=base,
                description=(
                    "Version strings were extracted from the JavaScript and "
                    "page metadata the target serves to any visitor. These "
                    "are observations, not vulnerability confirmations: a "
                    "version string can be stale, patched by the distributor, "
                    "or belong to an unrelated widget. Compare them with "
                    "vendor advisories and verify the exact build before "
                    "reporting."
                    + (" Some bundles exceeded the 1 MiB read cap, so versions "
                       "beyond the captured prefix were not examined."
                       if truncated else "")
                ),
                remediation=(
                    "Track these versions against vendor advisories and "
                    "rebuild bundles when a supported release supersedes them."
                ),
                evidence="\n".join(lines),
                confidence=CONFIDENCE_CONFIRMED,
                verified=True,
                verification=(
                    "version strings matched in served client-side content"
                    + (" (some sources read partially)" if truncated else "")),
                poc=poc,
            )
            finding.reproductions = 1
            finding.stable = None
            findings.append((finding, probe.result))

        report.library_sources = library_sources
        reports.append(report)

    meta = {
        "enabled": True,
        "hosts": [report.to_dict() for report in reports],
        "hosts_checked": len(reports),
        "assets_fetched": sum(len(report.assets) for report in reports),
        "manifests": sum(len(report.manifests) for report in reports),
        "drift": sum(len(report.drift) for report in reports),
        "missing_chunks": sum(len(report.missing) for report in reports),
        "truncated_assets": sum(len(report.truncated) for report in reports),
        "libraries": _library_summary(reports),
        "requests": requests,
        "warnings": list(dict.fromkeys(warnings)),
        "note": (
            "Drift means the served HTML and the served build artifacts "
            "disagree; it can indicate a stale deployment but is not proof of "
            "a vulnerability. Version strings are observations only."
        ),
    }
    return findings, reports, meta


def _build_id_drift(report: HostBundleReport) -> dict | None:
    ids = list(dict.fromkeys(report.build_ids))
    if len(ids) < 2:
        return None
    return {"type": "build-id-mismatch", "ids": ids[:6]}


def _library_summary(reports: list[HostBundleReport]) -> dict[str, list[str]]:
    summary: dict[str, set[str]] = {}
    for report in reports:
        for name, versions in report.library_sources.items():
            summary.setdefault(name, set()).update(versions)
    return {name: sorted(versions) for name, versions in sorted(summary.items())}


def version_hints(reports: list[HostBundleReport]) -> dict[str, dict]:
    """Return versions shaped like cve.extract_versions output for NVD lookup."""
    hints: dict[str, dict] = {}
    for report in reports:
        for name, versions in report.library_sources.items():
            component = NVD_LIBRARY_MAP.get(name)
            if not component:
                continue
            for version, urls in versions.items():
                current = hints.get(component)
                if current and current["version"] != version:
                    # Prefer the version observed on the most URLs.
                    if len(urls) <= current.get("count", 1):
                        continue
                hints[component] = {
                    "version": version,
                    "count": len(urls),
                    "hosts": [report.host],
                    "url": urls[0] if urls else report.url,
                    "evidence": f"{name} {version} observed in served content",
                }
    return hints
