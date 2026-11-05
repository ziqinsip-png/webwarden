"""Evidence-linked exploit chains assembled from observed findings.

A chain is only built from findings that already exist. Each link points at a
specific finding and carries its reproduction status, so a chain can never
introduce a condition that was not observed. Statuses are:

* ``observed`` - every link reproduced on independent requests and none is a
  decoy;
* ``partial``  - at least one link is a single observation or needs manual
  confirmation, or the chain needs a step that was deliberately not performed
  (it is then labelled a hypothesis);
* ``blocked``  - a link carries a decoy/canary marker or the chain crosses the
  read-only boundary (for example it would require replaying a token).

No chain is executed. Nothing here captures a session, replays a credential,
claims a takeover resource, or performs a write.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from .models import SEVERITY_ORDER, Finding

STATUS_OBSERVED = "observed"
STATUS_PARTIAL = "partial"
STATUS_BLOCKED = "blocked"
STATUS_ORDER = {STATUS_OBSERVED: 0, STATUS_PARTIAL: 1, STATUS_BLOCKED: 2}

BOUNDARY_NOTE = (
    "Read-only boundary: the chain is assembled from independent GET "
    "observations. No session was captured, no credential was replayed, and "
    "no exploitation step was performed."
)


@dataclass
class ChainLink:
    title: str
    host: str
    url: str
    role: str
    status: str
    evidence: str
    severity: str = "info"
    verified: bool = False
    reproductions: int = 0
    stable: bool | None = None
    decoy: bool = False

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "host": self.host,
            "url": self.url,
            "role": self.role,
            "status": self.status,
            "evidence": self.evidence,
            "severity": self.severity,
            "verified": self.verified,
            "reproductions": self.reproductions,
            "stable": self.stable,
            "decoy": self.decoy,
        }


@dataclass
class Chain:
    id: str
    title: str
    severity: str
    status: str
    summary: str
    impact: str
    links: list[ChainLink] = field(default_factory=list)
    proof: list[str] = field(default_factory=list)
    limitations: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "summary": self.summary,
            "impact": self.impact,
            "links": [link.to_dict() for link in self.links],
            "proof": list(self.proof),
            "limitations": self.limitations,
        }


def _link_status(finding: Finding) -> str:
    if finding.decoy_suspected:
        return STATUS_BLOCKED
    if finding.verified and finding.reproductions >= 2 \
            and finding.stable is not False:
        return STATUS_OBSERVED
    return STATUS_PARTIAL


def _evidence(finding: Finding) -> str:
    if finding.verification:
        return finding.verification.split(" | ")[0][:400]
    if finding.evidence:
        return finding.evidence.splitlines()[0][:400]
    return f"observed with confidence '{finding.confidence}'"


def _link(finding: Finding, role: str) -> ChainLink:
    return ChainLink(
        title=finding.title,
        host=finding.host,
        url=finding.url,
        role=role,
        status=_link_status(finding),
        evidence=_evidence(finding),
        severity=finding.severity,
        verified=finding.verified,
        reproductions=finding.reproductions,
        stable=finding.stable,
        decoy=finding.decoy_suspected,
    )


def _cap(severity: str, ceiling: str) -> str:
    """Return the less severe of the two (severity may not exceed ceiling)."""
    if SEVERITY_ORDER.get(severity, 9) >= SEVERITY_ORDER.get(ceiling, 9):
        return severity
    return ceiling


def _chain(
    chain_id: str,
    title: str,
    summary: str,
    impact: str,
    links: list[ChainLink],
    proof: list[str],
    limitations: str,
    *,
    hypothesis: bool = False,
) -> Chain:
    statuses = {link.status for link in links}
    if STATUS_BLOCKED in statuses:
        status = STATUS_BLOCKED
    elif statuses == {STATUS_OBSERVED}:
        status = STATUS_OBSERVED
    else:
        status = STATUS_PARTIAL
    if hypothesis and status == STATUS_OBSERVED:
        # The links were observed but the step between them was not, so the
        # chain itself is an inference and must not be reported as observed.
        status = STATUS_PARTIAL
    severity = min(
        (link.severity for link in links),
        key=lambda item: SEVERITY_ORDER.get(item, 9),
        default="info",
    )
    if status == STATUS_BLOCKED:
        severity = "info"
    elif status == STATUS_PARTIAL:
        severity = _cap(severity, "medium")
    return Chain(
        id=chain_id,
        title=title,
        severity=severity,
        status=status,
        summary=summary,
        impact=impact,
        links=links,
        proof=proof,
        limitations=limitations,
    )


def _with_severity(link: ChainLink, finding: Finding) -> ChainLink:
    link.severity = finding.severity
    return link


def _hosts(findings: list[Finding]) -> list[str]:
    return sorted({finding.host.lower() for finding in findings if finding.host})


def _on_host(findings: list[Finding], host: str, predicate) -> list[Finding]:
    return [
        finding for finding in findings
        if finding.host.lower() == host and predicate(finding)
    ]


def _first(findings: list[Finding], predicate):
    for finding in findings:
        if predicate(finding):
            return finding
    return None


def _read_only(url: str) -> str:
    return (
        f"curl -sS -D - -o /dev/null {shlex.quote(url)}")



def _session_plaintext(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        token = _first(
            _on_host(findings, host,
                     lambda f: f.category == "tokens"
                     and f.severity in ("high", "medium")),
            lambda f: True)
        if not token:
            continue
        cookie = _first(
            _on_host(findings, host,
                     lambda f: f.category == "cookies"
                     and "missing security attributes" in f.title.lower()),
            lambda f: True)
        links = [_with_severity(_link(token, "exposure"), token)]
        if cookie:
            links.insert(0, _with_severity(_link(cookie, "precondition"), cookie))
        chains.append(_chain(
            chain_id=f"session-plaintext-{host}",
            title="Session hijacking via cleartext session token",
            summary=(
                "A session-classified cookie is issued over plaintext HTTP"
                + (", and the same host omits cookie security attributes"
                   if cookie else "")
                + ". The two observations are linked; no interception was "
                  "performed."
            ),
            impact=(
                "An on-path observer could read the session identifier while "
                "it is valid and could reuse it against the application. This "
                "chain shows the conditions, not a completed hijack."
            ),
            links=links,
            proof=[
                _read_only(token.url),
                "# Inspect the Set-Cookie attributes and the scheme; do not "
                "send the cookie anywhere.",
                "# Do NOT replay the cookie to access authenticated pages.",
            ],
            limitations=(
                BOUNDARY_NOTE + " A real hijack would require an on-path "
                "position and use of a live credential, which this tool does "
                "not attempt."
            ),
        ))
    return chains


def _cors_cookie(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        cors = _first(
            _on_host(findings, host,
                     lambda f: f.category == "cors" and f.verified),
            lambda f: True)
        cookie = _first(
            _on_host(findings, host, lambda f: f.category == "cookies"),
            lambda f: True)
        if not cors or not cookie:
            continue
        links = [
            _with_severity(_link(cors, "precondition"), cors),
            _with_severity(_link(cookie, "exposure"), cookie),
        ]
        chains.append(_chain(
            chain_id=f"cors-credential-{host}",
            title="Cross-origin credentialed read against a weak cookie policy",
            summary=(
                "The host answers cross-origin requests with credentials and "
                "also sets a sensitive cookie with weak attributes. Together "
                "they raise cross-site data-theft risk."
            ),
            impact=(
                "A malicious origin could read authenticated responses if the "
                "browser attaches the cookie and the application echoes data "
                "without an additional check. The response content and any "
                "server-side session binding still need manual verification."
            ),
            links=links,
            proof=[
                _read_only(cors.url),
                "# Repeat with an Origin header you control and inspect "
                "Access-Control-Allow-Credentials.",
                "# Do not attach a real session cookie from an untrusted origin.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Reproducing the theft would require a "
                "browser-side attacker origin and a live session; that is out "
                "of scope here."
            ),
        ))
    return chains


def _redirect_credentials(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        redirect = _first(
            _on_host(findings, host, lambda f: f.category == "redirect"),
            lambda f: True)
        credential = _first(
            _on_host(findings, host,
                     lambda f: f.category in ("url-tokens", "secrets")),
            lambda f: True)
        if not redirect or not credential:
            continue
        links = [
            _with_severity(_link(redirect, "precondition"), redirect),
            _with_severity(_link(credential, "exposure"), credential),
        ]
        chains.append(_chain(
            chain_id=f"redirect-credential-{host}",
            title="Open redirect next to a credential-bearing URL",
            summary=(
                "A redirect parameter accepts an external destination and the "
                "site also carries credential-like values in URLs. Combined, "
                "they widen phishing and Referer leakage."
            ),
            impact=(
                "An attacker could bounce users through a trusted host and "
                "harvest a credential from the Referer or a forged login flow. "
                "The credential value was never replayed, so liveness is "
                "unconfirmed."
            ),
            links=links,
            proof=[
                _read_only(redirect.url),
                "# The redirect URL is shown with its credential parameter "
                "redacted; do not replay the live token.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Confirming credential liveness would require "
                "a request with the token, which is out of scope."
            ),
        ))
    return chains


def _bypass_admin(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        bypass = _first(
            _on_host(findings, host,
                     lambda f: f.category == "access-control-bypass"),
            lambda f: True)
        admin = _first(
            _on_host(findings, host,
                     lambda f: any(marker in f.title.lower() for marker in (
                         "admin interface", "phpmyadmin", "tomcat manager",
                         "actuator", "swagger"))),
            lambda f: True)
        if not bypass or not admin:
            continue
        links = [
            _with_severity(_link(bypass, "precondition"), bypass),
            _with_severity(_link(admin, "exposure"), admin),
        ]
        chains.append(_chain(
            chain_id=f"bypass-admin-{host}",
            title="Administrative surface reached through an access-control bypass",
            summary=(
                "The original request is rejected, but a read-only variant "
                "returns content from the protected path. The admin surface "
                "also responds publicly."
            ),
            impact=(
                "If the bypassed content is the real administrative area, an "
                "unauthenticated client can reach functionality that should "
                "require authorization. Credentials were not attempted."
            ),
            links=links,
            proof=[
                _read_only(bypass.url),
                "# Show the control response and the bypassed response side by "
                "side; do not submit credentials to the admin interface.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Whether the bypassed content is actionable "
                "administration still needs manual confirmation."
            ),
        ))
    return chains


def _listing_exposure(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        listing = _first(
            _on_host(findings, host,
                     lambda f: "directory listing" in f.title.lower()),
            lambda f: True)
        secret = _first(
            _on_host(findings, host,
                     lambda f: f.category == "secrets"),
            lambda f: True)
        if not listing or not secret:
            continue
        links = [
            _with_severity(_link(listing, "precondition"), listing),
            _with_severity(_link(secret, "exposure"), secret),
        ]
        chains.append(_chain(
            chain_id=f"listing-secret-{host}",
            title="Directory listing exposing a client-side credential",
            summary=(
                "The server enumerates directory contents and the same host "
                "ships a credential-shaped value in client content."
            ),
            impact=(
                "Discovery is easier because file names are enumerable; the "
                "credential still needs its real privileges confirmed before "
                "it can be called impact."
            ),
            links=links,
            proof=[
                _read_only(listing.url),
                "# The credential value is redacted; do not authenticate with it.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Credential liveness and privileges were not "
                "tested."
            ),
        ))
    return chains


def _sourcemap_secret(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        source_map = _first(
            _on_host(findings, host,
                     lambda f: "source map" in f.title.lower()),
            lambda f: True)
        secret = _first(
            _on_host(findings, host, lambda f: f.category == "secrets"),
            lambda f: True)
        if not source_map or not secret:
            continue
        links = [
            _with_severity(_link(source_map, "precondition"), source_map),
            _with_severity(_link(secret, "exposure"), secret),
        ]
        chains.append(_chain(
            chain_id=f"sourcemap-secret-{host}",
            title="Source disclosure plus an exposed client-side credential",
            summary=(
                "A source map reveals original source paths while served "
                "content contains a credential-shaped value."
            ),
            impact=(
                "Together they help an attacker locate API usage and build a "
                "targeted request. The credential itself remains unverified."
            ),
            links=links,
            proof=[
                _read_only(source_map.url),
                "# Do not use the exposed value to call the API.",
            ],
            limitations=(
                BOUNDARY_NOTE + " No secret was validated or replayed."
            ),
        ))
    return chains


def _stale_bundle(findings: list[Finding], recon: dict) -> list[Chain]:
    chains: list[Chain] = []
    bundles_meta = (recon or {}).get("bundles") or {}
    hosts = bundles_meta.get("hosts") or []
    drifts = [host for host in hosts
              if host.get("drift") or host.get("missing")]
    if not drifts:
        return chains
    version = _first(findings, lambda f: f.category == "client-version")
    cve = _first(findings, lambda f: f.category == "cve-candidate")
    for host_meta in drifts:
        host = str(host_meta.get("host") or "")
        drift_findings = _on_host(
            findings, host,
            lambda f: f.category == "bundle-drift"
            or "build artifact drift" in f.title.lower()
            or "build identifiers disagree" in f.title.lower())
        if not drift_findings:
            continue
        links = [_with_severity(_link(item, "precondition"),
                                item) for item in drift_findings[:2]]
        if version is not None and version.host.lower() == host:
            links.append(_with_severity(_link(version, "exposure"), version))
        if cve is not None and cve.host.lower() == host:
            links.append(_with_severity(_link(cve, "impact"), cve))
        chains.append(_chain(
            chain_id=f"stale-bundle-{host}",
            title="Stale build artifacts may keep a patched flaw reachable",
            summary=(
                "The page and the deployed build artifacts disagree, and "
                "version strings were extracted from the served bundles. A "
                "patched server can still serve an older bundle, so the "
                "visible code may not match the server build."
            ),
            impact=(
                "If the served bundle still contains a flaw that the server "
                "build fixed, a client-side attack may still succeed. Drift "
                "alone does not prove that; the specific behavior must be "
                "verified in the served artifact."
            ),
            links=links,
            proof=[
                "# The drift evidence lists the page hashes and manifest "
                "hashes; compare them manually.",
                "# Do not execute or load the bundle as an exploit.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Version strings and build hashes are "
                "observations; NVD matches are candidates, not confirmations."
            ),
        ))
    return chains


def _takeover_cookie(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        takeover = _first(
            _on_host(findings, host, lambda f: f.category == "takeover"),
            lambda f: True)
        cookie = _first(
            _on_host(findings, host,
                     lambda f: "parent domain" in f.title.lower()),
            lambda f: True)
        if not takeover or not cookie:
            continue
        links = [
            _with_severity(_link(takeover, "precondition"), takeover),
            _with_severity(_link(cookie, "exposure"), cookie),
        ]
        chains.append(_chain(
            chain_id=f"takeover-cookie-{host}",
            title="Dangling subdomain next to a parent-domain cookie",
            summary=(
                "A subdomain points at an unclaimed provider resource and a "
                "sensitive cookie is scoped to the parent domain."
            ),
            impact=(
                "If the dangling resource were claimable, a sibling host could "
                "collect the shared cookie. Claimability was not tested and no "
                "resource was claimed."
            ),
            links=links,
            proof=[
                f"dig +short CNAME {host}",
                "# Do not attempt to claim the provider resource.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Takeover claimability remains manual."
            ),
        ))
    return chains


def _idor(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    idor = [finding for finding in findings
            if finding.category == "access-control"]
    for finding in idor[:2]:
        link = _with_severity(_link(finding, "exposure"), finding)
        chains.append(_chain(
            chain_id=f"idor-{finding.host}-{len(chains) + 1}",
            title="Object-level authorization gap (possible IDOR/BOLA)",
            summary=(
                "An object that one principal can read was also returned to a "
                "different principal or anonymously."
            ),
            impact=(
                "Could allow cross-account data access if object ownership is "
                "not checked. Entitlement was not confirmed, so this stays a "
                "manual review item."
            ),
            links=[link],
            proof=[
                _read_only(finding.url),
                "# Compare responses between two accounts you are authorized "
                "to test.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Object ownership and entitlement need manual "
                "confirmation."
            ),
        ))
    return chains


def _robots_secret(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        reachable = _first(
            _on_host(findings, host,
                     lambda f: "robots.txt disallow paths" in f.title.lower()),
            lambda f: True)
        secret = _first(
            _on_host(findings, host,
                     lambda f: "robots.txt path" in f.title.lower()),
            lambda f: True)
        if not reachable or not secret:
            continue
        links = [
            _with_severity(_link(reachable, "precondition"), reachable),
            _with_severity(_link(secret, "exposure"), secret),
        ]
        chains.append(_chain(
            chain_id=f"robots-secret-{host}",
            title="Hidden path disclosed by robots.txt carries a credential",
            summary=(
                "robots.txt lists Disallow paths that answer without an "
                "authentication challenge, and one of them exposes a "
                "credential-shaped value."
            ),
            impact=(
                "Attackers read robots.txt first; the listed path makes the "
                "exposure easier to find. Authorization is still the real "
                "control that is missing."
            ),
            links=links,
            proof=[
                _read_only(reachable.url),
                "# Do not authenticate with any value found on the path.",
            ],
            limitations=(
                BOUNDARY_NOTE + " robots.txt is advisory, not access control."
            ),
        ))
    return chains


DATA_STORE_MARKERS = (
    "database dump",
    "exposed .env",
    "actuator environment",
    "git config",
    "web.config",
    ".htpasswd",
    "sftp client configuration",
    "wordpress config backup",
    "php config backup",
    "config backup",
)

BUILD_CONTEXT_MARKERS = (
    "source map",
    "exposed .git",
    "docker compose",
    "dockerfile",
    "composer lockfile",
    "phpinfo",
    "debug log",
)

READABLE_FILE_MARKERS = (
    "exposed .env",
    "config backup",
    "private ssh key",
    "sftp client configuration",
    "npm authentication token",
    "web.config",
    "database dump",
    "git config",
    "aws credentials",
)

LOG_MARKERS = ("laravel log", "debug log")


def _titled(findings: list[Finding], host: str, markers: tuple[str, ...]):
    return _first(
        _on_host(findings, host,
                 lambda f: any(marker in f.title.lower() for marker in markers)),
        lambda f: True)


def _in_class(findings: list[Finding], host: str, category: str):
    return _first(
        _on_host(findings, host, lambda f: f.category == category),
        lambda f: True)


def _webshell_exec(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    shells = [finding for finding in findings
              if finding.category == "backdoor" and not finding.decoy_suspected]
    for finding in shells[:3]:
        chains.append(_chain(
            chain_id=f"webshell-exec-{finding.host}-{len(chains) + 1}",
            title="Reachable web shell hands out command execution",
            summary=(
                "A known web-shell path answers with a script whose body "
                "dispatches request parameters into a command-execution "
                "function. The file is reachable without authentication."
            ),
            impact=(
                "Anyone who finds the file can run commands as the web server "
                "user: read configuration, reach the database, and move deeper "
                "into the network. No command parameter was sent; the served "
                "shell body is the evidence."
            ),
            links=[_with_severity(_link(finding, "execution"), finding)],
            proof=[
                _read_only(finding.url),
                "# Retrieval only. No cmd parameter or shell command was "
                "submitted.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Command execution was not attempted, so the "
                "server-side privileges of the shell remain unconfirmed."
            ),
        ))
    return chains


def _sqli_database(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        sqli = _in_class(findings, host, "sqli")
        if sqli is None:
            continue
        links = [_with_severity(_link(sqli, "injection"), sqli)]
        store = _titled(findings, host, DATA_STORE_MARKERS)
        summary = (
            "A request parameter changes the SQL the server executes, shown "
            "by behaviour that only appears when the payload is sent and not "
            "on the untouched baseline."
        )
        impact = (
            "Query control usually means reading rows the response never "
            "meant to show, or defeating a login check that compares user "
            "input. Only differential behaviour was measured; no rows were "
            "retrieved."
        )
        if store is not None:
            links.append(_with_severity(_link(store, "exposure"), store))
            summary += (
                " The same host also serves database or configuration "
                "material, so the data behind the query may already be "
                "downloadable."
            )
            impact += (
                " With that dump or configuration reachable, the database "
                "credentials can be read directly, which turns a single "
                "injectable parameter into wholesale data exposure."
            )
        chains.append(_chain(
            chain_id=f"sqli-database-{host}",
            title="SQL injection reachable toward the application database",
            summary=summary,
            impact=impact,
            links=links,
            proof=[
                _read_only(sqli.url),
                "# The exact payload is in the saved evidence; replay it only "
                "inside your authorized scope.",
                "# No UNION, stacked, time-based, or extraction payload was "
                "sent.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Dumping the schema, extracting rows, or "
                "escalating privileges inside the database was not attempted."
            ),
        ))
    return chains


def _ssti_rce(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        ssti = _in_class(findings, host, "ssti")
        if ssti is None:
            continue
        links = [_with_severity(_link(ssti, "injection"), ssti)]
        context = _titled(findings, host, BUILD_CONTEXT_MARKERS)
        summary = (
            "The server evaluates template expressions built from request "
            "input; a second arithmetic expression reproduced the same "
            "evaluation."
        )
        impact = (
            "Template evaluation sits inside the application runtime, so the "
            "usual escalation path runs from the engine's object graph "
            "(Jinja2 subclasses, FreeMarker Execute, Twig filters) to running "
            "commands as the web user. Only arithmetic was evaluated here."
        )
        if context is not None:
            links.append(_with_severity(_link(context, "exposure"), context))
            summary += (
                " The host also exposes build or debug material, which tells "
                "an attacker the exact engine version to target."
            )
            impact += (
                " Knowing the engine version makes a working runtime gadget "
                "much easier to select."
            )
        chains.append(_chain(
            chain_id=f"ssti-rce-{host}",
            title="Template injection on a path that can reach the runtime",
            summary=summary,
            impact=impact,
            links=links,
            proof=[
                _read_only(ssti.url),
                "# The arithmetic payload is in the saved evidence; no command "
                "or file-access expression was sent.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Command execution through the template engine "
                "was not attempted and remains engine-dependent."
            ),
        ))
    return chains


def _lfi_files(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        lfi = _in_class(findings, host, "lfi")
        if lfi is None:
            continue
        links = [_with_severity(_link(lfi, "injection"), lfi)]
        target = _titled(findings, host, READABLE_FILE_MARKERS)
        summary = (
            "A file-shaped parameter resolves paths outside the web root: the "
            "same system-file signature appeared at two traversal depths and "
            "not on the baseline."
        )
        impact = (
            "An attacker can read files the web server can open, which "
            "typically includes configuration holding database and API "
            "credentials."
        )
        if target is not None:
            links.append(_with_severity(_link(target, "exposure"), target))
            summary += (
                " A configuration or credential file is separately reachable "
                "on the same host, showing exactly which values the traversal "
                "would surface."
            )
            impact += (
                " Because those files are served directly, the traversal adds "
                "reach into paths that are not published at all, and the "
                "combination points at the same secrets."
            )
        chains.append(_chain(
            chain_id=f"lfi-files-{host}",
            title="Path traversal reaching configuration and credential files",
            summary=summary,
            impact=impact,
            links=links,
            proof=[
                _read_only(lfi.url),
                "# The traversal payload is in the saved evidence; only system "
                "files were read.",
                "# No credential file was parsed or reused.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Reading application secrets or chaining into "
                "code execution was not attempted."
            ),
        ))
    return chains


def _xss_session(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        xss = _in_class(findings, host, "xss")
        if xss is None:
            continue
        cookie = _first(
            _on_host(findings, host,
                     lambda f: f.category == "cookies"
                     and "sensitive cookie" in f.title.lower()
                     and "missing security attributes" in f.title.lower()),
            lambda f: True)
        csp = _first(
            _on_host(findings, host,
                     lambda f: "content-security-policy present but weak"
                     in f.title.lower()),
            lambda f: True)
        links = [_with_severity(_link(xss, "injection"), xss)]
        support = ""
        if cookie is not None:
            links.append(_with_severity(_link(cookie, "precondition"), cookie))
            support = (
                " The session cookie lacks security attributes, so script on "
                "the page could read it directly."
            )
        elif csp is not None:
            links.append(_with_severity(_link(csp, "precondition"), csp))
            support = (
                " The page's Content-Security-Policy is weak, so injected "
                "markup has a realistic path to executing."
            )
        chains.append(_chain(
            chain_id=f"xss-session-{host}",
            title="Reflected markup next to a session that script can reach",
            summary=(
                "A request parameter is reflected into HTML unescaped, "
                "confirmed against an untouched baseline." + support
            ),
            impact=(
                "A crafted link could run script in a victim's browser on the "
                "site origin, read page data, and act with the victim's "
                "session. The reflection was reproduced; execution in a "
                "browser was not attempted."
            ),
            links=links,
            proof=[
                _read_only(xss.url),
                "# The marker string is in the saved evidence; no browser and "
                "no session cookie were used.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Delivering the payload to a real browser and "
                "harvesting a session was not attempted."
            ),
        ))
    return chains


def _git_source(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        git = _first(
            _on_host(findings, host,
                     lambda f: any(marker in f.title.lower() for marker in (
                         "exposed .git", "git config", "git reflog"))),
            lambda f: True)
        if git is None:
            continue
        links = [_with_severity(_link(git, "exposure"), git)]
        source = _titled(findings, host, BUILD_CONTEXT_MARKERS)
        if source is None:
            source = _first(
                _on_host(findings, host, lambda f: f.category == "secrets"),
                lambda f: True)
        if source is not None:
            links.append(_with_severity(_link(source, "impact"), source))
        summary = (
            "Version-control metadata is served from the web root, so the "
            "repository history can be reconstructed from public requests."
        )
        impact = (
            "Recovered history exposes source, commit messages, and often "
            "environment files with live credentials. Reconstruction was not "
            "performed; only the metadata files were fetched."
        )
        if source is not None:
            summary += (
                " Source or build material is also published on the same host."
            )
            impact += (
                " Together with that material, the disclosed history points "
                "straight at the endpoints and secrets to attack."
            )
        chains.append(_chain(
            chain_id=f"git-source-{host}",
            title="Repository metadata exposed next to published build material",
            summary=summary,
            impact=impact,
            links=links,
            proof=[
                _read_only(git.url),
                "# Only the metadata file was fetched. Rebuilding the "
                "repository is out of scope.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Cloning or reconstructing the repository from "
                "the exposed metadata was not attempted."
            ),
        ))
    return chains


def _log_poisoning(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        lfi = _in_class(findings, host, "lfi")
        log = _titled(findings, host, LOG_MARKERS)
        if lfi is None or log is None:
            continue
        links = [
            _with_severity(_link(lfi, "precondition"), lfi),
            _with_severity(_link(log, "precondition"), log),
        ]
        chains.append(_chain(
            chain_id=f"log-poisoning-{host}",
            title="Log poisoning path from file inclusion to code execution",
            summary=(
                "A traversable file parameter and a log file that records "
                "request data are both reachable. If the log is writable "
                "through a request line or header, the traversal could include "
                "attacker-controlled PHP code."
            ),
            impact=(
                "That combination would escalate file read into code "
                "execution. The step in between was not performed: no request "
                "was crafted to poison the log and the log was not included.",
            ),
            links=links,
            proof=[
                _read_only(lfi.url),
                _read_only(log.url),
                "# Both steps above are retrieval only; the poisoning request "
                "was deliberately not sent.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Turning the log into code requires writing "
                "attacker-controlled content, which this tool never does. The "
                "chain is a documented hypothesis, not an observed exploit."
            ),
            hypothesis=True,
        ))
    return chains


def _ssrf_internal(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        ssrf = _in_class(findings, host, "ssrf")
        if ssrf is None:
            continue
        links = [_with_severity(_link(ssrf, "precondition"), ssrf)]
        target = _first(
            _on_host(findings, host,
                     lambda f: any(marker in f.title.lower() for marker in (
                         "actuator", "aws credentials", "heap dump",
                         "sftp client configuration",
                         "npm authentication token"))),
            lambda f: True)
        summary = (
            "A parameter makes the server fetch a URL it is given; the "
            "resolver error from a .invalid hostname proved the request is "
            "issued server-side."
        )
        impact = (
            "If the allowlist is missing, the same parameter can reach "
            "internal services and cloud metadata. No internal address was "
            "requested, so reachability beyond the resolver check is "
            "unconfirmed."
        )
        if target is not None:
            links.append(_with_severity(_link(target, "impact"), target))
            summary += (
                " An internal admin or credential-bearing surface is exposed "
                "on the same host, which is what an SSRF pivot would look for."
            )
            impact += (
                " That exposure is exactly the kind of target a server-side "
                "fetch is used to reach."
            )
        chains.append(_chain(
            chain_id=f"ssrf-internal-{host}",
            title="Server-side fetch reachable toward internal services",
            summary=summary,
            impact=impact,
            links=links,
            proof=[
                _read_only(ssrf.url),
                "# The probe host is a random .invalid name; no internal or "
                "third-party URL was requested.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Confirming internal reach would require "
                "pointing the parameter at internal addresses, which this tool "
                "never does."
            ),
            hypothesis=True,
        ))
    return chains


DEBUG_CONSOLE_MARKERS = (
    "symfony profiler",
    "laravel telescope",
    "elmah error log",
    "asp.net trace log",
    "apache server-info",
)


def _debug_console(findings: list[Finding]) -> list[Chain]:
    chains: list[Chain] = []
    for host in _hosts(findings):
        console = _titled(findings, host, DEBUG_CONSOLE_MARKERS)
        if console is None:
            continue
        links = [_with_severity(_link(console, "exposure"), console)]
        leak = _first(
            _on_host(findings, host, lambda f: f.category in (
                "secrets", "tokens", "cookies")),
            lambda f: True)
        if leak is not None:
            links.append(_with_severity(_link(leak, "impact"), leak))
        summary = (
            "A framework debug console answers publicly. These consoles keep "
            "per-request records: headers, cookies, SQL, exceptions, and mail."
        )
        impact = (
            "An attacker can read captured requests and session material "
            "without authenticating. The console page itself was fetched; its "
            "stored records were not enumerated."
        )
        if leak is not None:
            summary += (
                " Session or credential material is also observable on this "
                "host, which is the same data these consoles persist."
            )
        chains.append(_chain(
            chain_id=f"debug-console-{host}",
            title="Debug console exposing request and session data",
            summary=summary,
            impact=impact,
            links=links,
            proof=[
                _read_only(console.url),
                "# Only the console landing page was retrieved; no stored "
                "request or session record was opened.",
            ],
            limitations=(
                BOUNDARY_NOTE + " Enumerating captured requests would expose "
                "other users' sessions, which this tool does not do."
            ),
            hypothesis=True,
        ))
    return chains


def _decoy_blocked(findings: list[Finding]) -> list[Chain]:
    flagged = [finding for finding in findings if finding.decoy_suspected]
    if not flagged:
        return []
    links = [_with_severity(_link(finding, "excluded"), finding)
             for finding in flagged[:6]]
    return [_chain(
        chain_id="decoy-artifacts",
        title="Decoy/canary artifacts excluded from impact",
        summary=(
            "One or more findings carry decoy, honeytoken, or test-credential "
            "markers. They are kept as evidence but are not counted as impact."
        ),
        impact=(
            "A planted decoy can make a hardened target look vulnerable. "
            "Treating it as a real flaw would inflate the report."
        ),
        links=links,
        proof=[
            "# Review the decoy reason recorded on each linked finding.",
            "# Do not report these as vulnerabilities without operator "
            "confirmation.",
        ],
        limitations=(
            "Markers are heuristics; a real issue could share wording with a "
            "decoy. Manual review decides."
        ),
    )]


def build_chains(findings: list[Finding], recon: dict | None = None) -> list[Chain]:
    recon = recon or {}
    chains: list[Chain] = []
    chains.extend(_session_plaintext(findings))
    chains.extend(_cors_cookie(findings))
    chains.extend(_redirect_credentials(findings))
    chains.extend(_bypass_admin(findings))
    chains.extend(_listing_exposure(findings))
    chains.extend(_sourcemap_secret(findings))
    chains.extend(_stale_bundle(findings, recon))
    chains.extend(_takeover_cookie(findings))
    chains.extend(_idor(findings))
    chains.extend(_robots_secret(findings))
    chains.extend(_webshell_exec(findings))
    chains.extend(_sqli_database(findings))
    chains.extend(_ssti_rce(findings))
    chains.extend(_lfi_files(findings))
    chains.extend(_xss_session(findings))
    chains.extend(_git_source(findings))
    chains.extend(_log_poisoning(findings))
    chains.extend(_ssrf_internal(findings))
    chains.extend(_debug_console(findings))
    chains.extend(_decoy_blocked(findings))
    chains.sort(key=lambda item: (
        STATUS_ORDER.get(item.status, 9),
        SEVERITY_ORDER.get(item.severity, 9),
        item.links[0].host if item.links else "",
        item.title,
    ))
    return chains


def apply_chain_ids(chains: list[Chain], findings: list[Finding]) -> None:
    index: dict[tuple[str, str, str], Finding] = {
        (finding.title, finding.host.lower(), finding.url): finding
        for finding in findings
    }
    for chain in chains:
        for link in chain.links:
            key = (link.title, link.host.lower(), link.url)
            finding = index.get(key)
            if finding is None:
                continue
            if chain.id not in finding.chain_ids:
                finding.chain_ids.append(chain.id)


def chains_meta(chains: list[Chain], enabled: bool = True) -> dict:
    counts = {STATUS_OBSERVED: 0, STATUS_PARTIAL: 0, STATUS_BLOCKED: 0}
    for chain in chains:
        counts[chain.status] = counts.get(chain.status, 0) + 1
    return {
        "enabled": enabled,
        "total": len(chains),
        "observed": counts[STATUS_OBSERVED],
        "partial": counts[STATUS_PARTIAL],
        "blocked": counts[STATUS_BLOCKED],
        "items": [chain.to_dict() for chain in chains],
        "note": (
            "Chains are assembled only from observed findings. 'observed' "
            "means every link reproduced on independent requests; 'partial' "
            "means at least one link needs manual confirmation; 'blocked' "
            "means a link carries a decoy marker or the chain needs a "
            "forbidden action. No chain was executed."
        ),
    }
