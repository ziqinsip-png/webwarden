"""Read-only web shell and backdoor exposure detection.

The module requests a fixed list of common web shell paths and looks for the
signatures that such files expose (brand names, command-execution patterns in
PHP/JSP/ASPX). It never sends a command parameter, never authenticates, and
never tries to interact with a shell it finds. A hit must survive a second
request and must not be the host's catch-all page.
"""

from __future__ import annotations

import hashlib
import re

from .httpclient import HttpResult
from .models import CONFIDENCE_CONFIRMED, CONFIDENCE_FIRM, Finding
from .poc import evidence_slug, full_capture
from .util import in_scope

READ_LIMIT = 131072
MAX_TEXT = 400000

SHELL_PATHS = (
    "/shell.php",
    "/cmd.php",
    "/c99.php",
    "/r57.php",
    "/b374k.php",
    "/wso.php",
    "/wsoshell.php",
    "/indoxploit.php",
    "/alfa.php",
    "/backdoor.php",
    "/uploads/shell.php",
    "/upload/shell.php",
    "/files/shell.php",
    "/wp-content/uploads/shell.php",
    "/images/shell.php",
    "/shell.phtml",
    "/cmd.phtml",
    "/shell.jsp",
    "/cmd.jsp",
    "/shell.aspx",
    "/cmd.aspx",
)

# Every pattern in a group must match. ``brand`` marks a named shell family,
# which is far less likely to appear by accident than a source-code snippet.
SIGNATURES = (
    ("FilesMan shell", True, (
        re.compile(r"FilesMan", re.IGNORECASE),
    )),
    ("WSO web shell", True, (
        re.compile(r"WSO\s*\d\.\d|Web Shell by oRb|wso_version",
                   re.IGNORECASE),
    )),
    ("b374k shell", True, (
        re.compile(r"b374k", re.IGNORECASE),
    )),
    ("c99 shell", True, (
        re.compile(r"c99shell|c99madShell", re.IGNORECASE),
    )),
    ("r57 shell", True, (
        re.compile(r"r57shell|r57\.php", re.IGNORECASE),
    )),
    ("IndoXploit shell", True, (
        re.compile(r"IndoXploit", re.IGNORECASE),
    )),
    ("Ani-Shell", True, (
        re.compile(r"Ani-Shell|AniShell", re.IGNORECASE),
    )),
    ("PHP command-execution source", False, (
        re.compile(
            r"(?:eval|assert|system|shell_exec|passthru|popen|exec)\s*\(\s*"
            r"\$_(?:POST|GET|REQUEST|COOKIE)\b", re.IGNORECASE),
    )),
    ("PHP superglobal command dispatch", False, (
        re.compile(
            r"\$_(?:POST|GET|REQUEST|COOKIE)\s*\[\s*['\"]"
            r"(?:cmd|command|exec|shell|cmd1|cmd2)['\"]", re.IGNORECASE),
    )),
    ("JSP command-execution source", False, (
        re.compile(r"getRuntime\s*\(\s*\)\s*\.\s*exec", re.IGNORECASE),
        re.compile(r"request\.getParameter", re.IGNORECASE),
    )),
    ("ASP.NET command-execution source", False, (
        re.compile(r"ProcessStartInfo|Process\.Start\s*\(",
                   re.IGNORECASE),
        re.compile(r"cmd\.exe|System\.Diagnostics|Request\[",
                   re.IGNORECASE),
    )),
)


def _match(text: str) -> list[tuple[str, bool]]:
    sample = text[:MAX_TEXT]
    found: list[tuple[str, bool]] = []
    for name, brand, patterns in SIGNATURES:
        if all(pattern.search(sample) for pattern in patterns):
            found.append((name, brand))
    return found


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:16]


def analyze(
    origins,
    fetch,
    scopes,
    is_catch_all=None,
    *,
    max_hosts: int = 4,
    max_paths: int = 21,
    max_requests: int = 80,
):
    """Return ``(finding, evidence_result)`` pairs for reachable web shells."""
    meta = {
        "enabled": True,
        "hosts": 0,
        "paths_tested": 0,
        "requests": 0,
        "findings": 0,
        "budget_exhausted": False,
        "warnings": [],
    }
    produced: list[tuple[Finding, HttpResult]] = []  # type: ignore[name-defined]
    seen_hosts: set[str] = set()
    budget = max(0, int(max_requests))
    used = 0

    def request(url: str):
        nonlocal used
        if used >= budget:
            return None
        used += 1
        return fetch(url)

    for host, origin in origins:
        if used >= budget:
            break
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        if scopes and not in_scope(host, scopes):
            continue
        if len(seen_hosts) > max_hosts:
            break
        meta["hosts"] += 1
        for path in SHELL_PATHS[:max_paths]:
            if used >= budget:
                break
            url = origin.rstrip("/") + path
            result = request(url)
            if result is None:
                break
            meta["paths_tested"] += 1
            if not result.ok or result.status not in (200, 206) \
                    or not result.body:
                continue
            matches = _match(result.text)
            if not matches:
                continue
            if is_catch_all is not None and is_catch_all(origin, path, result):
                continue
            again = request(url)
            if again is None:
                break
            if not again.ok or not again.body:
                continue
            second = {name for name, _brand in _match(again.text)}
            confirmed = [
                (name, brand) for name, brand in matches if name in second
            ]
            if not confirmed:
                continue
            brand = any(item[1] for item in confirmed)
            names = ", ".join(name for name, _ in confirmed)
            severity = "critical" if brand else "high"
            confidence = CONFIDENCE_CONFIRMED if brand else CONFIDENCE_FIRM
            finding = Finding(
                title=f"Web shell or backdoor reachable at {path}",
                severity=severity,
                category="backdoor",
                host=host,
                url=url,
                description=(
                    f"The path {path} responds and its body matches known "
                    f"web-shell indicators ({names}). A web shell gives "
                    "whoever finds it command execution or file management on "
                    "the server. This check only retrieved the file; no "
                    "command parameter was sent and nothing was interacted "
                    "with."
                ),
                remediation=(
                    "Remove the file, preserve a copy for incident response, "
                    "rotate credentials reachable from the host, and review "
                    "access logs for prior use of this path."
                ),
                evidence=(
                    f"Path: {path}\n"
                    f"HTTP {result.status}, {len(result.body)} bytes, "
                    f"sha256:{_sha(result.body)}\n"
                    f"Signatures: {names}\n"
                    "Indicators were present on two independent requests; the "
                    "host catch-all page was excluded. No shell command was "
                    "sent and no parameter was supplied."
                ),
                confidence=confidence,
                verified=True,
                verification=(
                    f"web-shell indicators ({names}) matched on two "
                    "independent GET requests; no interaction attempted"
                ),
                poc=(
                    ["# retrieval only; this does not send a shell command"]
                    + full_capture(url, evidence_slug(url, "backdoor"))
                ),
                reproductions=2,
                stable=True,
            )
            produced.append((finding, again))
            meta["findings"] += 1

    meta["requests"] = used
    meta["budget_exhausted"] = used >= budget
    if meta["budget_exhausted"]:
        meta["warnings"].append(
            f"request budget reached after {used} probes; remaining paths "
            "were not tested")
    return produced, meta
