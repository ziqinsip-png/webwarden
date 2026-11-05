"""Read-only injection probes: SQL error/differential, SSTI, reflects, LFI,
SSRF, and CRLF/header injection.

Every probe is a single GET with a benign marker appended to one query
parameter. Nothing is extracted, written, uploaded, or authenticated. A
candidate is reported only when the signal is absent from the untouched
baseline and reproduces on an independent second request; the caller also
suppresses catch-all hosts. This module never claims a database name beyond
the error text it actually observed, and never performs blind extraction.

The SSRF probe points the server at a randomly named ``.invalid`` host, so a
fetch attempt can only fail at DNS resolution: no internal address, cloud
metadata endpoint, or third-party service is ever requested. The CRLF probe
injects a custom ``X-WW-*`` header name with a random token and reports only
when that exact header name comes back on the response, twice.
"""

from __future__ import annotations

import re
import secrets
import shlex
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .httpclient import HttpResult
from .models import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_FIRM,
    Finding,
)
from .util import in_scope

READ_LIMIT = 131072
MAX_VALUE = 120

INT_RE = re.compile(r"^\d{1,9}$")
TOKEN_VALUE_RE = re.compile(r"^[A-Za-z0-9_\-.]{40,}$")

SKIP_PARAMS = {
    "password", "passwd", "pwd", "token", "access_token", "refresh_token",
    "id_token", "jwt", "session", "sessionid", "sid", "auth", "authorization",
    "api_key", "apikey", "secret", "client_secret", "private_key", "csrf",
    "csrf_token", "xsrf", "xsrf_token", "nonce", "signature", "sig", "key",
}

FILE_PARAMS = {
    "file", "filename", "path", "page", "template", "doc", "document",
    "download", "include", "view", "folder", "dir", "directory", "lang",
    "locale", "load", "read", "src", "source",
}

SQL_ERROR_PATTERNS = (
    ("MySQL", re.compile(
        r"you have an error in your sql syntax|warning:\s*mysql_|"
        r"valid mysql result|mysqlclient|check that you have the right number "
        r"of arguments|unknown column|sqlstate\[42", re.IGNORECASE)),
    ("PostgreSQL", re.compile(
        r"pg_query\(\)|postgresql[\s\S]{0,40}error|unterminated quoted string|"
        r"syntax error at or near|psql:|invalid input syntax for",
        re.IGNORECASE)),
    ("Microsoft SQL Server", re.compile(
        r"microsoft ole db provider for sql server|unclosed quotation mark "
        r"after the character string|incorrect syntax near|microsoft sql "
        r"server|odbc sql server driver|system\.data\.sqlclient",
        re.IGNORECASE)),
    ("Oracle", re.compile(
        r"\bora-\d{5}\b|oracle[\s\S]{0,40}oci_|quoted string not properly "
        r"terminated|oracle\.manageddataaccess", re.IGNORECASE)),
    ("SQLite", re.compile(
        r"sqlite3?\.\w*error|sqlite error|unrecognized token:|"
        r"near \"[^\"]{1,40}\": syntax error", re.IGNORECASE)),
)

# template label -> builder(a, b)
SSTI_PROBES = (
    ("Jinja2/Twig", lambda a, b: "{{%d*%d}}" % (a, b)),
    ("JSP EL/FreeMarker", lambda a, b: "${%d*%d}" % (a, b)),
    ("ERB/EJS", lambda a, b: "<%%= %d*%d %%>" % (a, b)),
)

LFI_PROBES = (
    (
        "../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        ("root:x:0:0:",),
    ),
    (
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        ("for 16-bit app support", "[fonts]"),
    ),
)

URL_PARAMS = {
    "url", "uri", "link", "target", "dest", "destination", "redirect",
    "redirect_uri", "redirect_url", "return", "returnurl", "return_url",
    "callback", "callback_url", "webhook", "fetch", "proxy", "endpoint",
    "api", "remote", "rss", "feed", "site", "domain", "host", "goto",
    "out", "open", "src", "image", "imageurl", "image_url", "img",
    "avatar", "page_url", "source_url", "resource",
}

# Only name-resolution failures: the probe host is under .invalid, so any
# successful fetch attempt must fail exactly here.
FETCH_ERROR_PATTERNS = (
    "could not resolve host",
    "couldn't resolve host",
    "could not resolve the host",
    "getaddrinfo",
    "name or service not known",
    "no address associated with hostname",
    "temporary failure in name resolution",
    "eai_again",
    "nodename nor servname provided",
    "unknownhostexception",
    "php_network_getaddresses",
    "failed to resolve",
    "no such host",
    "unable to resolve",
)


class _Budget:
    def __init__(self, limit: int) -> None:
        self.limit = max(0, int(limit))
        self.used = 0

    @property
    def available(self) -> bool:
        return self.used < self.limit

    def fetch(self, fetch, url: str) -> HttpResult | None:
        if not self.available:
            return None
        self.used += 1
        return fetch(url)


def _testable(name: str, value: str) -> bool:
    if name.lower() in SKIP_PARAMS:
        return False
    if len(value) > MAX_VALUE:
        return False
    if TOKEN_VALUE_RE.match(value):
        return False
    return True


def _candidate_urls(urls, scopes, limit: int) -> list[str]:
    selected: list[str] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for raw in urls:
        if not raw or not raw.lower().startswith(("http://", "https://")):
            continue
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower()
        if not host or not parsed.query:
            continue
        if scopes and not in_scope(host, scopes):
            continue
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs or not any(_testable(name, value) for name, value in pairs):
            continue
        # A URL that carries a credential-like parameter is left completely
        # untouched so a token is never replayed as part of a probe.
        if any(name.lower() in SKIP_PARAMS for name, _ in pairs):
            continue
        if any(TOKEN_VALUE_RE.match(value) for _, value in pairs):
            continue
        names = tuple(sorted({name for name, _ in pairs}))
        key = (host, parsed.path, names)
        if key in seen:
            continue
        seen.add(key)
        selected.append(urlunsplit((
            parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")))
        if len(selected) >= limit:
            break
    return selected


def _mutate(parsed, pairs, index: int, value: str) -> str:
    updated = list(pairs)
    updated[index] = (pairs[index][0], value)
    return urlunsplit((
        parsed.scheme, parsed.netloc, parsed.path,
        urlencode(updated, doseq=True), "",
    ))


def _ratio(first: int, second: int) -> float:
    top = max(first, second)
    if top == 0:
        return 1.0
    return min(first, second) / top


def _close(first: int, second: int, tolerance: float = 0.04) -> bool:
    return _ratio(first, second) >= 1.0 - tolerance


def _dbms_error(text: str) -> tuple[str, str] | None:
    for name, pattern in SQL_ERROR_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        start = text.rfind("\n", 0, match.start()) + 1
        end = text.find("\n", match.end())
        if end == -1:
            end = len(text)
        line = " ".join(text[start:end].split())[:200]
        return name, line
    return None


def _is_html(result: HttpResult) -> bool:
    if "html" in result.content_type:
        return True
    head = result.text[:512].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def _pick_product(text: str, exclude: int | None = None):
    for _ in range(6):
        first = secrets.randbelow(5) + 5
        second = secrets.randbelow(5) + 5
        product = first * second
        if product == exclude or str(product) in text:
            continue
        return first, second, product
    return None


def _xss_context(text: str, index: int) -> str:
    before = text[:index]
    lowered = before.lower()
    if lowered.rfind("<script") > lowered.rfind("</script"):
        return "script context"
    tag_start = before.rfind("<")
    if tag_start != -1:
        fragment = before[tag_start:]
        if fragment.count('"') % 2 == 1:
            return "double-quoted attribute context"
        if fragment.count("'") % 2 == 1:
            return "single-quoted attribute context"
        if "=" in fragment:
            return "unquoted attribute context"
    return "HTML body context"


def _size_curl(label: str, url: str) -> str:
    return (
        "curl -sS --max-time 30 -o /dev/null "
        f"-w '{label} %{{http_code}} %{{size_download}}\\n' "
        + shlex.quote(url)
    )


def _check_sql_error(
    budget, fetch, parsed, pairs, index, baseline, meta, original
):
    name, value = pairs[index]
    for quote, label in (("'", "single quote"), ('"', "double quote")):
        injected = _mutate(parsed, pairs, index, value + quote)
        result = budget.fetch(fetch, injected)
        if result is None:
            return None
        if not result.ok or result.status is None or not result.body:
            continue
        if _dbms_error(baseline.text):
            return None
        match = _dbms_error(result.text)
        if not match:
            continue
        again = budget.fetch(fetch, injected)
        if again is None:
            return None
        if not again.ok or not again.body or not _dbms_error(again.text):
            continue
        dbms, line = match
        finding = Finding(
            title=f"SQL error response triggered by parameter '{name}'",
            severity="high",
            category="sqli",
            host=(parsed.hostname or "").lower(),
            url=injected,
            description=(
                f"Appending a {label} to parameter '{name}' made the server "
                f"return a {dbms} error that is absent from the untouched "
                "response. The value therefore reaches a SQL query without "
                "parameterization. No data was extracted and no other payload "
                "was sent."
            ),
            remediation=(
                "Use parameterized queries or prepared statements for every "
                "database call, validate input types, and return generic error "
                "pages so database details are not disclosed."
            ),
            evidence=(
                f"Parameter: {name}\n"
                f"Baseline: HTTP {baseline.status}, {len(baseline.body)} bytes "
                "(no database error)\n"
                f"Injected ({label}): HTTP {result.status}, "
                f"{len(result.body)} bytes\n"
                f"Observed {dbms} error: {line}\n"
                "Only a quote character was appended; the error reproduced on "
                "a second independent request."
            ),
            confidence=CONFIDENCE_CONFIRMED,
            verified=True,
            verification=(
                f"{dbms} error appeared only after injecting a {label} and "
                "reproduced on a second request"
            ),
            poc=[
                "# baseline; a database error should not appear",
                "curl -sS --max-time 30 " + shlex.quote(original)
                + " | grep -Ei 'sql|syntax|mysql|postgres|ora-|sqlite'"
                + " || echo 'baseline clean'",
                f"# appended {label}",
                "curl -sS --max-time 30 " + shlex.quote(injected)
                + " | grep -Ei 'sql|syntax|mysql|postgres|ora-|sqlite'",
            ],
            reproductions=2,
            stable=True,
        )
        meta["checks"]["sql_error"] += 1
        return finding, again
    return None


def _boolean_pair(baseline, true_res, false_res) -> bool:
    if not baseline.body:
        return False
    for result in (true_res, false_res):
        if not result.ok or result.status != baseline.status or not result.body:
            return False
    if baseline.content_type and true_res.content_type \
            and true_res.content_type != baseline.content_type:
        return False
    if true_res.content_type != false_res.content_type:
        return False
    true_len = len(true_res.body)
    false_len = len(false_res.body)
    if not _close(true_len, len(baseline.body), 0.04):
        return False
    return _ratio(true_len, false_len) <= 0.90 \
        and abs(true_len - false_len) >= 24


def _check_sql_boolean(
    budget, fetch, parsed, pairs, index, baseline, meta, original
):
    name, value = pairs[index]
    if not INT_RE.match(value):
        return None
    rounds = ((1, 1, 1, 2), (2, 2, 2, 3))
    observed: list[tuple[int, int]] = []
    false_result: HttpResult | None = None
    false_url = ""
    for left, right, wrong_left, wrong_right in rounds:
        true_url = _mutate(
            parsed, pairs, index, f"{value} AND {left}={right}")
        current_false_url = _mutate(
            parsed, pairs, index, f"{value} AND {wrong_left}={wrong_right}")
        true_res = budget.fetch(fetch, true_url)
        if true_res is None:
            return None
        false_res = budget.fetch(fetch, current_false_url)
        if false_res is None:
            return None
        if not _boolean_pair(baseline, true_res, false_res):
            return None
        observed.append((len(true_res.body), len(false_res.body)))
        false_result = false_res
        false_url = current_false_url
    if len(observed) != len(rounds) or false_result is None:
        return None
    pairs_text = "\n".join(
        f"AND {left}={right} -> {true_len} bytes; "
        f"AND {wrong_left}={wrong_right} -> {false_len} bytes"
        for (left, right, wrong_left, wrong_right), (true_len, false_len)
        in zip(rounds, observed)
    )
    finding = Finding(
        title=f"Boolean-based SQL injection candidate in parameter '{name}'",
        severity="medium",
        category="sqli",
        host=(parsed.hostname or "").lower(),
        url=false_url,
        description=(
            "Two independent true/false condition pairs changed the response "
            "length: the true condition matched the baseline while the false "
            "condition returned a different body. This is consistent with "
            "SQL injection, but the differential alone does not identify the "
            "database. No error page was triggered, no data was extracted, and "
            "nothing was written."
        ),
        remediation=(
            "Use parameterized queries or prepared statements and reject "
            "non-numeric input for numeric parameters."
        ),
        evidence=(
            f"Parameter: {name}\n"
            f"Baseline: HTTP {baseline.status}, {len(baseline.body)} bytes\n"
            f"{pairs_text}\n"
            "Both rounds reproduced; the true condition stayed close to the "
            "baseline and the false condition differed materially."
        ),
        confidence=CONFIDENCE_FIRM,
        verified=True,
        verification=(
            "two independent true/false condition pairs produced a stable "
            "length differential; no data was extracted"
        ),
        poc=[
            "# true condition should match the baseline size",
            _size_curl("true ", _mutate(
                parsed, pairs, index, f"{value} AND 1=1")),
            "# false condition should differ",
            _size_curl("false", _mutate(
                parsed, pairs, index, f"{value} AND 1=2")),
            "curl -sS --max-time 30 " + shlex.quote(original)
            + " | wc -c",
        ],
        reproductions=2,
        stable=True,
    )
    meta["checks"]["sql_boolean"] += 1
    return finding, false_result


def _check_ssti(
    budget, fetch, parsed, pairs, index, baseline, meta, original
):
    name, value = pairs[index]
    first = _pick_product(baseline.text)
    if first is None:
        return None
    a, b, product = first
    for engine, build in SSTI_PROBES:
        payload = build(a, b)
        injected = _mutate(parsed, pairs, index, value + payload)
        result = budget.fetch(fetch, injected)
        if result is None:
            return None
        if not result.ok or result.status is None or not result.body:
            continue
        if str(product) not in result.text:
            continue
        second = _pick_product(baseline.text, exclude=product)
        if second is None:
            continue
        a2, b2, product2 = second
        payload2 = build(a2, b2)
        injected2 = _mutate(parsed, pairs, index, value + payload2)
        verify = budget.fetch(fetch, injected2)
        if verify is None:
            return None
        if not verify.ok or not verify.body \
                or str(product2) not in verify.text:
            continue
        finding = Finding(
            title=(
                f"Server-side template injection in parameter '{name}' "
                f"({engine})"
            ),
            severity="high",
            category="ssti",
            host=(parsed.hostname or "").lower(),
            url=injected,
            description=(
                f"Injecting the {engine} expression '{payload}' returned "
                f"'{product}', and a second expression returned '{product2}'. "
                "The server evaluates template expressions built from user "
                "input, which can lead to remote code execution depending on "
                "the engine. Only arithmetic was evaluated; no command or file "
                "access was attempted."
            ),
            remediation=(
                "Do not build templates from user input; pass values as data, "
                "and run template engines in a sandbox with minimal privileges."
            ),
            evidence=(
                f"Parameter: {name}\n"
                f"Baseline: {len(baseline.body)} bytes; product {product} "
                "absent\n"
                f"Payload 1: {payload} -> product {product} returned "
                f"(HTTP {result.status}, {len(result.body)} bytes)\n"
                f"Payload 2: {payload2} -> product {product2} returned "
                f"(HTTP {verify.status}, {len(verify.body)} bytes)\n"
                "Reflection alone cannot produce the product, so the "
                "expression was evaluated server-side."
            ),
            confidence=CONFIDENCE_CONFIRMED,
            verified=True,
            verification=(
                f"two distinct {engine} expressions were evaluated to their "
                "arithmetic product on independent requests"
            ),
            poc=[
                f"# baseline; {product} should be absent",
                "curl -sS --max-time 30 " + shlex.quote(original)
                + f" | grep -F '{product}' || echo 'baseline clean'",
                f"# server evaluates the expression ({engine})",
                "curl -sS --max-time 30 " + shlex.quote(injected)
                + f" | grep -F '{product}'",
            ],
            reproductions=2,
            stable=True,
        )
        meta["checks"]["ssti"] += 1
        return finding, verify
    return None


def _check_xss(
    budget, fetch, parsed, pairs, index, baseline, meta, original
):
    name, value = pairs[index]
    token = secrets.token_hex(4)
    tag = f"<wwx{token}>"
    payload = tag + "\"'"
    if tag in baseline.text:
        return None
    injected = _mutate(parsed, pairs, index, value + payload)
    result = budget.fetch(fetch, injected)
    if result is None:
        return None
    if not result.ok or not _is_html(result):
        return None
    if tag not in result.text:
        return None
    context = _xss_context(result.text, result.text.find(tag))

    token2 = secrets.token_hex(4)
    tag2 = f"<wwx{token2}>"
    injected2 = _mutate(parsed, pairs, index, value + tag2 + "\"'")
    verify = budget.fetch(fetch, injected2)
    if verify is None:
        return None
    if not verify.ok or not _is_html(verify) or tag2 not in verify.text:
        return None
    finding = Finding(
        title=f"Reflected HTML injection (possible XSS) in parameter '{name}'",
        severity="medium",
        category="xss",
        host=(parsed.hostname or "").lower(),
        url=injected,
        description=(
            "A benign tag containing a unique marker was reflected verbatim in "
            f"an HTML response ({context}). Because the angle brackets and "
            "quotes were not encoded, attacker-controlled markup can break out "
            "of this context. Script execution was not attempted; confirm "
            "exploitability in a browser that renders the exact response."
        ),
        remediation=(
            "Context-aware output encoding for every sink, a restrictive "
            "Content-Security-Policy, and a framework auto-escaper for HTML "
            "and attributes."
        ),
        evidence=(
            f"Parameter: {name}\n"
            f"Context: {context}\n"
            f"Payload 1: {payload}\n"
            f"Reflected at HTTP {result.status}, {len(result.body)} bytes\n"
            f"Payload 2: {tag2}\"' reflected at HTTP {verify.status}, "
            f"{len(verify.body)} bytes\n"
            "The marker is absent from the baseline and the tag was not "
            "entity-encoded. No script was executed during testing."
        ),
        confidence=CONFIDENCE_FIRM,
        verified=True,
        verification=(
            f"raw tag reflected unencoded in an HTML response ({context}) on "
            "two independent requests; execution not attempted"
        ),
        poc=[
            "# raw tag reflection; pipe through grep -F to see the sink",
            "curl -sS --max-time 30 -D - " + shlex.quote(injected)
            + f" | grep -F '{tag}'",
        ],
        reproductions=2,
        stable=True,
    )
    meta["checks"]["xss"] += 1
    return finding, verify


def _check_lfi(
    budget, fetch, parsed, pairs, index, baseline, meta, original
):
    name, value = pairs[index]
    if name.lower() not in FILE_PARAMS:
        return None
    for payload, deeper, signatures in LFI_PROBES:
        if any(signature in baseline.text for signature in signatures):
            return None
        injected = _mutate(parsed, pairs, index, value + payload)
        result = budget.fetch(fetch, injected)
        if result is None:
            return None
        if not result.ok or result.status is None or not result.body:
            continue
        matched = next(
            (signature for signature in signatures
             if signature in result.text), None)
        if matched is None:
            continue
        injected2 = _mutate(parsed, pairs, index, value + deeper)
        verify = budget.fetch(fetch, injected2)
        if verify is None:
            return None
        if not verify.ok or not verify.body \
                or not any(signature in verify.text for signature in signatures):
            continue
        finding = Finding(
            title=f"Local file inclusion in parameter '{name}'",
            severity="high",
            category="lfi",
            host=(parsed.hostname or "").lower(),
            url=injected,
            description=(
                "A path-traversal payload in this parameter returned local "
                f"file content (matched '{matched}'). An attacker could read "
                "application source, credentials, and configuration files. "
                "Only a read of a standard system file was performed; no file "
                "was modified or created."
            ),
            remediation=(
                "Resolve the requested name against an allowlist of files, "
                "reject traversal sequences, and run the service with minimal "
                "filesystem privileges."
            ),
            evidence=(
                f"Parameter: {name}\n"
                f"Payload 1: {payload} -> matched '{matched}' "
                f"(HTTP {result.status}, {len(result.body)} bytes)\n"
                f"Payload 2: {deeper} -> matched the same signature "
                f"(HTTP {verify.status}, {len(verify.body)} bytes)\n"
                "The signature is absent from the baseline response."
            ),
            confidence=CONFIDENCE_CONFIRMED,
            verified=True,
            verification=(
                "the file signature appeared only after traversal and "
                "reproduced with a second traversal depth"
            ),
            poc=[
                "# traversal read; grep shows the matched file signature",
                "curl -sS --max-time 30 " + shlex.quote(injected)
                + f" | grep -F {shlex.quote(matched)}",
            ],
            reproductions=2,
            stable=True,
        )
        meta["checks"]["lfi"] += 1
        return finding, verify
    return None


def _fetch_error(text: str) -> str | None:
    lowered = text.lower()
    for marker in FETCH_ERROR_PATTERNS:
        if marker in lowered:
            return marker
    return None


def _check_ssrf(
    budget, fetch, parsed, pairs, index, baseline, meta, original
):
    name, value = pairs[index]
    if name.lower() not in URL_PARAMS:
        return None
    if _fetch_error(baseline.text):
        return None
    probe_host = f"ww-ssrf-{secrets.token_hex(4)}.invalid"
    injected = _mutate(parsed, pairs, index, f"http://{probe_host}/")
    result = budget.fetch(fetch, injected)
    if result is None:
        return None
    if result.status is None or not result.body:
        return None
    marker = _fetch_error(result.text)
    if marker is None:
        return None
    probe_host2 = f"ww-ssrf-{secrets.token_hex(4)}.invalid"
    injected2 = _mutate(parsed, pairs, index, f"https://{probe_host2}/")
    verify = budget.fetch(fetch, injected2)
    if verify is None:
        return None
    if verify.status is None or not verify.body:
        return None
    if _fetch_error(verify.text) is None:
        return None
    finding = Finding(
        title=f"Server-side request fetch in parameter '{name}' (possible SSRF)",
        severity="medium",
        category="ssrf",
        host=(parsed.hostname or "").lower(),
        url=injected,
        description=(
            "Replacing this parameter with a URL made the server try to "
            f"resolve it and return the resolver error ('{marker}'). That "
            "means the value drives a request the server performs, the usual "
            "precondition for server-side request forgery. The probe used a "
            "random .invalid hostname, so no internal address, metadata "
            "endpoint, or third-party service was contacted, and no response "
            "content from such a target was obtained."
        ),
        remediation=(
            "Resolve user-supplied URLs against a strict allowlist, block "
            "private/link-local ranges and redirects to them, and fetch from a "
            "dedicated egress proxy with no internal access."
        ),
        evidence=(
            f"Parameter: {name}\n"
            f"Probe 1: http://{probe_host}/ -> matched '{marker}' "
            f"(HTTP {result.status})\n"
            f"Probe 2: https://{probe_host2}/ -> resolver error reproduced "
            f"(HTTP {verify.status})\n"
            "The untouched baseline contains no resolver error."
        ),
        confidence=CONFIDENCE_FIRM,
        verified=True,
        verification=(
            "two distinct .invalid hostnames triggered the same server-side "
            "resolver failure that is absent from the baseline"
        ),
        poc=[
            "# shows the resolver error produced by the server-side fetch",
            "curl -sS --max-time 30 " + shlex.quote(injected)
            + f" | grep -iF {shlex.quote(marker)}",
            "# No internal or third-party URL was requested by this probe.",
        ],
        reproductions=2,
        stable=True,
    )
    meta["checks"]["ssrf"] += 1
    return finding, verify


def _injected_header(result: HttpResult, header_name: str):
    wanted = header_name.lower()
    for key in result.headers:
        if str(key).strip().lower().startswith(wanted):
            return str(key)
    return None


def _check_crlf(
    budget, fetch, parsed, pairs, index, baseline, meta, original
):
    name, value = pairs[index]
    token = f"X-WW-{secrets.token_hex(4)}"
    injected = _mutate(parsed, pairs, index, value + "\r\n" + token + ": 1")
    result = budget.fetch(fetch, injected)
    if result is None or result.status is None:
        return None
    hit = _injected_header(result, token)
    if hit is None:
        return None
    token2 = f"X-WW-{secrets.token_hex(4)}"
    injected2 = _mutate(parsed, pairs, index, value + "\r\n" + token2 + ": 1")
    verify = budget.fetch(fetch, injected2)
    if verify is None or verify.status is None:
        return None
    if _injected_header(verify, token2) is None:
        return None
    finding = Finding(
        title=f"CRLF/header injection in parameter '{name}'",
        severity="low",
        category="crlf",
        host=(parsed.hostname or "").lower(),
        url=injected,
        description=(
            "An encoded carriage-return/line-feed pair in this parameter was "
            f"decoded into a new response header ('{hit}: 1'). Because the "
            "value reaches the response headers, an attacker could inject "
            "additional headers, split the response, or set cookies; that "
            "second step was not performed."
        ),
        remediation=(
            "Strip CR/LF from any value copied into a header or redirect, and "
            "let the framework build headers from validated fields."
        ),
        evidence=(
            f"Parameter: {name}\n"
            f"Probe 1: marker header '{hit}' appeared with token "
            f"{token} (HTTP {result.status})\n"
            f"Probe 2: a second random token appeared as its own header "
            f"(HTTP {verify.status})\n"
            "Only a custom X-WW-* header name was used."
        ),
        confidence=CONFIDENCE_FIRM,
        verified=True,
        verification=(
            "two random marker header names were returned by the server and "
            "were never present on the baseline"
        ),
        poc=[
            "# shows the injected header in the response",
            "curl -sS --max-time 30 -D - -o /dev/null " + shlex.quote(injected)
            + f" | grep -iF {shlex.quote(token)}",
        ],
        reproductions=2,
        stable=True,
    )
    meta["checks"]["crlf"] += 1
    return finding, verify


def analyze(
    urls,
    fetch,
    scopes,
    is_catch_all=None,
    *,
    max_urls: int = 8,
    max_params: int = 10,
    max_requests: int = 180,
):
    """Probe in-scope URLs and return ``(finding, evidence_result)`` pairs."""
    meta = {
        "enabled": True,
        "candidate_urls": 0,
        "parameters": 0,
        "requests": 0,
        "checks": {
            "sql_error": 0,
            "sql_boolean": 0,
            "ssti": 0,
            "xss": 0,
            "lfi": 0,
            "ssrf": 0,
            "crlf": 0,
        },
        "findings": 0,
        "budget_exhausted": False,
        "warnings": [],
    }
    produced: list[tuple[Finding, HttpResult]] = []
    budget = _Budget(max_requests)
    candidates = _candidate_urls(urls, scopes, max(0, max_urls))
    meta["candidate_urls"] = len(candidates)
    if not candidates:
        meta["warnings"].append(
            "no in-scope crawl URLs with testable query parameters")
        return produced, meta

    for original in candidates:
        if not budget.available:
            break
        parsed = urlsplit(original)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            continue
        baseline = budget.fetch(fetch, original)
        if baseline is None:
            break
        # An empty body is normal for a redirect endpoint, which is exactly
        # where header injection shows up, so only a failed request is skipped.
        if not baseline.ok or baseline.status is None:
            continue
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        for index, (name, value) in enumerate(pairs):
            if meta["parameters"] >= max_params or not budget.available:
                break
            if not _testable(name, value):
                continue
            meta["parameters"] += 1
            raw: list[tuple[Finding, HttpResult]] = []
            error_hit = _check_sql_error(
                budget, fetch, parsed, pairs, index, baseline, meta, original)
            if error_hit:
                raw.append(error_hit)
            else:
                boolean_hit = _check_sql_boolean(
                    budget, fetch, parsed, pairs, index, baseline, meta,
                    original)
                if boolean_hit:
                    raw.append(boolean_hit)
            for detector in (_check_ssti, _check_xss, _check_lfi, _check_ssrf,
                             _check_crlf):
                found = detector(
                    budget, fetch, parsed, pairs, index, baseline, meta,
                    original,
                )
                if found:
                    raw.append(found)

            for finding, evidence in raw:
                if evidence is None:
                    continue
                if is_catch_all is not None and \
                        is_catch_all(origin, path, evidence):
                    continue
                produced.append((finding, evidence))
                meta["findings"] += 1

    meta["requests"] = budget.used
    meta["budget_exhausted"] = budget.used >= budget.limit
    if meta["budget_exhausted"]:
        meta["warnings"].append(
            f"request budget reached after {budget.used} probes; "
            "remaining parameters were not tested")
    return produced, meta
