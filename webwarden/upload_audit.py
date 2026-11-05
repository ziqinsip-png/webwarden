"""Read-only upload-surface audit for an isolated lab.

The command exists to map an intentionally vulnerable training lab before an
exercise: which forms accept files, what the HTML claims to validate, whether
upload folders are listable, and which PHP/runtime details are exposed. It is
GET/HEAD only. Nothing is uploaded, no PHP is executed, and the lab gate
refuses any host that resolves outside loopback, RFC1918, or link-local space.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import socket
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import __version__
from .httpclient import HttpClient
from .models import CONFIDENCE_CONFIRMED, Finding
from .util import Budget, iso_now, sanitize_name, utc_stamp

LAB_NOTICE = (
    "LAB ONLY - upload-audit is read-only (GET/HEAD) and refuses any host that "
    "resolves outside loopback, RFC1918, or link-local space. Nothing is "
    "uploaded and no PHP is executed."
)

DIR_CANDIDATES = (
    "uploads/",
    "upload/",
    "files/",
    "file/",
    "images/",
    "media/",
    "assets/uploads/",
)

CONFIG_CANDIDATES = (
    (".htaccess", ("addtype", "addhandler", "rewriteengine", "php_flag",
                   "php_value", "options ")),
    ("web.config", ("<configuration", "<system.webserver")),
    ("phpinfo.php", ("php version", "configuration file")),
)

LISTING_MARKERS = ("index of /", "<title>index of", "directory listing for")
MAX_REQUESTS = 80


class LabScopeError(RuntimeError):
    """The target is not an isolated lab address."""


class LabAuditError(RuntimeError):
    """The audit could not complete."""


@dataclass
class UploadForm:
    action: str = ""
    method: str = "get"
    enctype: str = ""
    fields: list[str] = field(default_factory=list)
    file_fields: list[str] = field(default_factory=list)
    accepts: list[str] = field(default_factory=list)
    hidden: int = 0

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "method": self.method,
            "enctype": self.enctype,
            "fields": list(self.fields),
            "file_fields": list(self.file_fields),
            "accepts": list(self.accepts),
            "hidden": self.hidden,
        }


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[UploadForm] = []
        self._current: UploadForm | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag == "form":
            self._current = UploadForm(
                action=values.get("action", ""),
                method=(values.get("method") or "get").lower(),
                enctype=(values.get("enctype") or "").lower(),
            )
            self.forms.append(self._current)
            return
        if tag != "input" or self._current is None:
            return
        kind = (values.get("type") or "text").lower()
        name = values.get("name", "")
        if kind == "file":
            if name:
                self._current.file_fields.append(name)
            accept = values.get("accept", "")
            if accept:
                self._current.accepts.append(accept)
        elif kind == "hidden":
            self._current.hidden += 1
        elif name:
            self._current.fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def parse_upload_forms(html: str) -> list[UploadForm]:
    parser = _FormParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    return [form for form in parser.forms if form.file_fields]


def sapi_profile(headers: dict[str, str], set_cookies: list[str]) -> dict:
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    via = headers.get("via", "")
    blob = " ".join((server, powered, via)).lower()
    match = re.search(r"php/([0-9][0-9.]*)", f"{powered} {server}".lower())
    php_version = match.group(1).rstrip(".") if match else None
    sapi = "unknown"
    if "fpm" in blob or "frankenphp" in blob:
        sapi = "php-fpm"
    elif "cgi" in blob:
        sapi = "cgi"
    elif "php" in powered.lower():
        sapi = "php (fpm or mod_php)"
    cookie_names = sorted({
        cookie.split("=", 1)[0].strip()
        for cookie in set_cookies
        if "=" in cookie
    })
    php_session = any(name.lower() in ("phpsessid", "phpssid")
                      for name in cookie_names)
    if sapi == "unknown" and php_session:
        sapi = "php (session cookie only)"
    return {
        "server": server,
        "powered_by": powered,
        "via": via,
        "php_version": php_version,
        "sapi": sapi,
        "php_session_cookie": php_session,
        "cookie_names": cookie_names[:10],
        "confidence": "header-only",
    }


def _resolve(host: str, port: int) -> list:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise LabScopeError(f"cannot resolve {host!r}: {exc}") from exc
    addresses = []
    for _family, _kind, _proto, _canon, sockaddr in infos:
        raw = str(sockaddr[0]).split("%")[0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


def _is_lab_address(address) -> bool:
    return bool(
        address.is_loopback or address.is_private or address.is_link_local
    )


def assert_lab_url(target: str) -> str:
    parsed = urlsplit(target if "://" in target else "http://" + target)
    if parsed.scheme not in ("http", "https"):
        raise LabScopeError("target must be an http:// or https:// URL")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise LabScopeError("target URL has no host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = _resolve(host, port)
    if not addresses:
        raise LabScopeError(f"cannot resolve {host!r}")
    public = [str(address) for address in addresses if not _is_lab_address(address)]
    if public:
        raise LabScopeError(
            f"refusing {host!r}: resolves to {', '.join(public)}. upload-audit "
            "only runs against an isolated lab on loopback or a private range"
        )
    return host


def _base_url(target: str) -> str:
    parsed = urlsplit(target if "://" in target else "http://" + target)
    return parsed._replace(fragment="").geturl()


def _looks_like_listing(text: str) -> bool:
    lowered = (text or "")[:8000].lower()
    return "href=" in lowered and any(marker in lowered
                                      for marker in LISTING_MARKERS)


def _control_name(extension: str) -> str:
    return f"ww-control-{secrets.token_hex(4)}{extension}"


def _finding(
    title: str,
    severity: str,
    category: str,
    url: str,
    description: str,
    evidence: str = "",
    body: bytes = b"",
    remediation: str = "",
    poc: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        host=urlsplit(url).hostname or "",
        url=url,
        description=description,
        remediation=remediation,
        evidence=evidence[:600],
        confidence=CONFIDENCE_CONFIRMED,
        verified=True,
        verification="observed directly in a read-only GET response",
        poc=list(poc or []),
        evidence_sha256=hashlib.sha256(body).hexdigest() if body else "",
        evidence_bytes=len(body),
    )


def _curl(url: str) -> str:
    return f"curl -sS {url}"


def audit_lab_upload_surface(
    target: str,
    timeout: float = 8.0,
    rate: float = 10.0,
) -> dict:
    host = assert_lab_url(target)
    base = _base_url(target)
    client = HttpClient(
        scopes=[host],
        rate=rate,
        timeout=timeout,
        max_bytes=512 * 1024,
        budget=Budget(MAX_REQUESTS),
    )
    page = client.get(base)
    if page.error:
        raise LabAuditError(f"request failed: {page.error}")
    if not page.ok:
        raise LabAuditError(f"target returned no HTTP status ({base})")

    forms = parse_upload_forms(page.text)
    profile = sapi_profile(page.headers, page.set_cookies)
    findings: list[Finding] = []
    checks: list[dict] = []

    for rel in DIR_CANDIDATES:
        check = {"kind": "upload-dir", "path": rel}
        result = client.get(urljoin(base, rel))
        check["status"] = result.status
        checks.append(check)
        if result.status != 200 or not _looks_like_listing(result.text):
            continue
        control_name = _control_name("")
        control_url = urljoin(base, f"{control_name}/")
        control = client.get(control_url)
        check["control_path"] = f"/{control_name}/"
        check["control_status"] = control.status
        if control.status == 200 and _looks_like_listing(control.text):
            continue
        url = urljoin(base, rel)
        findings.append(_finding(
            "Upload directory is listable",
            "low",
            "upload",
            url,
            (
                f"GET {url} returned a directory index instead of a 404 or a "
                "blank page, and a randomly named control directory did not. "
                "Anyone can read the names of files that were uploaded."
            ),
            evidence=result.text[:400],
            body=result.body,
            remediation=(
                "Disable autoindex for upload folders and serve stored files "
                "through an application route with randomized names."
            ),
            poc=[_curl(url)],
        ))

    for rel, markers in CONFIG_CANDIDATES:
        check = {"kind": "config", "path": rel}
        result = client.get(urljoin(base, rel))
        check["status"] = result.status
        checks.append(check)
        if result.status != 200:
            continue
        lowered = (result.text or "").lower()
        if not any(marker in lowered for marker in markers):
            continue
        suffix = Path(rel).suffix
        control_name = _control_name(suffix)
        control = client.get(urljoin(base, control_name))
        check["control_path"] = f"/{control_name}"
        check["control_status"] = control.status
        if control.status == 200 and any(
            marker in (control.text or "").lower() for marker in markers
        ):
            continue
        url = urljoin(base, rel)
        titles = {
            ".htaccess": "Apache .htaccess is publicly readable",
            "web.config": "IIS web.config is publicly readable",
            "phpinfo.php": "phpinfo() page is exposed",
        }
        notes = {
            ".htaccess": (
                "A readable .htaccess exposes the upload directory's handler "
                "and rewrite rules, which tells a tester exactly what file "
                "types the server will execute."
            ),
            "web.config": (
                "A readable web.config exposes handler mappings and request "
                "filtering rules for the application."
            ),
            "phpinfo.php": (
                "phpinfo() exposes the PHP version, loaded extensions, "
                "document root, and configuration paths. It is not proof of "
                "a vulnerability, but it removes guesswork from the lab."
            ),
        }
        findings.append(_finding(
            titles[rel],
            "low",
            "upload",
            url,
            notes[rel],
            evidence=result.text[:400],
            body=result.body,
            remediation=f"Block public access to {rel} in the web server.",
            poc=[_curl(url)],
        ))

    for form in forms:
        action = urljoin(page.final_url, form.action or base)
        fields = ", ".join(form.file_fields)
        accepts = ", ".join(form.accepts) or "none declared"
        description = (
            f"The page exposes a file upload form (action={action}, "
            f"method={form.method}, enctype={form.enctype or 'unspecified'}) "
            f"with file field(s) {fields} and accept={accepts}. This audit "
            "only read the HTML; it did not submit the form."
        )
        findings.append(_finding(
            "Upload form discovered",
            "info",
            "upload",
            action,
            description,
            evidence=page.text[:400],
            body=page.body,
            remediation=(
                "Validate extension and content on the server, store uploads "
                "outside the web root, generate random file names, and never "
                "execute stored files."
            ),
            poc=[_curl(action)],
        ))
        if form.accepts:
            findings.append(_finding(
                "Client-side upload restriction declared",
                "info",
                "upload",
                action,
                (
                    f"The form declares accept={accepts}. That attribute only "
                    "guides the browser picker; it is not a server-side filter "
                    "and does not prove which extensions the server accepts."
                ),
                evidence=page.text[:400],
                body=page.body,
                remediation=(
                    "Treat accept= as a usability hint only and enforce the "
                    "real allow-list on the server."
                ),
                poc=[_curl(action)],
            ))

    findings.append(_finding(
        "PHP runtime fingerprint",
        "info",
        "upload",
        base,
        (
            f"Server={profile['server'] or 'not sent'}; "
            f"X-Powered-By={profile['powered_by'] or 'not sent'}; "
            f"guessed SAPI={profile['sapi']}; PHP={profile['php_version'] or 'unknown'}; "
            f"PHP session cookie={profile['php_session_cookie']}. "
            "This is a header-only observation, not a vulnerability claim, "
            "and no fault or memory probe was sent."
        ),
        evidence=(
            "\n".join(
                f"{name}: {profile[name]}"
                for name in ("server", "powered_by", "sapi", "php_version")
            )
        ),
        body=page.body,
        remediation=(
            "Reduce version disclosure in Server and X-Powered-By, and keep "
            "PHP patched."
        ),
        poc=[_curl(base)],
    ))

    return {
        "host": host,
        "target": base,
        "forms": [form.to_dict() for form in forms],
        "sapi": profile,
        "checks": checks,
        "findings": findings,
        "request_count": 1 + len(checks) + sum(
            1 for check in checks if "control_path" in check
        ),
    }


def _markdown(result: dict, lang: str = "en") -> str:
    idn = (lang or "en").lower().startswith("id")

    def t(en: str, i: str) -> str:
        return i if idn else en

    lines = [
        (f"# Audit permukaan upload - {result['host']}" if idn
         else f"# Upload surface audit - {result['host']}"),
        "",
        f"> {LAB_NOTICE}",
        "",
        f"- {t('generated', 'dibuat')}: {iso_now()}",
        f"- target: {result['target']}",
        f"- webwarden: {__version__}",
        f"- SAPI guess: {result['sapi']['sapi']} (header-only)",
        f"- PHP: {result['sapi']['php_version'] or t('unknown', 'tidak diketahui')}",
        f"- {t('upload forms', 'form upload')}: {len(result['forms'])}",
        f"- {t('GET requests', 'request GET')}: {result['request_count']}",
        "",
        "## " + t("Upload forms", "Form upload"),
        "",
    ]
    if result["forms"]:
        lines.append(
            "| " + t("action", "action") + " | method | enctype | file field | "
            "accept | hidden |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for form in result["forms"]:
            lines.append(
                f"| {form['action'] or '(self)'} | {form['method']} | "
                f"{form['enctype'] or t('(unspecified)', '(tidak dispesifikasikan)')} | "
                f"{', '.join(form['file_fields'])} | "
                f"{', '.join(form['accepts']) or '-'} | {form['hidden']} |"
            )
    else:
        lines.append(t(
            "No multipart file input was found on the target page.",
            "Tidak ditemukan input file multipart di halaman target."))
    lines += ["", "## " + t("Findings", "Temuan"), ""]
    if result["findings"]:
        for finding in result["findings"]:
            lines.append(f"### [{finding.severity.upper()}] {finding.title}")
            lines.append("")
            lines.append(f"- url: {finding.url}")
            lines.append(f"- {t('verification', 'verifikasi')}: "
                         f"{finding.verification}")
            lines.append("")
            lines.append(finding.description)
            if finding.evidence:
                lines += ["", "```", finding.evidence.strip(), "```"]
            if finding.remediation:
                lines += ["", f"{t('Remediation', 'Remediasi')}: "
                              f"{finding.remediation}"]
            if finding.poc:
                lines += ["", t("Read-only proof:", "Bukti read-only:"), ""]
                lines += [f"    {command}" for command in finding.poc]
            lines.append("")
    else:
        lines.append(t(
            "No upload surface was observed.",
            "Tidak ada permukaan upload yang teramati."))
    lines += [
        "## " + t("Checked paths", "Path yang diperiksa"),
        "",
        "| kind | path | status | control |",
        "| --- | --- | --- | --- |",
    ]
    for check in result["checks"]:
        control = (
            f"{check.get('control_path')} -> {check.get('control_status')}"
            if check.get("control_path")
            else "-"
        )
        lines.append(
            f"| {check['kind']} | {check['path']} | {check.get('status', '-')} | "
            f"{control} |"
        )
    boundary = (
        [
            "GET/HEAD only; tidak ada POST dan tidak ada upload file.",
            "Tidak ada file PHP yang dieksekusi dan tidak ada shell yang diminta.",
            "Lab gate menolak target di luar loopback/private range.",
            "Tidak ada probe OOM, heap-spray, session-poison, atau mass-scan "
            "yang dikirim.",
        ]
        if idn else [
            "GET/HEAD only; no POST and no file upload.",
            "No PHP file was executed and no shell was requested.",
            "The lab gate refused any target outside loopback/private ranges.",
            "No OOM, heap-spray, session-poison, or mass-scan probe was sent.",
        ]
    )
    lines += ["", "## " + t("Boundary", "Batas"), ""]
    lines += [f"- {item}" for item in boundary]
    lines.append("")
    return "\n".join(lines)


def write_upload_audit(result: dict, out_dir: str | Path | None = None,
                       lang: str = "en") -> dict[str, str]:
    if out_dir is None:
        base = Path("reports") / (
            f"upload-audit-{sanitize_name(result['host'])}-{utc_stamp()}"
        )
    else:
        base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    markdown = base / "upload-audit.md"
    json_path = base / "upload-audit.json"
    markdown.write_text(_markdown(result, lang), encoding="utf-8", newline="\n")
    payload = {
        "tool": "webwarden",
        "version": __version__,
        "generated_at": iso_now(),
        "lab_only": True,
        "target": result["target"],
        "host": result["host"],
        "request_count": result["request_count"],
        "sapi": result["sapi"],
        "forms": result["forms"],
        "checks": result["checks"],
        "findings": [finding.to_dict() for finding in result["findings"]],
    }
    json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {"markdown": str(markdown), "json": str(json_path)}
