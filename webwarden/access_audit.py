"""Two-session access-control audit (IDOR/BOLA) with operator-owned accounts.

The operator supplies two session headers for accounts they own. The audit only
sends GET requests to object URLs the operator already knows. It never logs in,
creates accounts, enumerates IDs, changes sharing/permissions, or writes data.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .httpclient import Budget, HttpClient
from .util import in_scope, iso_now, sha_prefix, similar_length

MAX_BYTES = 1048576
MAX_URLS = 50

NOTICE = (
    "AUTH OWNED ACCOUNTS ONLY - access-audit uses two session headers that the "
    "operator supplies for accounts they own. It sends GET/HEAD only, never "
    "logs in or creates accounts, never enumerates object IDs, and never "
    "changes sharing or permissions."
)

BOUNDARY = (
    "Kedua sesi (A dan B) adalah akun uji milik operator di dalam scope. Audit "
    "ini hanya mengirim GET ke URL objek yang sudah diketahui; tidak ada login "
    "otomatis, pembuatan akun, enumerasi ID, perubahan sharing/permission, "
    "atau penulisan data."
)

DENY_MARKERS = (
    "type=\"password\"", "type='password'", "sign in", "log in", "login",
    "masuk", "unauthorized", "forbidden", "access denied", "not authorized",
    "tidak memiliki akses", "tidak diizinkan",
)

VERDICT_LABEL = {
    "cross-account": "Akses lintas akun (IDOR/BOLA)",
    "cross-account-partial": "Kemungkinan akses lintas akun",
    "unauthenticated": "Objek bisa dibaca tanpa autentikasi",
    "denied": "Akses ditolak (kontrol lolos)",
    "inconclusive": "Tidak konklusif",
}


class AccessAuditError(RuntimeError):
    pass


class AccessScopeError(RuntimeError):
    pass


@dataclass
class AccessCheck:
    url: str
    verdict: str = "inconclusive"
    severity: str = "info"
    note: str = ""
    owner_status: int | None = None
    other_status: int | None = None
    anon_status: int | None = None
    owner_bytes: int = 0
    other_bytes: int = 0
    anon_bytes: int = 0
    owner_sha: str = ""
    other_sha: str = ""
    anon_sha: str = ""
    content_type: str = ""
    reproductions: int = 1
    stable: bool | None = None
    evidence_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "verdict": self.verdict,
            "severity": self.severity,
            "note": self.note,
            "owner": {"status": self.owner_status, "bytes": self.owner_bytes,
                      "sha256_prefix": self.owner_sha},
            "other": {"status": self.other_status, "bytes": self.other_bytes,
                      "sha256_prefix": self.other_sha},
            "anonymous": {"status": self.anon_status, "bytes": self.anon_bytes,
                          "sha256_prefix": self.anon_sha},
            "content_type": self.content_type,
            "reproductions": self.reproductions,
            "stable": self.stable,
            "evidence_files": list(self.evidence_files),
        }


@dataclass
class AccessAuditResult:
    target: str
    scopes: list[str]
    urls: list[str]
    checks: list[AccessCheck]
    started_at: str
    finished_at: str
    version: str = __version__
    requests: int = 0
    anonymous_checked: bool = True

    def findings(self) -> list[AccessCheck]:
        return [
            check for check in self.checks
            if check.verdict in (
                "cross-account", "cross-account-partial", "unauthenticated")
        ]

    def counts(self) -> dict:
        counts = {"cross-account": 0, "cross-account-partial": 0,
                  "unauthenticated": 0, "denied": 0, "inconclusive": 0}
        for check in self.checks:
            counts[check.verdict] = counts.get(check.verdict, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "tool": "webwarden",
            "command": "access-audit",
            "version": self.version,
            "target": self.target,
            "scopes": list(self.scopes),
            "urls": list(self.urls),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "authorized": True,
            "accounts_owned": True,
            "anonymous_checked": self.anonymous_checked,
            "requests": self.requests,
            "counts": self.counts(),
            "checks": [check.to_dict() for check in self.checks],
        }


def _login_or_denied(text: str) -> bool:
    lowered = (text or "")[:20000].lower()
    return any(marker in lowered for marker in DENY_MARKERS)


def _within_scope(url: str, scopes: list[str]) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return bool(host) and in_scope(host, scopes)


def _shell_single(value: str) -> str:
    return value.replace("'", "'\\''")


def assert_scope(urls: list[str], scopes: list[str]) -> None:
    outside = [url for url in urls if not _within_scope(url, scopes)]
    if outside:
        raise AccessScopeError(
            f"refusing {outside[0]}: host is outside the supplied scope "
            f"({', '.join(scopes)}). access-audit only tests objects you own."
        )


def parse_urls(raw: list[str], files: list[str]) -> list[str]:
    urls: list[str] = []
    for item in raw:
        urls.extend(part for part in item.replace(",", "\n").splitlines())
    for name in files:
        path = Path(name).expanduser()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise AccessAuditError(f"cannot read url list {path}: {exc}")
        urls.extend(text.splitlines())
    cleaned = []
    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise AccessAuditError(f"not an http(s) object URL: {url}")
        cleaned.append(url)
    cleaned = list(dict.fromkeys(cleaned))
    if len(cleaned) > MAX_URLS:
        raise AccessAuditError(
            f"at most {MAX_URLS} object URLs per run (got {len(cleaned)})")
    return cleaned


def _get(client: HttpClient, url: str, headers: dict[str, str] | None) -> object:
    kwargs = {"follow": False, "read_limit": MAX_BYTES, "max_bytes": MAX_BYTES}
    if headers:
        kwargs.update({"auth": True, "auth_headers": headers})
    return client.get(url, **kwargs)


def _same_body(first, second) -> bool:
    return bool(first.body) and first.body == second.body


def audit_cross_account(
    *,
    target: str,
    urls: list[str],
    auth_a: dict[str, str],
    auth_b: dict[str, str],
    scopes: list[str] | None = None,
    timeout: float = 10.0,
    rate: float = 4.0,
    check_anonymous: bool = True,
    allow_auth_http: bool = False,
) -> AccessAuditResult:
    scopes = [scope.lower() for scope in (scopes or [urlsplit(target).hostname or ""])]
    urls = parse_urls(urls, [])
    if not urls:
        raise AccessAuditError("no object URLs supplied")
    assert_scope(urls, scopes)

    client = HttpClient(
        scopes=scopes,
        rate=rate,
        timeout=timeout,
        max_bytes=MAX_BYTES,
        budget=Budget(min(3000, 12 * len(urls) + 20)),
        auth_host=urlsplit(target).hostname or "",
        allow_auth_http=allow_auth_http,
    )
    started = iso_now()
    checks: list[AccessCheck] = []

    for url in urls:
        check = AccessCheck(url=url)
        owner = _get(client, url, auth_b)
        check.owner_status = owner.status
        check.owner_bytes = len(owner.body or b"")
        check.owner_sha = sha_prefix(owner.body or b"") if owner.body else ""
        check.content_type = owner.content_type or ""

        if not owner.ok or owner.status != 200 or not owner.body:
            check.note = (
                "sesi B (pemilik) tidak bisa membaca objek dengan HTTP 200; "
                "pastikan URL benar dan B memang pemiliknya sebelum menyimpulkan"
            )
            checks.append(check)
            continue

        other = _get(client, url, auth_a)
        check.other_status = other.status
        check.other_bytes = len(other.body or b"")
        check.other_sha = sha_prefix(other.body or b"") if other.body else ""

        if other.status in (401, 403):
            check.verdict = "denied"
            check.note = (
                f"sesi A menerima HTTP {other.status} sementara B menerima 200; "
                "otorisasi tingkat objek tampaknya diterapkan untuk request ini"
            )
        elif other.ok and other.status == 200 and _login_or_denied(other.text):
            check.verdict = "denied"
            check.note = (
                "sesi A dijawab halaman login/ditolak alih-alih objek, jadi "
                "request tidak sampai ke data B"
            )
        elif other.ok and other.status == 200 and _same_body(other, owner):
            again = _get(client, url, auth_a)
            stable = _same_body(again, owner)
            check.reproductions = 2 if stable else 1
            check.stable = stable
            if stable:
                check.verdict = "cross-account"
                check.severity = "high"
                check.note = (
                    "sesi A menerima konten byte-identik dengan objek B pada dua "
                    "request GET terpisah; audit ini tidak mengubah sharing apa pun"
                )
            else:
                check.verdict = "cross-account-partial"
                check.severity = "medium"
                check.note = (
                    "sesi A cocok dengan objek B sekali tetapi tidak pada request "
                    "kedua; ulangi manual sebelum melapor"
                )
        elif (other.ok and other.status == 200
              and other.content_type == owner.content_type
              and similar_length(len(other.body), len(owner.body), 0.10)):
            check.verdict = "cross-account-partial"
            check.severity = "medium"
            check.note = (
                "sesi A menerima HTTP 200 dengan payload berukuran mirip dan "
                "content-type sama tetapi byte berbeda; pastikan manual apakah "
                "itu objek B atau objek milik A sendiri"
            )
        elif other.ok and other.status == 200:
            check.verdict = "inconclusive"
            check.severity = "info"
            check.note = (
                "sesi A menerima HTTP 200 dengan payload berbeda; verifikasi "
                "manual apakah identifier itu memetakan ke objek B"
            )
        else:
            check.verdict = "inconclusive"
            check.note = (
                f"sesi A menerima HTTP {other.status}; tidak ada perbedaan akses "
                "yang bisa dipastikan"
            )

        if check_anonymous:
            anon = _get(client, url, None)
            check.anon_status = anon.status
            check.anon_bytes = len(anon.body or b"")
            check.anon_sha = sha_prefix(anon.body or b"") if anon.body else ""
            if (anon.ok and anon.status == 200 and _same_body(anon, owner)
                    and not _login_or_denied(anon.text)):
                again = _get(client, url, None)
                stable = _same_body(again, owner)
                check.reproductions = max(check.reproductions,
                                          2 if stable else 1)
                check.stable = bool(check.stable and stable) \
                    if check.stable is not None else stable
                check.verdict = "unauthenticated"
                check.severity = "critical" if stable else "high"
                check.note = (
                    "request anonymous (tanpa header sesi) menerima konten objek "
                    "B" + (" pada dua request terpisah" if stable
                           else "; request kedua berbeda")
                )

        checks.append(check)

    finished = iso_now()
    return AccessAuditResult(
        target=target,
        scopes=scopes,
        urls=urls,
        checks=checks,
        started_at=started,
        finished_at=finished,
        requests=getattr(client.budget, "used", 0),
        anonymous_checked=check_anonymous,
    )


def _write_evidence(result: AccessAuditResult, out_dir: Path) -> None:
    evidence = out_dir / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(evidence, 0o700)
    except OSError:
        pass
    index = []
    for number, check in enumerate(result.findings(), start=1):
        slug = f"{number:02d}-{urlsplit(check.url).path.strip('/').replace('/', '-') or 'root'}"[:60]
        entry = {"url": check.url, "files": []}
        for label, status, size, digest in (
            ("owner-b", check.owner_status, check.owner_bytes, check.owner_sha),
            ("other-a", check.other_status, check.other_bytes, check.other_sha),
            ("anonymous", check.anon_status, check.anon_bytes, check.anon_sha),
        ):
            if status is None:
                continue
            name = f"{slug}-{label}.json"
            payload = {
                "url": check.url,
                "role": label,
                "status": status,
                "bytes": size,
                "sha256_prefix": digest,
                "note": (
                    "Metadata only. Raw bodies are stored separately when the "
                    "operator enables evidence capture."
                ),
            }
            path = evidence / name
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            entry["files"].append(str(path))
            check.evidence_files.append(str(path))
        index.append(entry)
    (evidence / "index.json").write_text(
        json.dumps({"target": result.target, "entries": index}, indent=2),
        encoding="utf-8")


def _scenario_lines(findings: list[AccessCheck]) -> list[str]:
    if not findings:
        return []
    confirmed = [item for item in findings if item.verdict == "cross-account"]
    unauth = [item for item in findings if item.verdict == "unauthenticated"]
    lines = [
        "## Skenario attacker (simulasi)",
        "",
        "> **" + BOUNDARY + "**",
        "",
        "1. Attacker membuat/memegang akun A miliknya sendiri di dalam scope.",
        "2. Attacker mengumpulkan ID objek milik akun B (sheet, workspace, "
        "attachment) dari URL yang memang sudah diketahui; audit ini tidak "
        "melakukan enumerasi ID.",
        "3. Request GET yang sama dikirim dengan sesi A dan sesi B, lalu body, "
        "status, dan hash dibandingkan.",
        "4. Bila A menerima byte-identik dengan B, objek tersebut tidak "
        "memeriksa kepemilikan (IDOR/BOLA). Attacker dapat membaca data itu "
        "tanpa izin.",
        "5. Audit berhenti di bukti read-only; tidak ada perubahan sharing, "
        "permission, atau data.",
        "",
        "Tools yang biasa dipakai saat verifikasi manual oleh pemilik scope: "
        "browser DevTools, Burp Suite Repeater, curl (GET saja). Tidak ada tool "
        "yang dijalankan otomatis oleh audit ini.",
        "",
    ]
    if confirmed:
        lines.append(
            f"- **{len(confirmed)} objek** byte-identik antara sesi A dan B.")
    if unauth:
        lines.append(
            f"- **{len(unauth)} objek** dapat dibaca tanpa sesi sama sekali.")
    lines.append("")
    return lines


def _oauth_lines() -> list[str]:
    return [
        "## Checklist SSO/OAuth (manual, belum dijalankan)",
        "",
        "Audit ini tidak memulai alur login SSO/OAuth. Checklist berikut untuk "
        "verifikasi manual di dalam scope:",
        "",
        "- `state` wajib acak dan divalidasi di callback (CSRF pada alur OAuth).",
        "- PKCE `S256` dipakai untuk client publik; `plain` hanya bila tidak "
        "mungkin.",
        "- `redirect_uri` harus exact match dengan allowlist, bukan prefix/wildcard.",
        "- Token audience/issuer divalidasi; token untuk app lain tidak diterima.",
        "- Scope minimal; consent menampilkan scope yang benar-benar diminta.",
        "- Logout/refresh mencabut sesi di semua RP (single logout) bila didukung.",
        "",
    ]


def render_access_markdown(result: AccessAuditResult) -> str:
    findings = result.findings()
    counts = result.counts()
    lines = [
        f"# Audit access-control — {result.target}",
        "",
        f"- **Tool:** webwarden {result.version} (`access-audit`)",
        f"- **Mulai:** {result.started_at}",
        f"- **Selesai:** {result.finished_at}",
        f"- **Scope:** {', '.join(result.scopes)}",
        "- **Izin:** operator menyatakan punya izin tertulis untuk scope ini",
        "- **Akun:** A = akun uji penyerang-simulasi, B = akun pemilik objek "
        "(keduanya milik operator)",
        "- **Metode:** hanya GET/HEAD; tanpa login, tanpa pembuatan akun, tanpa "
        "enumerasi ID, tanpa perubahan sharing/permission",
        "",
        "> **BUKTI PRIVAT.** Direktori `evidence/` mencatat status, jumlah byte, "
        "dan prefix SHA-256 setiap objek. Simpan hanya untuk pemilik (mode 600); "
        "isi body bisa milik akun B.",
        "",
        "## Ringkasan",
        "",
        "| Verdict | Jumlah |",
        "| --- | --- |",
    ]
    for key, label in (
        ("cross-account", "Lintas akun (terkonfirmasi)"),
        ("cross-account-partial", "Kemungkinan lintas akun"),
        ("unauthenticated", "Akses tanpa autentikasi"),
        ("denied", "Ditolak (kontrol)"),
        ("inconclusive", "Tidak konklusif"),
    ):
        lines.append(f"| {label} | {counts.get(key, 0)} |")
    lines.extend([
        "",
        f"- Objek diuji: **{len(result.checks)}**",
        f"- Request GET: **{result.requests}**",
        f"- Pemeriksaan anonymous: **{'ya' if result.anonymous_checked else 'tidak'}**",
        "",
        "## Hasil per objek",
        "",
        "| # | URL | B (pemilik) | A (lain) | Anonymous | Verdict |",
        "| --- | --- | --- | --- | --- | --- |",
    ])
    for number, check in enumerate(result.checks, start=1):
        lines.append(
            f"| {number} | `{check.url}` | {check.owner_status or '-'} | "
            f"{check.other_status or '-'} | {check.anon_status or '-'} | "
            f"{VERDICT_LABEL.get(check.verdict, check.verdict)} |")
    lines.append("")

    if findings:
        lines.extend(["## Temuan", ""])
        for number, check in enumerate(findings, start=1):
            lines.extend([
                f"### {number}. [{check.severity.upper()}] "
                f"{VERDICT_LABEL.get(check.verdict, check.verdict)}",
                "",
                f"- **URL:** `{check.url}`",
                f"- **Sesi B (pemilik):** HTTP {check.owner_status}, "
                f"{check.owner_bytes} bytes, sha256:{check.owner_sha}",
                f"- **Sesi A (lain):** HTTP {check.other_status}, "
                f"{check.other_bytes} bytes, sha256:{check.other_sha}",
            ])
            if result.anonymous_checked:
                lines.append(
                    f"- **Anonymous:** HTTP {check.anon_status}, "
                    f"{check.anon_bytes} bytes, sha256:{check.anon_sha}")
            lines.extend([
                f"- **Reproduksi:** {check.reproductions} request; "
                f"stabil={check.stable}",
                f"- **Catatan:** {check.note}",
                "",
                "```bash",
                "# Isi nilai sesi secara lokal; jangan pernah menempelkannya di report.",
                "# export SESSION_B='Cookie: ...'   # akun B (pemilik objek)",
                "# export SESSION_A='Cookie: ...'   # akun A (uji lintas akun)",
                f"curl -sS -H \"$SESSION_B\" '{_shell_single(check.url)}' | sha256sum",
                f"curl -sS -H \"$SESSION_A\" '{_shell_single(check.url)}' | sha256sum",
            ])
            if result.anonymous_checked:
                lines.append(
                    f"curl -sS '{_shell_single(check.url)}' | sha256sum")
            lines.extend(["```", ""])
    else:
        lines.extend([
            "## Temuan",
            "",
            "Tidak ada akses lintas akun yang terkonfirmasi. Perbedaan status "
            "dicatat di tabel di atas sebagai kontrol.",
            "",
        ])

    lines.extend(_scenario_lines(findings))
    lines.extend(_oauth_lines())
    lines.extend([
        "## Remediasi",
        "",
        "- Terapkan object-level authorization di server untuk setiap objek "
        "(sheet/workspace/attachment), bukan hanya pengecekan login.",
        "- Gunakan pemetaan kepemilikan (owner_id/tenant_id) pada query, dan "
        "kembalikan 404 untuk objek yang bukan milik principal.",
        "- Uji ulang setelah perbaikan dengan dua akun yang sama.",
        "",
        "## Batasan",
        "",
        "- Hanya GET/HEAD; tidak ada login otomatis, pembuatan akun, enumerasi "
        "ID, atau perubahan sharing/permission.",
        "- URL objek B disuplai operator; audit tidak menebak ID.",
        "- Bukti byte-identik menunjukkan respons sama; kepemilikan objek tetap "
        "dikonfirmasi manual di UI aplikasi.",
        "",
    ])
    return "\n".join(lines)


def write_access_audit(
    result: AccessAuditResult,
    out_dir: str | Path | None = None,
) -> dict[str, Path]:
    if out_dir is None:
        stamp = (result.finished_at or result.started_at).replace(":", "").replace("-", "")
        slug = (urlsplit(result.target).hostname or "target").replace(":", "_")
        out_dir = Path("reports") / f"access-audit-{slug}-{stamp[:15]}"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass
    _write_evidence(result, out_dir)
    markdown = out_dir / "access-audit.md"
    payload = out_dir / "access-audit.json"
    markdown.write_text(render_access_markdown(result), encoding="utf-8")
    payload.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    for path in (markdown, payload):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return {"markdown": markdown, "json": payload}
