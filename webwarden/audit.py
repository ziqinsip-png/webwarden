"""Offline AI-assisted audit.

Two providers are supported:

* ``local``  - deterministic correlation and risk ranking; no network at all.
* ``ollama`` - a local LLM served by Ollama on this machine. No API token and
  no cloud account are needed. The default endpoint is loopback-only so scan
  data never leaves the host.

The audit only re-ranks and explains findings that were already produced by
the scanners. It never invents vulnerabilities and never creates exploitation
instructions.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import (
    CONFIDENCE_MANUAL,
    CveRef,
    Finding,
    ScanResult,
    SEVERITY_ORDER,
)
from .util import iso_now

SEVERITY_WEIGHT = {
    "critical": 28.0,
    "high": 16.0,
    "medium": 6.0,
    "low": 1.2,
    "info": 0.2,
}

CATEGORY_IMPACT = {
    "takeover": "A dangling third-party hostname can be claimed by an unrelated party.",
    "exposure": "Files that should not be public may disclose configuration or secrets.",
    "access-control": "A response differs by user, which may indicate missing authorization.",
    "access-control-bypass": "A protected path may be reachable without the expected guard.",
    "cors": "Cross-origin reads may expose data to an untrusted site.",
    "redirect": "Redirects can be abused for phishing that appears to originate from the target.",
    "tls": "Transport or certificate weakness enables interception or trains users to ignore warnings.",
    "cookies": "Weak cookie flags increase the impact of script injection or plaintext transport.",
    "tokens": "Session or authentication tokens issued over plaintext HTTP can be read and replayed on the network path.",
    "secrets": "A live credential in client-delivered content can be reused by anyone who reads it.",
    "url-tokens": "Credentials in URLs leak through logs, Referer headers, and browser history.",
    "headers": "Missing browser defenses make client-side attacks easier to execute.",
    "idor": "Object identifiers may be enumerable across accounts.",
    "sqli": "Injected input changes database behavior, which can lead to data disclosure or authentication bypass.",
    "ssti": "Server-side template evaluation runs injected expressions inside the rendering engine.",
    "xss": "Reflected markup lets an attacker run script in a victim's browser on the site origin.",
    "lfi": "Path traversal reads local files that should never be served.",
    "backdoor": "A reachable web shell gives command execution to anyone who finds it.",
    "ssrf": "A server-side fetch driven by a parameter can reach internal services if no allowlist is enforced.",
    "crlf": "CR/LF in a value that reaches response headers allows header or response injection.",
    "graphql": "An introspectable schema tells an attacker every type, field, and mutation to target.",
}

SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|"
    r"cookie|session|set-cookie)\s*[:=]\s*[^\s,;]{3,}"
)


def _is_id(lang: str | None) -> bool:
    return (lang or "en").lower().startswith("id")


def _L(lang: str | None, english: str, indonesian: str) -> str:
    return indonesian if _is_id(lang) else english


CATEGORY_IMPACT_ID = {
    "takeover": "Hostname pihak ketiga yang menggantung bisa diklaim pihak lain.",
    "exposure": "File yang seharusnya tidak publik dapat membocorkan konfigurasi "
                "atau secret.",
    "access-control": "Respons berbeda antar pengguna, bisa menandakan otorisasi "
                      "yang hilang.",
    "access-control-bypass": "Path terlindungi mungkin bisa dijangkau tanpa guard "
                             "yang seharusnya.",
    "cors": "Pembacaan lintas origin dapat mengekspos data ke situs tak tepercaya.",
    "redirect": "Redirect bisa disalahgunakan untuk phishing yang seolah berasal "
                "dari target.",
    "tls": "Kelemahan transport atau sertifikat memungkinkan intersepsi atau "
           "melatih pengguna mengabaikan peringatan.",
    "cookies": "Flag cookie yang lemah memperbesar dampak script injection atau "
               "transport plaintext.",
    "tokens": "Token sesi/autentikasi yang dikirim lewat HTTP plaintext bisa "
              "dibaca dan di-replay di jalur jaringan.",
    "secrets": "Kredensial aktif di konten sisi klien bisa dipakai ulang siapa pun "
               "yang membacanya.",
    "url-tokens": "Kredensial di URL bocor lewat log, header Referer, dan riwayat "
                  "browser.",
    "headers": "Hilangnya pertahanan browser memudahkan serangan sisi klien.",
    "idor": "Identifier objek mungkin bisa dienumerasi antar akun.",
    "sqli": "Input terinjeksi mengubah perilaku database, bisa berujung pada "
            "kebocoran data atau bypass autentikasi.",
    "ssti": "Evaluasi template server menjalankan ekspresi terinjeksi di dalam "
            "engine rendering.",
    "xss": "Markup yang direfleksikan memungkinkan penyerang menjalankan skrip di "
           "browser korban pada origin situs.",
    "lfi": "Path traversal membaca file lokal yang seharusnya tidak pernah "
           "disajikan.",
    "backdoor": "Web shell yang bisa dijangkau memberi eksekusi perintah kepada "
                "siapa pun yang menemukannya.",
    "ssrf": "Fetch server-side yang dikendalikan parameter bisa menjangkau layanan "
            "internal bila tidak ada allowlist.",
    "crlf": "CR/LF pada nilai yang masuk ke header respons memungkinkan injeksi "
            "header atau respons.",
    "graphql": "Skema yang bisa diintrospeksi memberi penyerang semua tipe, field, "
               "dan mutation untuk diserang.",
}

CHAIN_TEXT_ID = {
    "Session token issued over plaintext HTTP": {
        "title": "Token sesi diterbitkan lewat HTTP plaintext",
        "why": "Respons HTTP menetapkan cookie token, jadi pengamat di jalur "
               "jaringan bisa membacanya selama masih valid; dampaknya bergantung "
               "pada klaim dan masa berlaku token.",
        "next_step": "Pastikan scope dan expiry cookie, rotasi token yang melewati "
                     "jaringan tak tepercaya, lalu paksa HTTPS dengan cookie "
                     "Secure/HttpOnly/SameSite.",
    },
    "Credential delivered to every visitor": {
        "title": "Kredensial dikirim ke setiap pengunjung",
        "why": "Nilai berbentuk kredensial yang dikirim di HTML atau JavaScript "
               "bisa dibaca siapa pun. Dampaknya bergantung pada hak akses nyata "
               "kredensial itu, yang tidak pernah diuji tool ini.",
        "next_step": "Pastikan kredensial milik target dan masih aktif tanpa "
                     "memakainya untuk aksi istimewa, lalu rotasi dan laporkan "
                     "eksposurnya beserta scope-nya.",
    },
    "Credential-like parameter exposed in URLs": {
        "title": "Parameter mirip kredensial terekspos di URL",
        "why": "URL dicatat di log dan diteruskan lewat header Referer, jadi "
               "kredensial di query string bisa bocor tanpa penyerang jaringan.",
        "next_step": "Pastikan parameter menerima kredensial aktif, lalu gunakan "
                     "tautan sekali pakai berumur pendek dan jauhkan kredensial "
                     "dari query string.",
    },
    "Cookie exposure over plaintext HTTP": {
        "title": "Cookie terekspos lewat HTTP plaintext",
        "why": "Cookie tanpa Secure bisa dikirim lewat HTTP pada host yang tidak "
               "melakukan redirect, sehingga penyerang jaringan bisa menangkapnya.",
        "next_step": "Pastikan cookie sesi memang diterbitkan lewat HTTP, lalu "
                     "wajibkan HTTPS dan set Secure/HttpOnly/SameSite.",
    },
    "Certificate warnings plus no HTTPS redirect": {
        "title": "Peringatan sertifikat plus tidak ada redirect HTTPS",
        "why": "Pengguna didorong mengabaikan peringatan sertifikat, membuat "
               "intersepsi kredensial lebih mungkin terjadi.",
        "next_step": "Perbaiki sertifikat agar cocok dengan setiap vhost, lalu "
                     "redirect semua trafik HTTP ke HTTPS.",
    },
    "Directory listing next to sensitive files": {
        "title": "Directory listing di dekat file sensitif",
        "why": "Direktori yang bisa dibaca bisa mengungkap backup, log, atau file "
               "konfigurasi tambahan yang tidak diprobe satu per satu.",
        "next_step": "Enumerasi listing secara manual di dalam scope berizin lalu "
                     "matikan autoindex.",
    },
    "Permissive CORS with weak cookie flags": {
        "title": "CORS permisif dengan flag cookie lemah",
        "why": "Bila kredensial diizinkan lintas origin dan cookie tanpa flag "
               "pelindung, data terautentikasi mungkin bisa dibaca di tempat lain.",
        "next_step": "Verifikasi pasangan Access-Control-Allow-Origin/Credentials "
                     "yang tepat dengan request lintas origin jinak.",
    },
    "Trusted-domain open redirect": {
        "title": "Open redirect di domain tepercaya",
        "why": "Open redirect di domain tepercaya berguna untuk tautan phishing "
               "yang meyakinkan dan bisa melewati filter tautan naif.",
        "next_step": "Pastikan target redirect sepenuhnya dikendalikan penyerang, "
                     "lalu batasi ke allowlist.",
    },
    "Hostname takeover candidate": {
        "title": "Kandidat takeover hostname",
        "why": "CNAME menggantung yang masih menyajikan halaman not-found provider "
               "dapat memungkinkan pihak lain mengklaim hostname.",
        "next_step": "Pastikan resource provider belum diklaim, lalu hapus CNAME "
                     "atau klaim ulang resource. Jangan mengklaimnya sendiri.",
    },
    "Reachable web shell on the target": {
        "title": "Web shell yang bisa dijangkau di target",
        "why": "Skrip yang disajikan memetakan parameter request ke fungsi eksekusi "
               "perintah, jadi siapa pun yang menemukan path-nya bisa bertindak "
               "sebagai user web server.",
        "next_step": "Perlakukan sebagai insiden aktif: amankan file bukti, "
                     "beri tahu pemilik, dan jangan pernah mengirim command ke "
                     "shell tersebut.",
    },
    "SQL injection toward the application database": {
        "title": "SQL injection menuju database aplikasi",
        "why": "Parameter mengubah query yang dijalankan server; host yang sama "
               "lebih berbahaya bila juga menyajikan dump atau file konfigurasi "
               "berisi kredensial database.",
        "next_step": "Laporkan parameter dan bukti diferensialnya. Ekstraksi baris "
                     "butuh izin program eksplisit.",
    },
    "Template injection on a path that can reach the runtime": {
        "title": "Template injection pada jalur yang bisa mencapai runtime",
        "why": "Engine mengevaluasi ekspresi dari input request, dan sebagian besar "
               "engine mengekspos gadget dari object graph menuju eksekusi "
               "perintah. Hanya aritmetika yang dievaluasi.",
        "next_step": "Pastikan engine dan versinya, lalu laporkan ekspresi yang "
                     "dievaluasi; jangan mencoba akses runtime.",
    },
    "Path traversal reaching configuration and credential files": {
        "title": "Path traversal mencapai file konfigurasi dan kredensial",
        "why": "Parameter menyelesaikan path di luar web root, jadi file yang bisa "
               "dibuka user web menjadi terbaca; log request di host yang sama "
               "akan membuka jalur ke eksekusi kode, yang tidak dicoba.",
        "next_step": "Laporkan traversal beserta signature file sistem; jangan baca "
                     "secret aplikasi atau meracuni log.",
    },
    "Reflected markup next to a session script can reach": {
        "title": "Markup terefleksi di dekat sesi yang bisa dijangkau skrip",
        "why": "Parameter direfleksikan tanpa escaping, jadi tautan rekayasa bisa "
               "menjalankan skrip pada origin dan membaca apa pun yang diekspos "
               "halaman, termasuk cookie sesi tanpa HttpOnly.",
        "next_step": "Laporkan parameter dan marker yang terefleksi; eksekusi di "
                     "browser dan pencurian sesi tetap di luar scope.",
    },
    "Server-side fetch reachable toward internal services": {
        "title": "Fetch server-side bisa menjangkau layanan internal",
        "why": "Parameter menggerakkan request server-side, jadi penyerang yang "
               "mengendalikannya mungkin menjangkau layanan internal atau metadata "
               "cloud bila tidak ada allowlist. Probe hanya memakai hostname "
               ".invalid.",
        "next_step": "Pastikan allowlist tanpa menyasar alamat internal; laporkan "
                     "parameter dan bukti resolver.",
    },
    "Debug console exposing request and session data": {
        "title": "Konsol debug mengekspos data request dan sesi",
        "why": "Konsol ini menyimpan request, cookie, SQL, dan exception yang "
               "tertangkap, jadi konsol publik membocorkan materi sesi tanpa "
               "autentikasi.",
        "next_step": "Matikan konsol di produksi dan perlakukan data sesi yang "
                     "tertangkap sebagai sudah terekspos.",
    },
}


def _translate_chain(chain: dict, lang: str | None) -> dict:
    if not _is_id(lang):
        return chain
    translated = CHAIN_TEXT_ID.get(str(chain.get("title") or ""))
    if not translated:
        return chain
    return {**chain, **translated}



@dataclass
class AuditResult:
    provider: str
    model: str
    generated_at: str
    risk_score: int
    risk_band: str
    summary: str
    priorities: list[dict] = field(default_factory=list)
    chains: list[dict] = field(default_factory=list)
    manual_review: list[dict] = field(default_factory=list)
    remediation_plan: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    ai_generated: bool = False

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "generated_at": self.generated_at,
            "ai_generated": self.ai_generated,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "summary": self.summary,
            "priorities": list(self.priorities),
            "chains": list(self.chains),
            "manual_review": list(self.manual_review),
            "remediation_plan": list(self.remediation_plan),
            "next_steps": list(self.next_steps),
            "notes": list(self.notes),
        }


def _risk_score(result: ScanResult) -> tuple[int, str]:
    scored = [
        finding for finding in result.findings
        if not finding.decoy_suspected
    ]
    counts = {severity: 0 for severity in SEVERITY_WEIGHT}
    for finding in scored:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    score = 0.0
    for severity, weight in SEVERITY_WEIGHT.items():
        count = counts.get(severity, 0)
        if count:
            score += weight * (count ** 0.6)
    risky = {
        "takeover", "exposure", "access-control",
        "access-control-bypass", "cors", "redirect", "idor", "tokens", "secrets",
    }
    score += min(10.0, 2.0 * sum(
        1 for finding in scored if finding.category in risky
    ))
    score = int(round(min(100.0, score)))
    if score < 15:
        band = "low"
    elif score < 35:
        band = "moderate"
    elif score < 60:
        band = "elevated"
    else:
        band = "high"
    return score, band


def _group_priorities(result: ScanResult, limit: int = 8,
                      lang: str = "en") -> list[dict]:
    impacts = CATEGORY_IMPACT_ID if _is_id(lang) else CATEGORY_IMPACT
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in result.sorted_findings():
        if finding.decoy_suspected:
            continue
        groups.setdefault((finding.title, finding.severity), []).append(finding)
    priorities: list[dict] = []
    for index, ((title, severity), items) in enumerate(
        sorted(
            groups.items(),
            key=lambda pair: (
                SEVERITY_ORDER.get(pair[0][1], 9),
                -len(pair[1]),
                pair[0][0].lower(),
            ),
        ),
        start=1,
    ):
        if index > limit:
            break
        sample = items[0]
        why = impacts.get(
            sample.category,
            _L(lang,
               "The finding weakens a defense layer or discloses information.",
               "Temuan ini melemahkan lapisan pertahanan atau membocorkan "
               "informasi."),
        )
        if not sample.verified:
            why += _L(lang,
                      " It still needs manual confirmation before it is reported.",
                      " Masih perlu konfirmasi manual sebelum dilaporkan.")
        priorities.append({
            "rank": index,
            "title": title,
            "severity": severity,
            "category": sample.category,
            "hosts": sorted({item.host for item in items}),
            "count": len(items),
            "why": why,
            "action": sample.remediation or _L(
                lang, "Review and remediate the root cause.",
                "Tinjau dan perbaiki akar masalahnya."),
            "host": sample.host,
            "url": sample.url,
            "confidence": sample.confidence,
            "verified": sample.verified,
            "reproductions": sample.reproductions,
            "stable": sample.stable,
            "chain_ids": list(sample.chain_ids),
        })
    return priorities


def _hosts_with(result: ScanResult, predicate) -> set[str]:
    return {
        finding.host.lower()
        for finding in result.findings
        if predicate(finding)
    }


def _build_chains(result: ScanResult, lang: str = "en") -> list[dict]:
    chains: list[dict] = []
    https_weak = _hosts_with(
        result, lambda f: f.title.lower().startswith("https not enforced")
    )
    tls_weak = _hosts_with(
        result, lambda f: "tls" in f.category and "not enforced" not in f.title.lower()
    )
    cookie_weak = _hosts_with(
        result, lambda f: f.category == "cookies"
    )
    listings = _hosts_with(
        result, lambda f: "directory listing" in f.title.lower()
    )
    exposures = _hosts_with(
        result, lambda f: f.category in ("exposure", "takeover")
        and "directory listing" not in f.title.lower()
    )
    cors_weak = _hosts_with(
        result, lambda f: f.category == "cors"
    )
    redirects = _hosts_with(
        result, lambda f: f.category == "redirect"
    )
    takeovers = _hosts_with(
        result, lambda f: f.category == "takeover"
    )
    plaintext_tokens = _hosts_with(
        result, lambda f: f.category == "tokens"
    )

    if plaintext_tokens:
        chains.append({
            "title": "Session token issued over plaintext HTTP",
            "findings": ["Plaintext token exposure"],
            "hosts": sorted(plaintext_tokens),
            "why": "The HTTP response sets a token cookie, so an on-path observer "
                   "can read it while it remains valid; impact depends on the "
                   "token's claims and lifetime.",
            "next_step": "Confirm the cookie scope and expiry, rotate any token "
                         "that crossed an untrusted network, then enforce HTTPS "
                         "with Secure/HttpOnly/SameSite cookies.",
            "confidence": "hypothesis",
        })

    secrets_exposed = _hosts_with(
        result, lambda f: f.category == "secrets"
    )
    if secrets_exposed:
        chains.append({
            "title": "Credential delivered to every visitor",
            "findings": ["Secret in client-side content"],
            "hosts": sorted(secrets_exposed),
            "why": "A credential-shaped value shipped in HTML or JavaScript is "
                   "readable by anyone. The impact depends on the credential's "
                   "real privileges, which this tool never tests.",
            "next_step": "Confirm the credential belongs to the target and is live "
                         "without using it for privileged actions, then rotate it "
                         "and report the exposure plus its scope.",
            "confidence": "hypothesis",
        })
    url_tokens = _hosts_with(
        result, lambda f: f.category == "url-tokens"
    )
    if url_tokens:
        chains.append({
            "title": "Credential-like parameter exposed in URLs",
            "findings": ["Credential-like URL parameter"],
            "hosts": sorted(url_tokens),
            "why": "URLs are logged and forwarded in Referer headers, so a "
                   "credential in the query string can leak without any network "
                   "attacker.",
            "next_step": "Confirm the parameter accepts a live credential, then use "
                         "short-lived single-use links and keep credentials out of "
                         "query strings.",
            "confidence": "hypothesis",
        })

    shared = https_weak & cookie_weak
    if shared:
        chains.append({
            "title": "Cookie exposure over plaintext HTTP",
            "findings": ["HTTPS not enforced",
                         "Sensitive cookie missing security attributes"],
            "hosts": sorted(shared),
            "why": "A cookie without Secure can be sent over HTTP on a host that "
                   "does not redirect, so a network attacker can capture it.",
            "next_step": "Confirm a session cookie is actually issued over HTTP, "
                         "then require HTTPS and set Secure/HttpOnly/SameSite.",
            "confidence": "hypothesis",
        })
    if https_weak & tls_weak:
        chains.append({
            "title": "Certificate warnings plus no HTTPS redirect",
            "findings": ["HTTPS not enforced", "TLS configuration issue"],
            "hosts": sorted(https_weak & tls_weak),
            "why": "Users are encouraged to click through certificate warnings, "
                   "which makes interception of credentials more likely.",
            "next_step": "Fix the certificate to match every vhost, then redirect "
                         "all HTTP traffic to HTTPS.",
            "confidence": "hypothesis",
        })
    if listings & exposures:
        chains.append({
            "title": "Directory listing next to sensitive files",
            "findings": ["Directory listing enabled", "exposure finding"],
            "hosts": sorted(listings & exposures),
            "why": "A browsable directory can reveal additional backups, logs, or "
                   "configuration files that were not individually probed.",
            "next_step": "Enumerate the listing manually inside the authorized scope "
                         "and disable autoindex afterwards.",
            "confidence": "hypothesis",
        })
    if cors_weak & cookie_weak:
        chains.append({
            "title": "Permissive CORS with weak cookie flags",
            "findings": ["CORS finding", "Cookie missing security attributes"],
            "hosts": sorted(cors_weak & cookie_weak),
            "why": "If credentials are allowed cross-origin and the cookie lacks "
                   "protective flags, authenticated data may be readable elsewhere.",
            "next_step": "Verify the exact Access-Control-Allow-Origin/Credentials "
                         "pair with a benign cross-origin request.",
            "confidence": "hypothesis",
        })
    if redirects:
        chains.append({
            "title": "Trusted-domain open redirect",
            "findings": ["Open redirect"],
            "hosts": sorted(redirects),
            "why": "An open redirect on a trusted domain is useful for convincing "
                   "phishing links and can bypass naive link filters.",
            "next_step": "Confirm the redirect target is fully controlled by the "
                         "attacker, then restrict it to an allowlist.",
            "confidence": "hypothesis",
        })
    if takeovers:
        chains.append({
            "title": "Hostname takeover candidate",
            "findings": ["Possible subdomain takeover"],
            "hosts": sorted(takeovers),
            "why": "A dangling CNAME that still serves a provider not-found page may "
                   "allow an unrelated party to claim the hostname.",
            "next_step": "Verify the provider resource is unclaimed, then remove the "
                         "CNAME or reclaim the resource. Do not claim it yourself.",
            "confidence": "hypothesis",
        })
    shells = _hosts_with(result, lambda f: f.category == "backdoor")
    if shells:
        chains.append({
            "title": "Reachable web shell on the target",
            "findings": ["Web shell or backdoor reachable"],
            "hosts": sorted(shells),
            "why": "The served script maps request parameters onto a command-"
                   "execution function, so anyone who finds the path can act as "
                   "the web server user.",
            "next_step": "Treat it as a live incident: preserve the evidence file, "
                         "notify the owner, and never send the shell a command.",
            "confidence": "observed",
        })
    sqli = _hosts_with(result, lambda f: f.category == "sqli")
    if sqli:
        stores = _hosts_with(
            result,
            lambda f: any(marker in f.title.lower() for marker in (
                "database dump", "exposed .env", "actuator environment",
                "git config", "wordpress config backup", "php config backup")),
        )
        chains.append({
            "title": "SQL injection toward the application database",
            "findings": ["SQL injection candidate"]
                        + (["database/configuration exposure"]
                           if sqli & stores else []),
            "hosts": sorted(sqli),
            "why": "A parameter changes the query the server runs; the same host "
                   "matters more if it also serves a dump or configuration file "
                   "holding the database credentials.",
            "next_step": "Report the parameter and the differential evidence. "
                         "Extracting rows needs explicit program permission.",
            "confidence": "hypothesis",
        })
    ssti = _hosts_with(result, lambda f: f.category == "ssti")
    if ssti:
        chains.append({
            "title": "Template injection on a path that can reach the runtime",
            "findings": ["Server-side template injection"],
            "hosts": sorted(ssti),
            "why": "The engine evaluates expressions built from request input, and "
                   "most engines expose a gadget from the object graph to command "
                   "execution. Only arithmetic was evaluated.",
            "next_step": "Confirm the engine and version, then report the "
                         "evaluated expression; do not attempt runtime access.",
            "confidence": "hypothesis",
        })
    lfi = _hosts_with(result, lambda f: f.category == "lfi")
    if lfi:
        log_hosts = _hosts_with(
            result,
            lambda f: any(marker in f.title.lower() for marker in (
                "laravel log", "debug log")),
        )
        chains.append({
            "title": "Path traversal reaching configuration and credential files",
            "findings": ["Local file inclusion"]
                        + (["writable log next to the traversal"]
                           if lfi & log_hosts else []),
            "hosts": sorted(lfi),
            "why": "The parameter resolves paths outside the web root, so files the "
                   "web user can open become readable; a request log on the same "
                   "host would open a route to code execution, which was not "
                   "attempted.",
            "next_step": "Report the traversal with the system-file signature; do "
                         "not read application secrets or poison a log.",
            "confidence": "hypothesis",
        })
    xss = _hosts_with(result, lambda f: f.category == "xss")
    if xss:
        chains.append({
            "title": "Reflected markup next to a session script can reach",
            "findings": ["Reflected HTML injection"]
                        + (["Sensitive cookie missing security attributes"]
                           if xss & cookie_weak else []),
            "hosts": sorted(xss),
            "why": "A parameter is reflected unescaped, so a crafted link could run "
                   "script on the origin and read whatever the page exposes, "
                   "including a session cookie without HttpOnly.",
            "next_step": "Report the parameter and reflected marker; browser "
                         "execution and session capture stay out of scope.",
            "confidence": "hypothesis",
        })
    ssrf = _hosts_with(result, lambda f: f.category == "ssrf")
    if ssrf:
        internal = _hosts_with(
            result,
            lambda f: any(marker in f.title.lower() for marker in (
                "actuator", "aws credentials", "heap dump")),
        )
        chains.append({
            "title": "Server-side fetch reachable toward internal services",
            "findings": ["Possible SSRF"]
                        + (["internal admin/credential surface"]
                           if ssrf & internal else []),
            "hosts": sorted(ssrf),
            "why": "A parameter drives a server-side request, so an attacker who "
                   "controls it may reach internal services or cloud metadata if "
                   "no allowlist is enforced. The probe only used a .invalid "
                   "hostname.",
            "next_step": "Confirm the allowlist without targeting internal "
                         "addresses; report the parameter and the resolver "
                         "evidence.",
            "confidence": "hypothesis",
        })
    consoles = _hosts_with(
        result,
        lambda f: any(marker in f.title.lower() for marker in (
            "symfony profiler", "laravel telescope", "elmah error log",
            "asp.net trace log")),
    )
    if consoles:
        chains.append({
            "title": "Debug console exposing request and session data",
            "findings": ["Framework debug console reachable"],
            "hosts": sorted(consoles),
            "why": "These consoles persist captured requests, cookies, SQL, and "
                   "exceptions, so a public console leaks session material "
                   "without authentication.",
            "next_step": "Disable the console in production and treat captured "
                         "session data as exposed.",
            "confidence": "hypothesis",
        })
    return [_translate_chain(chain, lang) for chain in chains]


def _manual_review(result: ScanResult, lang: str = "en") -> list[dict]:
    rows: list[dict] = []
    for finding in result.sorted_findings():
        if finding.decoy_suspected:
            rows.append({
                "title": finding.title,
                "host": finding.host,
                "url": finding.url,
                "reason": (
                    _L(lang, "decoy/canary marker: ", "marker decoy/canary: ")
                    + (finding.decoy_reason or _L(
                        lang, "planted-artifact heuristic",
                        "heuristik artefak yang ditanam"))
                    + _L(
                        lang,
                        "; excluded from risk scoring until the operator confirms "
                        "it is a real issue",
                        "; dikeluarkan dari skor risiko sampai operator memastikan "
                        "itu masalah nyata")
                ),
            })
            continue
        if finding.confidence == CONFIDENCE_MANUAL or not finding.verified:
            rows.append({
                "title": finding.title,
                "host": finding.host,
                "url": finding.url,
                "reason": finding.verification
                or _L(lang, "not reproduced by the automated check",
                      "tidak tereproduksi oleh pemeriksaan otomatis"),
            })
    chains = (result.recon or {}).get("chains") or {}
    for chain in chains.get("items") or []:
        if chain.get("status") == "blocked":
            rows.append({
                "title": _L(lang, "Blocked chain: ", "Rantai terblokir: ")
                         + str(chain.get("title") or ""),
                "host": (chain.get("links") or [{}])[0].get("host", ""),
                "url": (chain.get("links") or [{}])[0].get("url", ""),
                "reason": _L(
                    lang,
                    "a link carries a decoy marker or the chain would need an "
                    "action outside the read-only boundary",
                    "ada mata rantai bermarker decoy atau rantai membutuhkan "
                    "tindakan di luar batas read-only"),
            })
        elif chain.get("status") == "partial":
            rows.append({
                "title": _L(lang, "Partial chain: ", "Rantai parsial: ")
                         + str(chain.get("title") or ""),
                "host": (chain.get("links") or [{}])[0].get("host", ""),
                "url": (chain.get("links") or [{}])[0].get("url", ""),
                "reason": _L(
                    lang,
                    "at least one link is a single observation or needs manual "
                    "confirmation",
                    "minimal satu mata rantai baru satu observasi atau perlu "
                    "konfirmasi manual"),
            })
    for finding in result.findings:
        for cve in finding.cves:
            if cve.status.startswith("candidate"):
                rows.append({
                    "title": _L(lang, "CVE candidate ", "Kandidat CVE ")
                             + str(cve.id),
                    "host": finding.host,
                    "url": finding.url,
                    "reason": _L(
                        lang,
                        "version/CPE match only; confirm the exact build and "
                        "vendor backports",
                        "hanya kecocokan versi/CPE; konfirmasi build tepat dan "
                        "backport vendor"),
                })
    return rows[:24]


def _remediation_plan(priorities: list[dict], lang: str = "en") -> list[str]:
    plan: list[str] = []
    seen: set[str] = set()
    for item in priorities:
        action = str(item.get("action") or "").strip()
        if not action or action in seen:
            continue
        seen.add(action)
        plan.append(action)
    generic = (
        [
            "Wajibkan HTTPS di setiap vhost dan jaga sertifikat cocok dengan "
            "hostname yang disajikan.",
            "Tambahkan set header defensif serta Secure/HttpOnly/SameSite pada "
            "cookie.",
            "Matikan directory listing dan hapus file backup atau konfigurasi dari "
            "web root.",
            "Uji ulang scope yang sama setelah remediasi dan bandingkan scan baru "
            "dengan yang lama.",
        ]
        if _is_id(lang)
        else [
            "Enforce HTTPS on every vhost and keep certificates matching the "
            "served hostname.",
            "Add the defensive header set and Secure/HttpOnly/SameSite on cookies.",
            "Disable directory listings and remove backup or configuration files "
            "from web roots.",
            "Re-test the same scope after remediation and compare the new scan "
            "with the old one.",
        ]
    )
    for item in generic:
        if item not in seen:
            plan.append(item)
        if len(plan) >= 9:
            break
    return plan


def _next_steps(result: ScanResult, manual: list[dict],
                lang: str = "en") -> list[str]:
    steps: list[str] = []
    recon = result.recon or {}
    bypass = recon.get("bypass") or {}
    nuclei = recon.get("nuclei") or {}
    if bypass.get("enabled") and not bypass.get("bypasses"):
        steps.append(_L(
            lang,
            "The fixed 401/403 variant set did not bypass the tested paths. Try "
            "manual authorization testing on the same paths with two real sessions.",
            "Set varian 401/403 tetap tidak membypass path yang diuji. Coba uji "
            "otorisasi manual pada path yang sama dengan dua sesi nyata."))
    elif not bypass.get("enabled"):
        steps.append(_L(
            lang,
            "Run again with --bypass to test the fixed read-only 401/403 variant set.",
            "Jalankan ulang dengan --bypass untuk menguji set varian 401/403 "
            "read-only."))
    if not nuclei.get("matches"):
        steps.append(_L(
            lang,
            "Template matching did not run or produced no matches. Run --nuclei on "
            "a small host subset only after confirming the extra load is acceptable.",
            "Pencocokan template tidak berjalan atau tidak ada match. Jalankan "
            "--nuclei pada subset host kecil hanya setelah memastikan beban "
            "tambahan dapat diterima."))
    uses_auth = any(
        "$SESSION_A" in command
        for finding in result.findings
        for command in finding.poc
    )
    if not uses_auth:
        steps.append(_L(
            lang,
            "Authenticated coverage is still missing. Use --auth-a/--auth-b with "
            "two authorized accounts for read-only IDOR comparison.",
            "Cakupan terautentikasi masih kurang. Gunakan --auth-a/--auth-b dengan "
            "dua akun berizin untuk perbandingan IDOR read-only."))
    if manual:
        steps.append(_L(
            lang,
            f"Manually confirm the {len(manual)} item(s) in the review list before "
            "including them in a report.",
            f"Konfirmasi manual {len(manual)} item di daftar review sebelum "
            "memasukkannya ke laporan."))
    if not any(f.severity in ("critical", "high") for f in result.findings):
        steps.append(_L(
            lang,
            "No critical/high issue was reproduced. Treat the automated result as "
            "a baseline, not as proof that the target is secure.",
            "Tidak ada isu kritis/tinggi yang tereproduksi. Anggap hasil otomatis "
            "sebagai baseline, bukan bukti target aman."))
    return steps[:6]


def _summary(result: ScanResult, score: int, band: str,
             lang: str = "en") -> str:
    counts = result.severity_counts()
    verified = sum(1 for finding in result.findings if finding.verified)
    decoys = sum(1 for finding in result.findings if finding.decoy_suspected)
    high = counts.get("critical", 0) + counts.get("high", 0)
    takeovers = sum(1 for finding in result.findings if finding.category == "takeover")
    if _is_id(lang):
        text = (
            f"Skor risiko {score}/100 ({band}). "
            f"{high} kritis/tinggi dan {counts.get('medium', 0)} sedang; "
            f"{verified}/{len(result.findings)} tereproduksi. "
        )
        if takeovers:
            text += (f"{takeovers} kemungkinan takeover hostname perlu konfirmasi "
                     "manual. ")
        if decoys:
            text += (f"{decoys} temuan membawa marker decoy/canary dan dikeluarkan "
                     "dari skor risiko. ")
        text += ("Audit ini hanya memprioritaskan temuan yang teramati; ia tidak "
                 "menciptakan kerentanan baru atau membuktikan exploitability.")
        return text
    text = (
        f"Risk score {score}/100 ({band}). "
        f"{high} critical/high and {counts.get('medium', 0)} medium finding(s); "
        f"{verified}/{len(result.findings)} reproduced. "
    )
    if takeovers:
        text += f"{takeovers} possible hostname takeover(s) need manual confirmation. "
    if decoys:
        text += (
            f"{decoys} finding(s) carry decoy/canary markers and are excluded "
            "from the risk score. "
        )
    text += (
        "This audit only prioritizes observed findings; it does not create new "
        "vulnerabilities or prove exploitability."
    )
    return text


def heuristic_audit(result: ScanResult, lang: str = "en") -> AuditResult:
    score, band = _risk_score(result)
    priorities = _group_priorities(result, lang=lang)
    manual = _manual_review(result, lang)
    chains = (result.recon or {}).get("chains") or {}
    notes = ([
        "Provider lokal: dihitung di mesin ini tanpa panggilan jaringan.",
        "Rantai adalah hipotesis untuk diverifikasi, bukan exploit terkonfirmasi.",
    ] if _is_id(lang) else [
        "Local provider: computed on this machine with no network calls.",
        "Chains are hypotheses to verify, not confirmed exploits.",
    ])
    if chains.get("items"):
        notes.append(_L(
            lang,
            "Evidence-linked chains: "
            f"{chains.get('observed', 0)} observed, "
            f"{chains.get('partial', 0)} partial, "
            f"{chains.get('blocked', 0)} blocked (decoy or read-only boundary).",
            "Rantai berbasis bukti: "
            f"{chains.get('observed', 0)} teramati, "
            f"{chains.get('partial', 0)} parsial, "
            f"{chains.get('blocked', 0)} terblokir (decoy atau batas read-only)."))
    bundles = (result.recon or {}).get("bundles") or {}
    if bundles.get("drift") or bundles.get("missing_chunks"):
        notes.append(_L(
            lang,
            "Build-artifact drift observed on "
            f"{bundles.get('hosts_checked', 0)} host(s): "
            f"{bundles.get('drift', 0)} drift signal(s), "
            f"{bundles.get('missing_chunks', 0)} missing chunk(s). Drift is a "
            "deployment signal, not a vulnerability.",
            "Drift artefak build teramati pada "
            f"{bundles.get('hosts_checked', 0)} host: "
            f"{bundles.get('drift', 0)} sinyal drift, "
            f"{bundles.get('missing_chunks', 0)} chunk hilang. Drift adalah sinyal "
            "deployment, bukan kerentanan."))
    return AuditResult(
        provider="local",
        model="deterministic",
        generated_at=iso_now(),
        risk_score=score,
        risk_band=band,
        summary=_summary(result, score, band, lang),
        priorities=priorities,
        chains=_build_chains(result, lang),
        manual_review=manual,
        remediation_plan=_remediation_plan(priorities, lang),
        next_steps=_next_steps(result, manual, lang),
        notes=notes,
    )


def _scrub(text: str, limit: int = 600) -> str:
    cleaned = SECRET_RE.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:limit]


def _is_loopback(endpoint: str) -> bool:
    try:
        host = urllib.parse.urlsplit(endpoint).hostname or ""
    except ValueError:
        return False
    return host in ("127.0.0.1", "localhost", "::1")


def _http_json(url: str, payload: dict | None = None, timeout: float = 60.0) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def ollama_models(
    endpoint: str = "http://127.0.0.1:11434", timeout: float = 3.0
) -> list[str]:
    base = endpoint.rstrip("/")
    try:
        payload = _http_json(f"{base}/api/tags", timeout=timeout)
    except (OSError, ValueError, urllib.error.URLError):
        return []
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        return []
    names = []
    for item in models:
        if isinstance(item, dict) and item.get("name"):
            names.append(str(item["name"]))
    return names


def _audit_payload(
    result: ScanResult, heuristic: AuditResult, *, compact: bool = False
) -> dict:
    findings = []
    limit = 20 if compact else 60
    for finding in result.sorted_findings()[:limit]:
        findings.append({
            "title": finding.title,
            "severity": finding.severity,
            "category": finding.category,
            "host": finding.host,
            "url": finding.url,
            "description": _scrub(finding.description, limit=200 if compact else 600),
            "evidence": _scrub(finding.evidence, limit=240 if compact else 600),
            "confidence": finding.confidence,
            "verified": finding.verified,
            "reproductions": finding.reproductions,
            "stable": finding.stable,
            "decoy": finding.decoy_suspected,
            "decoy_reason": _scrub(finding.decoy_reason, 160),
            "chain_ids": list(finding.chain_ids),
            "cves": finding.cve_ids(),
        })
    chains_meta = (result.recon or {}).get("chains") or {}
    bundles = (result.recon or {}).get("bundles") or {}
    payload = {
        "target": result.target,
        "counts": result.severity_counts(),
        "risk_score": heuristic.risk_score,
        "risk_band": heuristic.risk_band,
        "validation": {
            "verified": sum(1 for finding in result.findings if finding.verified),
            "reproduced_twice": sum(
                1 for finding in result.findings
                if finding.reproductions >= 2),
            "decoys": sum(
                1 for finding in result.findings if finding.decoy_suspected),
            "chains_total": int(chains_meta.get("total") or 0),
            "chains_observed": int(chains_meta.get("observed") or 0),
            "chains_partial": int(chains_meta.get("partial") or 0),
            "chains_blocked": int(chains_meta.get("blocked") or 0),
            "bundle_drift": int(bundles.get("drift") or 0),
            "missing_chunks": int(bundles.get("missing_chunks") or 0),
            "truncated_assets": int(bundles.get("truncated_assets") or 0),
        },
        "findings": findings,
    }
    if not compact:
        payload["observed_chains"] = heuristic.chains
        payload["manual_review"] = heuristic.manual_review
        payload["evidence_chains"] = chains_meta.get("items") or []
        payload["decoys"] = [
            {
                "title": finding.title,
                "host": finding.host,
                "url": finding.url,
                "reason": _scrub(finding.decoy_reason, 200),
            }
            for finding in result.findings if finding.decoy_suspected
        ]
        payload["bundles"] = {
            "hosts_checked": int(bundles.get("hosts_checked") or 0),
            "assets_fetched": int(bundles.get("assets_fetched") or 0),
            "drift": int(bundles.get("drift") or 0),
            "missing_chunks": int(bundles.get("missing_chunks") or 0),
            "truncated_assets": int(bundles.get("truncated_assets") or 0),
            "libraries": bundles.get("libraries") or {},
            "hosts": [
                {
                    "host": entry.get("host"),
                    "frameworks": entry.get("frameworks") or [],
                    "build_ids": entry.get("build_ids") or [],
                    "drift": entry.get("drift") or [],
                    "missing": entry.get("missing") or [],
                    "truncated": entry.get("truncated") or [],
                }
                for entry in (bundles.get("hosts") or [])
            ],
        }
    return payload


AUDIT_PROMPT = """You are a senior application-security reviewer.
Audit ONLY the scanner findings provided below.

What the JSON contains:
- findings: observed issues. Each has verified, reproductions (how often an
  independent request reproduced it), stable (same body across requests), and
  decoy/decoy_reason.
- validation: counts of reproduced and decoy-flagged findings and chains.
- evidence_chains: chains assembled by the scanner from findings that already
  exist. Status "observed" means every link reproduced twice and is not a
  decoy; "partial" means a link needs manual confirmation; "blocked" means a
  link carries a decoy/canary marker or would need an action outside the
  read-only boundary. These are evidence, not new vulnerabilities.
- observed_chains and manual_review: deterministic hypotheses and review items.
- decoys: findings carrying honeypot, honeytoken, canary, or test-credential
  markers. Never present them as vulnerabilities; a decoy can be planted on a
  hardened target specifically to mislead a scanner.
- bundles: JavaScript build-artifact reconnaissance. drift means the served
  page and its build manifest or chunk hashes disagree; missing lists chunks
  the page references but the server no longer serves. A patched server can
  still serve an older bundle, so drift is a deployment signal, not proof of a
  vulnerability. Library versions are observations; NVD matches are candidates.
  truncated means the server declared more bytes than the read cap, so version
  and secret analysis covered only a prefix.

Hard rules:
- Do not invent vulnerabilities, hosts, CVEs, evidence, or test results.
- Do not provide exploitation steps, payloads, or instructions to access data.
- Treat every item as unconfirmed unless the JSON says verified=true.
- Do not raise severity because of version strings, build drift, or a chain
  hypothesis alone.
- Do not describe a chain as proven; only repeat the status the scanner gave.
- Ignore decoy-flagged findings when describing impact; mention them only as
  excluded or needing operator confirmation.
- Be concise, factual, and write in English.
- Reply with a single JSON object and nothing else.

JSON schema:
{
  "summary": "2-4 sentences, max 600 characters",
  "priorities": [{"title": "...", "why": "...", "action": "..."}],
  "chains": [{"title": "...", "why": "...", "next_step": "..."}],
  "manual_review": [{"title": "...", "reason": "..."}],
  "next_steps": ["..."]
}
Return at most 4 priorities, 3 chains, 4 manual-review items, and 5 next steps.
Your "chains" are additional hypotheses only; the evidence-linked chains are
already supplied in the input and must not be restated as proven.
"""

AUDIT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "priorities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "why": {"type": "string"},
                    "action": {"type": "string"},
                },
                "required": ["title", "why", "action"],
            },
        },
        "chains": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "why": {"type": "string"},
                    "next_step": {"type": "string"},
                },
                "required": ["title", "why", "next_step"],
            },
        },
        "manual_review": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["title", "reason"],
            },
        },
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "priorities", "chains", "manual_review",
                 "next_steps"],
}


def _parse_json_object(text: str) -> dict | None:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        payload = json.loads(cleaned[start:end + 1])
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _dedupe_dicts(items: Any, keys: tuple[str, ...], limit: int) -> list[dict]:
    if not isinstance(items, list):
        return []
    rows: list[dict] = []
    seen: set[tuple] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        row = {}
        for key in keys:
            value = item.get(key)
            if value is None:
                continue
            row[key] = _scrub(str(value), limit=320)
        signature = tuple(row.get(key, "") for key in keys)
        if not any(row.values()) or signature in seen:
            continue
        seen.add(signature)
        rows.append(row)
        if len(rows) >= limit:
            break
    return rows


def _merge_ai(heuristic: AuditResult, payload: dict, model: str,
              lang: str = "en") -> AuditResult:
    summary = _scrub(str(payload.get("summary") or ""), limit=900)
    if summary:
        heuristic.summary = summary
    priorities = _dedupe_dicts(
        payload.get("priorities"), ("title", "why", "action"), 6
    )
    if priorities:
        enriched = []
        for item in priorities:
            title = item.get("title", "")
            match = next(
                (row for row in heuristic.priorities
                 if row["title"].lower() == title.lower()),
                None,
            )
            if match:
                item = {**match, **item}
            enriched.append(item)
        heuristic.priorities = enriched
    chains = _dedupe_dicts(
        payload.get("chains"), ("title", "why", "next_step"), 4
    )
    if chains:
        for item in chains:
            item["confidence"] = "hypothesis"
        heuristic.chains = chains
    manual = _dedupe_dicts(
        payload.get("manual_review"), ("title", "reason"), 6
    )
    if manual:
        heuristic.manual_review = manual
    steps = payload.get("next_steps")
    if isinstance(steps, list):
        cleaned = [
            _scrub(str(step), limit=320) for step in steps
            if str(step).strip()
        ]
        if cleaned:
            heuristic.next_steps = cleaned[:6]
    heuristic.provider = "ollama"
    heuristic.model = model
    heuristic.ai_generated = True
    heuristic.notes.append(_L(
        lang,
        f"Summary and priorities were reviewed by the local Ollama model {model}.",
        f"Ringkasan dan prioritas ditinjau oleh model Ollama lokal {model}."))
    return heuristic


def ollama_audit(
    result: ScanResult,
    heuristic: AuditResult,
    model: str | None = None,
    endpoint: str = "http://127.0.0.1:11434",
    timeout: float = 600.0,
    allow_remote: bool = False,
    lang: str = "en",
) -> AuditResult:
    if not allow_remote and not _is_loopback(endpoint):
        heuristic.notes.append(_L(
            lang,
            "Refused a non-loopback Ollama endpoint. Use --ai-allow-remote only "
            "if you accept that scan data leaves this machine.",
            "Endpoint Ollama non-loopback ditolak. Gunakan --ai-allow-remote hanya "
            "bila Anda menerima data scan keluar dari mesin ini."))
        return heuristic
    models = ollama_models(endpoint, timeout=min(5.0, timeout))
    if not models:
        heuristic.notes.append(_L(
            lang,
            "Ollama is not reachable on the configured endpoint; used the local "
            "deterministic audit instead.",
            "Ollama tidak bisa dijangkau di endpoint yang dikonfigurasi; memakai "
            "audit deterministik lokal."))
        return heuristic
    chosen = model or models[0]
    if model and model not in models:
        heuristic.notes.append(_L(
            lang,
            f"Model {model} is not installed; used {chosen} instead.",
            f"Model {model} tidak terpasang; memakai {chosen}."))
        chosen = models[0]
    prompt = AUDIT_PROMPT
    if _is_id(lang):
        prompt = prompt.replace(
            "- Be concise, factual, and write in English.",
            "- Be concise, factual, and write in Indonesian.",
        )
    prompt += "\nFindings JSON:\n" + json.dumps(
        _audit_payload(result, heuristic, compact=True), indent=2
    )
    payload = {
        "model": chosen,
        "stream": False,
        "format": AUDIT_SCHEMA,
        "messages": [{"role": "user", "content": prompt}],
        "options": {"temperature": 0.1, "num_ctx": 8192, "num_predict": 900},
    }
    try:
        response = _http_json(
            f"{endpoint.rstrip('/')}/api/chat", payload, timeout=timeout
        )
    except (OSError, ValueError, urllib.error.URLError) as exc:
        heuristic.notes.append(_L(
            lang,
            f"Ollama request failed ({exc}); used the local audit instead.",
            f"Request Ollama gagal ({exc}); memakai audit lokal."))
        return heuristic
    message = response.get("message") if isinstance(response, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    parsed = _parse_json_object(str(content or ""))
    if not parsed:
        heuristic.notes.append(_L(
            lang,
            "Ollama returned no parseable JSON; used the local audit instead.",
            "Ollama tidak mengembalikan JSON yang bisa diparse; memakai audit "
            "lokal."))
        return heuristic
    return _merge_ai(heuristic, parsed, chosen, lang)


def run_audit(
    result: ScanResult,
    provider: str = "local",
    model: str | None = None,
    endpoint: str = "http://127.0.0.1:11434",
    timeout: float = 600.0,
    allow_remote: bool = False,
    lang: str = "en",
) -> AuditResult:
    heuristic = heuristic_audit(result, lang)
    if provider == "ollama":
        return ollama_audit(
            result,
            heuristic,
            model=model,
            endpoint=endpoint,
            timeout=timeout,
            allow_remote=allow_remote,
            lang=lang,
        )
    return heuristic


def finding_from_dict(data: dict) -> Finding:
    cves = []
    for item in data.get("cves") or []:
        if not isinstance(item, dict):
            continue
        cves.append(CveRef(
            id=str(item.get("id") or ""),
            source=str(item.get("source") or ""),
            status=str(item.get("status") or ""),
            score=item.get("score"),
            severity=item.get("severity"),
            url=item.get("url"),
        ))
    return Finding(
        title=str(data.get("title") or ""),
        severity=str(data.get("severity") or "info"),
        category=str(data.get("category") or "unknown"),
        host=str(data.get("host") or ""),
        url=str(data.get("url") or ""),
        description=str(data.get("description") or ""),
        remediation=str(data.get("remediation") or ""),
        evidence=str(data.get("evidence") or ""),
        confidence=str(data.get("confidence") or CONFIDENCE_MANUAL),
        references=[str(item) for item in (data.get("references") or [])],
        verified=bool(data.get("verified")),
        verification=str(data.get("verification") or ""),
        poc=[str(item) for item in (data.get("poc") or [])],
        cves=cves,
        evidence_sha256=str(data.get("evidence_sha256") or ""),
        evidence_bytes=int(data.get("evidence_bytes") or 0),
        evidence_file=str(data.get("evidence_file") or ""),
        evidence_files=[str(item) for item in (data.get("evidence_files") or [])],
        evidence_truncated=bool(data.get("evidence_truncated")),
        reproductions=int(data.get("reproductions") or 0),
        stable=data.get("stable"),
        decoy_suspected=bool(data.get("decoy_suspected")),
        decoy_reason=str(data.get("decoy_reason") or ""),
        chain_ids=[str(item) for item in (data.get("chain_ids") or [])],
    )


def load_scan_result(path: str | Path) -> ScanResult:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError("not a webwarden scan file")
    return ScanResult(
        target=str(data.get("target") or "unknown"),
        scopes=[str(item) for item in (data.get("scopes") or [])],
        version=str(data.get("version") or ""),
        started_at=str(data.get("started_at") or ""),
        finished_at=data.get("finished_at"),
        authorized=bool(data.get("authorized", True)),
        stats=dict(data.get("stats") or {}),
        recon=dict(data.get("recon") or {}),
        findings=[
            finding_from_dict(item)
            for item in (data.get("findings") or [])
            if isinstance(item, dict)
        ],
        warnings=[str(item) for item in (data.get("warnings") or [])],
        audit=dict(data.get("audit") or {}),
    )


def render_audit_section(
    audit: dict, target: str, heading: str = "##", lang: str = "en"
) -> str:
    if not isinstance(audit, dict) or not audit:
        return ""
    lines = []
    if heading:
        lines.extend([
            f"{heading} " + _L(lang, "AI-assisted audit", "Audit berbantuan AI"),
            "",
        ])
    lines.extend([
        f"- **{_L(lang, 'Provider', 'Provider')}:** "
        f"{audit.get('provider', 'local')}"
        + (f" ({audit.get('model')})" if audit.get("model") else ""),
        f"- **{_L(lang, 'Generated', 'Dibuat')}:** "
        f"{audit.get('generated_at', '-')}",
        f"- **{_L(lang, 'Risk score', 'Skor risiko')}:** "
        f"{audit.get('risk_score', 0)}/100 "
        f"({audit.get('risk_band', _L(lang, 'unknown', 'tidak diketahui'))})",
        "",
    ])
    if audit.get("summary"):
        lines.extend([str(audit["summary"]), ""])
    priorities = audit.get("priorities") or []
    if priorities:
        lines.extend([
            "### " + _L(lang, "Priority order", "Urutan prioritas"),
            "",
            "| # | " + _L(lang, "Issue", "Temuan") + " | "
            + _L(lang, "Severity", "Severity") + " | "
            + _L(lang, "Hosts", "Host") + " | "
            + _L(lang, "Why it matters", "Kenapa penting") + " | "
            + _L(lang, "Action", "Tindakan") + " |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for item in priorities:
            hosts = item.get("hosts") or [item.get("host") or "-"]
            shown = ", ".join(str(host) for host in hosts[:4])
            if len(hosts) > 4:
                shown += _L(lang, f" (+{len(hosts) - 4} more)",
                            f" (+{len(hosts) - 4} lainnya)")
            lines.append(
                f"| {item.get('rank', '-')} | "
                f"{_cell(item.get('title'))} | "
                f"{str(item.get('severity', '-')).upper()} | "
                f"{_cell(shown)} | {_cell(item.get('why'))} | "
                f"{_cell(item.get('action'))} |"
            )
        lines.append("")
    chains = audit.get("chains") or []
    if chains:
        lines.extend([
            "### " + _L(lang, "Correlated hypotheses", "Hipotesis terkait"), ""
        ])
        for item in chains:
            lines.append(
                f"- **{_cell(item.get('title'))}** — "
                f"{_cell(item.get('why'))} "
                + _L(lang, "Next step: ", "Langkah berikutnya: ")
                + f"{_cell(item.get('next_step'))}")
        lines.append("")
        lines.append(_L(
            lang,
            "Correlation is a lead for manual verification, not proof of "
            "exploitability.",
            "Korelasi ini adalah petunjuk untuk verifikasi manual, bukan bukti "
            "exploitability."))
        lines.append("")
    manual = audit.get("manual_review") or []
    if manual:
        lines.extend([
            "### " + _L(lang, "Manual review queue", "Antrian review manual"), ""
        ])
        for item in manual:
            lines.append(
                f"- `{item.get('host') or '-'}` — {_cell(item.get('title'))}: "
                f"{_cell(item.get('reason'))}"
            )
        lines.append("")
    plan = audit.get("remediation_plan") or []
    if plan:
        lines.extend([
            "### " + _L(lang, "Remediation plan", "Rencana remediasi"), ""
        ])
        for index, item in enumerate(plan, start=1):
            lines.append(f"{index}. {item}")
        lines.append("")
    steps = audit.get("next_steps") or []
    if steps:
        lines.extend([
            "### " + _L(lang, "Suggested next steps", "Langkah berikutnya"), ""
        ])
        for item in steps:
            lines.append(f"- {item}")
        lines.append("")
    notes = audit.get("notes") or []
    if notes:
        lines.extend(["### " + _L(lang, "Audit notes", "Catatan audit"), ""])
        for item in notes:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)


def _cell(value: object) -> str:
    text = str(value if value not in (None, "") else "-")
    return text.replace("|", "\\|").replace("\n", " ")
