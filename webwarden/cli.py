"""Command line interface for webwarden."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from . import AUTHORIZED_USE_NOTICE, __version__, licensing
from . import chains as chain_engine
from . import bundles as bundle_recon
from .access_audit import (
    NOTICE as ACCESS_NOTICE,
    AccessAuditError,
    AccessScopeError,
    assert_scope,
    audit_cross_account,
    write_access_audit,
    parse_urls as parse_object_urls,
)
from .audit import load_scan_result, ollama_models, run_audit
from .checks import Checker
from .cve import extract_versions, lookup_versions
from .diffing import compare, load_findings, write_diff
from .dnsq import Resolver
from .evidence import DEFAULT_EVIDENCE_BYTES
from .httpclient import HttpClient
from .models import Finding, ScanResult
from .netcheck import DnsIntegrity, preflight
from .nuclei import availability as nuclei_availability, run_nuclei
from .recon import (
    DEFAULT_PORTS,
    brute_subdomains,
    crawl,
    crt_sh,
    probe_hosts,
    scan_ports,
    subfinder,
)
from .report import write_report
from .takeover import detect_takeovers
from .upload_audit import (
    LAB_NOTICE,
    LabAuditError,
    LabScopeError,
    audit_lab_upload_surface,
    write_upload_audit,
)
from .util import (
    Budget,
    BudgetExceeded,
    ScopeError,
    in_scope,
    iso_now,
    normalize_scope,
    normalize_target,
    parse_ports,
    sanitize_name,
    utc_stamp,
)
from . import whoisq

AUTH_ENV = "WEBWARDEN_I_AM_AUTHORIZED"

DEFAULT_WORDS = [
    "www", "mail", "webmail", "smtp", "imap", "pop", "mx", "ns1", "ns2",
    "dns", "api", "api-dev", "api-staging", "api-prod", "app", "apps",
    "dev", "staging", "stage", "test", "testing", "qa", "uat", "demo",
    "beta", "alpha", "old", "new", "legacy", "backup", "bak", "admin",
    "administrator", "portal", "dashboard", "panel", "cpanel", "whm",
    "login", "sso", "auth", "id", "account", "accounts", "secure", "vpn",
    "remote", "gateway", "gw", "proxy", "cdn", "static", "assets", "img",
    "images", "media", "video", "files", "file", "upload", "download",
    "docs", "doc", "help", "support", "status", "health", "monitor",
    "monitoring", "grafana", "kibana", "prometheus", "metrics", "logs",
    "jenkins", "jira", "confluence", "git", "gitlab", "gitea", "ci", "cd",
    "build", "registry", "docker", "k8s", "kubernetes", "swagger", "graphql",
    "db", "database", "sql", "mysql", "postgres", "mongo", "redis", "ftp",
    "sftp", "nas", "intranet", "internal", "corp", "office", "hr", "erp",
    "crm", "shop", "store", "blog", "news", "forum", "community", "m",
    "mobile", "wap", "iot", "camera", "cctv", "printer", "router", "switch",
    "autodiscover", "autoconfig", "mailgun", "email", "newsletter", "pay",
    "payment", "checkout", "cart", "order", "orders", "invoice", "billing",
]

TOOL_CHECKS = (
    ("whois", "WHOIS records"),
    ("nmap", "port scanning (fallback: built-in)"),
    ("subfinder", "passive subdomains (fallback: crt.sh)"),
    ("openssl", "certificate decoding (fallback: Python)"),
    ("nuclei", "optional template matching (--nuclei)"),
)


LICENSED_COMMANDS = frozenset(
    {"scan", "audit", "diff", "upload-audit", "access-audit"}
)


def _say(quiet: bool, message: str) -> None:
    if not quiet:
        print(message, flush=True)


def _merge_findings(base: list[Finding], extra: list[Finding]) -> list[Finding]:
    seen = {finding.key() for finding in base}
    for finding in extra:
        if finding.key() in seen:
            continue
        seen.add(finding.key())
        base.append(finding)
    return base


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr, flush=True)


def _stamp_license(result, args) -> None:
    decision = getattr(args, "license_decision", None)
    if decision is not None:
        result.recon.setdefault("license", licensing.record(decision))


class Audit:
    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(mode=0o600, exist_ok=True)
        except OSError:
            pass

    def write(self, action: str, **details) -> None:
        record = {"ts": time.time(), "action": action, **details}
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass


def _authorized(args) -> bool:
    if getattr(args, "i_am_authorized", False):
        return True
    return os.environ.get(AUTH_ENV) == "1"


def _scope_covers(target: str, scopes: Iterable[str]) -> bool:
    if in_scope(target, list(scopes)):
        return True
    return any(scope.startswith("*.") and scope[2:] == target for scope in scopes)


def _parse_auth(value: str | None, option: str) -> dict[str, str]:
    if not value:
        return {}
    if ":" not in value:
        raise ValueError(f'{option} must look like "Header: value"')
    name, header_value = value.split(":", 1)
    name = name.strip()
    header_value = header_value.strip()
    if not name or not header_value:
        raise ValueError(f"{option} has an empty header name or value")
    lowered = name.lower()
    if lowered not in ("cookie", "authorization", "x-api-key", "x-auth-token"):
        print(f"warning: {option} uses a non-standard auth header {name!r}",
              file=sys.stderr, flush=True)
    return {name: header_value}


def _load_words(path: str | None) -> list[str]:
    if not path:
        return list(DEFAULT_WORDS)
    words: list[str] = []
    file = Path(path).expanduser()
    try:
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#") or "." in line:
                continue
            words.append(line)
    except OSError as exc:
        raise ValueError(f"cannot read wordlist: {exc}") from exc
    if not words:
        raise ValueError("wordlist is empty")
    return words[:400]


def build_parser() -> argparse.ArgumentParser:
    quickstart = (
        "QUICK START\n"
        "  One command runs recon, every read-only check, exploit-chain\n"
        "  analysis, and a local audit, then writes report.md, report.html,\n"
        "  scan.json, poc.sh, and evidence/:\n"
        "\n"
        "      webwarden scan example.com --i-am-authorized\n"
        "      webwarden scan example.com --i-am-authorized --full\n"
        "\n"
        "  More guidance:\n"
        "      webwarden -h            this overview\n"
        "      webwarden scan -h       every option, with examples\n"
        "      webwarden doctor        check DNS and local tools first\n"
        "      webwarden audit -h      re-audit a saved scan, offline\n"
        "      webwarden diff -h       compare two saved scans\n"
        "      webwarden upload-audit -h  read-only audit of a lab upload form\n"
        "      webwarden access-audit -h  two-account IDOR/BOLA check (own accounts)\n"
        "      webwarden license status   trial days left / license details\n"
        "\n"
        "  Run only on domains you own or are explicitly authorized to test.\n"
    )
    parser = argparse.ArgumentParser(
        prog="webwarden",
        description="Scoped, non-destructive web recon and bug bounty reporting.",
        epilog=quickstart + "\n" + AUTHORIZED_USE_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"webwarden {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan", help="one-shot: recon, read-only checks, report, local audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Recon, non-destructive checks, exploit-chain analysis, and a local\n"
            "audit in a single run. By default this covers subdomains, HTTP,\n"
            "headers, sensitive paths, CORS, cookies/JWT, client-side secrets,\n"
            "bundle drift, injection (SQLi/SSTI/XSS/LFI/SSRF/CRLF), backdoors,\n"
            "and subdomain takeover. Outputs report.md, report.html, scan.json,\n"
            "poc.sh, evidence/, and audit/."
        ),
        epilog=(
            "EXAMPLES\n"
            "  One command, default modules (recommended):\n"
            "      webwarden scan example.com --i-am-authorized\n"
            "\n"
            "  Everything read-only in one run (adds 401/403 bypass and\n"
            "  robots.txt path checks):\n"
            "      webwarden scan example.com --i-am-authorized --full\n"
            "\n"
            "  Explicit modules plus a free local LLM audit:\n"
            "      webwarden scan example.com --i-am-authorized --bypass \\\n"
            "          --robots-paths --ai-audit ollama --ai-model qwen2.5:3b\n"
            "\n"
            "  Recon only, no vulnerability checks:\n"
            "      webwarden scan example.com --i-am-authorized --recon-only\n"
            "\n"
            "  Extra in-scope domains or wildcards:\n"
            "      webwarden scan example.com --i-am-authorized \\\n"
            "          --scope '*.example.com' --scope api.example.net\n"
            "\n"
            "  Lighter run on a large scope:\n"
            "      webwarden scan example.com --i-am-authorized --rate 10 \\\n"
            "          --max-hosts 50 --max-requests 1500\n"
            "\n"
            "NOTES\n"
            "  Injection and backdoor checks are on by default; disable them\n"
            "  with --no-injection / --no-backdoors. --bypass, --robots-paths,\n"
            "  and --nuclei are opt-in; --full enables the first two. Nuclei\n"
            "  stays explicit because templates send their own requests.\n"
        ),
    )
    scan.add_argument("target", help="root domain in scope (e.g. example.com)")
    scan.add_argument("--i-am-authorized", action="store_true",
                      help="confirm you own the target or have written permission")
    scan.add_argument("--scope", action="append", metavar="DOMAIN",
                      help="additional in-scope domain or wildcard (repeatable)")
    scan.add_argument("--out", help="output directory for reports")
    scan.add_argument("--rate", type=float, default=5.0,
                      help="requests per second per host (default 5)")
    scan.add_argument("--timeout", type=float, default=8.0,
                      help="HTTP/DNS timeout in seconds (default 8)")
    scan.add_argument("--evidence-bytes", type=int, default=DEFAULT_EVIDENCE_BYTES,
                      help="max bytes stored verbatim per response (default 5 MiB; "
                           "0 = 64 MiB ceiling). Evidence is never redacted")
    scan.add_argument("--threads", type=int, default=6,
                      help="parallel HTTP workers (default 6, max 12)")
    scan.add_argument("--max-hosts", type=int, default=150,
                      help="maximum hosts to probe (default 150)")
    scan.add_argument("--max-requests", type=int, default=4000,
                      help="global request budget (default 4000)")
    scan.add_argument("--ports", help="ports for the apex scan, e.g. 80,443,8000-8100")
    scan.add_argument("--no-ports", action="store_true", help="skip the port scan")
    scan.add_argument("--no-brute", action="store_true",
                      help="skip DNS brute force for subdomains")
    scan.add_argument("--no-passive", action="store_true",
                      help="skip crt.sh and subfinder")
    scan.add_argument("--wordlist", help="custom subdomain wordlist")
    scan.add_argument("--recon-only", action="store_true",
                      help="recon and report only; skip vulnerability checks")
    scan.add_argument("--bypass", action="store_true",
                      help="opt-in read-only 401/403 bypass checks on sensitive "
                           "paths (path normalization and proxy headers)")
    scan.add_argument("--bypass-paths", type=int, default=4,
                      help="max 401/403 paths per host to test (default 4)")
    scan.add_argument("--bypass-variants", type=int, default=10,
                      help="max variants per path, 1-16 (default 10)")
    scan.add_argument("--robots-paths", action="store_true",
                      help="opt-in read-only GETs to robots.txt Disallow paths to "
                           "check reachability (Disallow is not access control)")
    scan.add_argument("--full", action="store_true",
                      help="enable every read-only module in one run "
                           "(adds --bypass and --robots-paths; nuclei still "
                           "requires --nuclei because templates send their own "
                           "requests)")
    scan.add_argument("--no-secrets", action="store_true",
                      help="skip client-side secret scanning of HTML/JS and "
                           "robots.txt paths")
    scan.add_argument("--lang", choices=("id", "en"), default="id",
                      help="report language: id = Bahasa Indonesia mixed with "
                           "English technical terms (default), en = English")
    scan.add_argument("--no-bundles", action="store_true",
                      help="skip JavaScript bundle and build-artifact drift "
                           "reconnaissance")
    scan.add_argument("--no-injection", action="store_true",
                      help="skip read-only SQLi/SSTI/XSS/LFI/SSRF/CRLF probes "
                           "of query parameters (signature, differential, and "
                           "marker checks only)")
    scan.add_argument("--no-backdoors", action="store_true",
                      help="skip read-only checks for common web shell and "
                           "backdoor paths")
    scan.add_argument("--pages", type=int, default=20,
                      help="max crawled pages to inspect for verbose error "
                           "pages and unauthenticated JSON endpoints "
                           "(default 20, 0 disables)")
    scan.add_argument("--ai-audit", choices=("off", "local", "ollama"),
                      default="local",
                      help="AI-assisted audit provider (default: local, fully "
                           "offline; ollama uses a free local LLM with no token)")
    scan.add_argument("--ai-model", default=None,
                      help="Ollama model name (default: first installed model)")
    scan.add_argument("--ai-endpoint", default="http://127.0.0.1:11434",
                      help="Ollama endpoint (default: loopback only)")
    scan.add_argument("--ai-timeout", type=float, default=600.0,
                      help="Ollama request timeout in seconds (default 600; "
                           "CPU-only models need several minutes)")
    scan.add_argument("--ai-allow-remote", action="store_true",
                      help="allow a non-loopback Ollama endpoint (scan data "
                           "will leave this machine)")
    scan.add_argument("--allow-intercepted", action="store_true",
                      help="continue even when DNS interception or an ISP block "
                           "page is detected (findings will not be valid)")
    scan.add_argument("--no-takeover", action="store_true",
                      help="skip read-only subdomain-takeover correlation")
    scan.add_argument("--nuclei", action="store_true",
                      help="opt-in nuclei template matching (safe tags; may send "
                           "template-defined requests)")
    scan.add_argument("--nuclei-templates",
                      help="nuclei template directory (default: detected)")
    scan.add_argument("--nuclei-timeout", type=float, default=300.0,
                      help="nuclei run timeout in seconds (default 300)")
    scan.add_argument("--nvd", dest="nvd", action="store_true", default=True,
                      help="look up NVD CVE candidates for detected versions "
                           "(default: on)")
    scan.add_argument("--no-nvd", dest="nvd", action="store_false",
                      help="disable NVD candidate lookup")
    scan.add_argument("--nvd-api-key", default=None,
                      help="NVD API key (or set NVD_API_KEY)")
    scan.add_argument("--nvd-timeout", type=float, default=20.0,
                      help="NVD request timeout in seconds (default 20)")
    scan.add_argument("--auth-a", metavar="HEADER",
                      help='session A header, e.g. "Cookie: session=..."')
    scan.add_argument("--auth-b", metavar="HEADER",
                      help='session B header for read-only IDOR comparison')
    scan.add_argument("--auth-host",
                      help="host that may receive the auth header (default: target)")
    scan.add_argument("--allow-auth-http", action="store_true",
                      help="allow sending credentials over plain HTTP (not recommended)")
    scan.add_argument("--user-agent", default=None, help="custom User-Agent")
    scan.add_argument("--quiet", action="store_true", help="only print the summary")

    doctor = sub.add_parser(
        "doctor", help="check network tools and DNS/HTTP access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "EXAMPLES\n"
            "      webwarden doctor\n"
            "      webwarden doctor --quiet\n"
            "\n"
            "Run this before a scan when DNS or tools look wrong (for example\n"
            "an ISP block page); it makes no requests to the target.\n"
        ),
    )

    doctor.add_argument("--quiet", action="store_true")

    audit = sub.add_parser(
        "audit", help="re-audit a saved scan.json without scanning again",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "EXAMPLES\n"
            "  Offline re-rank (no network, no target requests):\n"
            "      webwarden audit reports/example.com-20261029/scan.json\n"
            "\n"
            "  Same scan, local LLM summary:\n"
            "      webwarden audit reports/example.com-20261029/scan.json \\\n"
            "          --ai-audit ollama --ai-model qwen2.5:3b\n"
            "\n"
            "  Write the audit elsewhere:\n"
            "      webwarden audit scan.json --out ./audit-again\n"
            "\n"
            "A saved scan.json is written next to every report.\n"
        ),
    )
    audit.add_argument("scan_file", help="path to a saved scan.json")
    audit.add_argument("--ai-audit", choices=("local", "ollama"), default="local",
                       help="audit provider (default: local, fully offline)")
    audit.add_argument("--ai-model", default=None, help="Ollama model name")
    audit.add_argument("--ai-endpoint", default="http://127.0.0.1:11434",
                       help="Ollama endpoint (default: loopback only)")
    audit.add_argument("--ai-timeout", type=float, default=600.0,
                       help="Ollama request timeout in seconds (default 600; "
                            "CPU-only models need several minutes)")
    audit.add_argument("--ai-allow-remote", action="store_true",
                       help="allow a non-loopback Ollama endpoint")
    audit.add_argument("--out", help="output directory (default: next to scan)")
    audit.add_argument("--lang", choices=("id", "en"), default="id",
                       help="report language (default: id, Bahasa Indonesia + "
                            "English technical terms)")
    audit.add_argument("--quiet", action="store_true")

    diff = sub.add_parser(
        "diff", help="compare two saved scans for new, fixed, and persisting findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "EXAMPLES\n"
            "  Compare an older and a newer scan:\n"
            "      webwarden diff reports/example.com-old/scan.json \\\n"
            "          reports/example.com-new/scan.json\n"
            "\n"
            "  Fail a CI job when the new scan adds findings:\n"
            "      webwarden diff old/scan.json new/scan.json --fail-on-new\n"
            "\n"
            "Both arguments accept scan.json or findings.json and make no\n"
            "network requests.\n"
        ),
    )
    diff.add_argument("old", help="older scan.json or findings.json")
    diff.add_argument("new", help="newer scan.json or findings.json")
    diff.add_argument("--out", help="output directory for diff.md/diff.json")
    diff.add_argument("--fail-on-new", action="store_true",
                      help="exit 1 when the new scan contains new findings")
    diff.add_argument("--quiet", action="store_true")

    lab = sub.add_parser(
        "upload-audit",
        help="read-only upload-surface audit for an isolated lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Map the upload surface of an intentionally vulnerable lab: file\n"
            "forms, client-side accept hints, listable upload folders, exposed\n"
            ".htaccess/web.config/phpinfo, and a header-only PHP/SAPI\n"
            "fingerprint. GET/HEAD only; nothing is uploaded and no PHP runs."
        ),
        epilog=(
            "LAB GATE\n"
            "  The target must resolve to loopback, RFC1918, or link-local\n"
            "  space. Public hosts are refused even with --lab. --lab is a\n"
            "  required confirmation that the host is your own isolated lab.\n"
            "\n"
            "EXAMPLES\n"
            "      webwarden upload-audit http://127.0.0.1:8081 --lab\n"
            "      webwarden upload-audit http://10.0.0.5:8080 --lab \\\n"
            "          --out ./lab-audit\n"
        ),
    )
    lab.add_argument("target",
                     help="http(s) URL of the lab page with the upload form")
    lab.add_argument("--lab", action="store_true",
                     help="confirm this target is an isolated lab you own "
                          "(required; public hosts are still refused)")
    lab.add_argument("--out",
                     help="output directory (default: "
                          "reports/upload-audit-<host>-<stamp>)")
    lab.add_argument("--timeout", type=float, default=8.0,
                     help="HTTP timeout in seconds (default 8)")
    lab.add_argument("--lang", choices=("id", "en"), default="id",
                     help="report language (default: id, Bahasa Indonesia)")
    lab.add_argument("--quiet", action="store_true")

    access = sub.add_parser(
        "access-audit",
        help="two-session IDOR/BOLA check with operator-owned accounts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Compare one object URL between two session headers that the\n"
            "operator supplies for test accounts they own. GET/HEAD only; no\n"
            "login, no account creation, no ID enumeration, and no changes to\n"
            "sharing or permissions."
        ),
        epilog=(
            "HOW IT WORKS\n"
            "  The URL must belong to account B (the owner). The audit sends\n"
            "  the same GET with session B, session A, and (optionally) with no\n"
            "  session, then compares status, content type, byte count, and\n"
            "  SHA-256. Byte-identical data returned to A is reported as a\n"
            "  confirmed IDOR/BOLA; 401/403 is recorded as a passing control.\n"
            "\n"
            "EXAMPLES\n"
            "      webwarden access-audit https://app.example.com \\\n"
            "          --auth-a 'Cookie: session=A_TOKEN' \\\n"
            "          --auth-b 'Cookie: session=B_TOKEN' \\\n"
            "          --url https://app.example.com/sheets/42 \\\n"
            "          --url https://app.example.com/attachments/7 \\\n"
            "          --accounts-owned --i-am-authorized --out ./access\n"
            "\n"
            "  Use --urls urls.txt for a list (one B-owned URL per line).\n"
            "  Session values are never written to the report.\n"
        ),
    )
    access.add_argument("target",
                        help="base URL of the application (defines the scope)")
    access.add_argument("--auth-a", required=True, metavar="HEADER",
                        help='session header for account A, e.g. "Cookie: ..."')
    access.add_argument("--auth-b", required=True, metavar="HEADER",
                        help='session header for account B (object owner)')
    access.add_argument("--url", action="append", default=[], metavar="URL",
                        help="object URL owned by B (repeatable)")
    access.add_argument("--urls", action="append", default=[], metavar="FILE",
                        help="file with one B-owned object URL per line")
    access.add_argument("--accounts-owned", action="store_true",
                        help="confirm both sessions are test accounts you own "
                             "(required)")
    access.add_argument("--i-am-authorized", action="store_true",
                        help="confirm written permission for this scope "
                             "(required)")
    access.add_argument("--no-anon", action="store_true",
                        help="skip the anonymous (no session) request")
    access.add_argument("--out",
                        help="output directory (default: "
                             "reports/access-audit-<host>-<stamp>)")
    access.add_argument("--timeout", type=float, default=10.0,
                        help="HTTP timeout in seconds (default 10)")
    access.add_argument("--rate", type=float, default=4.0,
                        help="max requests per second per host (default 4)")
    access.add_argument("--allow-auth-http", action="store_true",
                        help="send session headers over plain HTTP (only for a "
                             "local lab on 127.0.0.1/RFC1918)")
    access.add_argument("--quiet", action="store_true")

    licensing.add_license_parser(
        sub,
        product=licensing.PRODUCT_WEBWARDEN,
        blurb=(
            f"webwarden berjalan dalam masa uji {licensing.TRIAL_DAYS} hari.\n"
            "Setelah itu kunci lisensi berbayar diperlukan.\n"
            "\n"
            "      webwarden license status      sisa hari uji coba\n"
            "      webwarden license activate KUNCI\n"
            "      webwarden license verify KUNCI"
        ),
    )
    return parser


def cmd_doctor(args) -> int:
    rows: list[tuple[str, str, str]] = []
    rows.append(("python", "ok", sys.version.split()[0]))
    rows.append(("root", "ok" if hasattr(os, "geteuid") and os.geteuid() == 0 else "info",
                 "root" if hasattr(os, "geteuid") and os.geteuid() == 0
                 else "unprivileged (connect scan still works)"))
    for tool, purpose in TOOL_CHECKS:
        path = shutil.which(tool)
        rows.append((tool, "ok" if path else "fallback", path or purpose))
    status = nuclei_availability()
    rows.append((
        "templates",
        "ok" if status.templates else "warn",
        status.templates or status.note or "not configured",
    ))
    models = ollama_models(timeout=2.0)
    rows.append((
        "ollama",
        "ok" if models else "fallback",
        ", ".join(models[:3]) if models
        else "not running; deterministic local audit still works",
    ))
    resolver = Resolver(timeout=3.0)
    try:
        addresses = resolver.query("example.com", "A")
        rows.append(("dns", "ok" if addresses else "fail",
                     ", ".join(addresses[:2]) or "no answer"))
    except Exception as exc:
        rows.append(("dns", "fail", str(exc)))
    try:
        with socket.create_connection(("crt.sh", 443), timeout=4) as _sock:
            pass
        rows.append(("crt.sh", "ok", "reachable on 443"))
    except OSError as exc:
        rows.append(("crt.sh", "warn", f"unreachable: {exc}"))
    rows.append(("scope gate", "ok", f"requires --i-am-authorized or {AUTH_ENV}=1"))

    print(f"webwarden {__version__} environment check")
    print(AUTHORIZED_USE_NOTICE)
    print("CHECK            STATUS  DETAIL")
    print("---------------  ------  -------------------------------")
    for name, status, detail in rows:
        print(f"{name:<15}  {status:<6}  {detail}")
    return 0


def cmd_scan(args) -> int:
    if args.full:
        args.bypass = True
        args.robots_paths = True
    if not _authorized(args):
        print(AUTHORIZED_USE_NOTICE)
        _error(
            "authorization not confirmed. Re-run with --i-am-authorized "
            f"or set {AUTH_ENV}=1"
        )
        return 2

    try:
        target = normalize_target(args.target)
        scopes = [normalize_scope(item) for item in (args.scope or [target])]
    except ScopeError as exc:
        _error(str(exc))
        return 2
    if not _scope_covers(target, scopes):
        _error("target is outside --scope; refusing to continue")
        return 2

    try:
        auth_a = _parse_auth(args.auth_a, "--auth-a")
        auth_b = _parse_auth(args.auth_b, "--auth-b")
        words = _load_words(args.wordlist)
    except ValueError as exc:
        _error(str(exc))
        return 2

    auth_host = (args.auth_host or target).lower().rstrip(".")
    if (auth_a or auth_b) and not in_scope(auth_host, scopes):
        _error("--auth-host is outside scope; refusing to send credentials")
        return 2
    if auth_b and not auth_a:
        _error("--auth-b requires --auth-a (needs a baseline session)")
        return 2

    try:
        ports = parse_ports(args.ports, DEFAULT_PORTS)
    except ValueError as exc:
        _error(str(exc))
        return 2

    quiet = bool(args.quiet)
    resolver = Resolver(timeout=min(max(args.timeout, 1.0), 6.0))
    _say(quiet, f"preflight checking DNS integrity for {target}")
    try:
        integrity = preflight(target, resolver)
    except (OSError, ValueError) as exc:
        integrity = DnsIntegrity(warnings=[f"DNS preflight failed: {exc}"])
    if integrity.blocked and not bool(args.allow_intercepted):
        _error(
            "DNS interception or ISP block page detected; refusing to scan "
            "(results would not describe the target)"
        )
        for reason in integrity.reasons:
            print(f"  blocked  {reason}")
        print("  hint     use a clean resolver/network or run from a VPS, then "
              "verify with a DoH lookup before retrying")
        print("  override --allow-intercepted only if you accept that the "
              "findings are invalid")
        return 3
    stamp = utc_stamp()
    outdir = Path(args.out).expanduser() if args.out else \
        Path.cwd() / f"webwarden-{sanitize_name(target)}-{stamp}"
    try:
        outdir.mkdir(parents=True, exist_ok=True)
        os.chmod(outdir, 0o700)
    except OSError as exc:
        _error(f"cannot create output directory: {exc}")
        return 1

    audit = Audit(outdir / "audit.jsonl")
    started = iso_now()
    warnings: list[str] = []
    if integrity.blocked:
        warnings.append(
            "DNS interception/ISP block page detected and overridden with "
            "--allow-intercepted: findings describe the interceptor, not the "
            "target, and must not be reported. "
            + "; ".join(integrity.reasons)
        )
    warnings.extend(integrity.warnings)
    audit.write("scan_start", target=target, scopes=scopes, authorized=True,
                dns_integrity=integrity.to_dict())

    budget = Budget(args.max_requests)
    client = HttpClient(
        scopes=scopes,
        rate=max(0.5, args.rate),
        timeout=max(2.0, args.timeout),
        budget=budget,
        user_agent=args.user_agent or "webwarden/0.1 (+authorized bug bounty testing)",
        auth_headers=auth_a,
        auth_host=auth_host,
        allow_auth_http=bool(args.allow_auth_http),
    )

    _say(quiet, f"[1/7] dns      resolving {target}")
    addresses = resolver.query(target, "A")
    addresses_v6 = resolver.query(target, "AAAA")
    if not addresses and not addresses_v6:
        www = resolver.resolve_all(f"www.{target}")
        if www:
            addresses = [item for item in www if ":" not in item]
            addresses_v6 = [item for item in www if ":" in item]
    if not addresses:
        warnings.append("no A record found; HTTP probing may fail")
    private = []
    for address in addresses:
        try:
            if ipaddress.ip_address(address).is_private:
                private.append(address)
        except ValueError:
            continue
    if private:
        warnings.append("target resolves to private addresses "
                        f"({', '.join(private)}); make sure this is your own lab")

    _say(quiet, f"[2/7] whois    querying registry")
    whois = whoisq.lookup(target, timeout=min(max(args.timeout, 5.0), 20.0))
    dns_records: dict[str, list[str]] = {}
    for record in ("NS", "MX", "TXT", "CAA"):
        dns_records[record] = resolver.query(target, record)
    dns_records["CNAME"] = resolver.query(f"www.{target}", "CNAME")

    _say(quiet, "[3/7] subs     crt.sh, subfinder, DNS brute")
    crt_names: list[str] = []
    subfinder_names: list[str] = []
    brute_names: list[str] = []
    if not args.no_passive:
        crt_names, crt_warning = crt_sh(target)
        if crt_warning:
            warnings.append(crt_warning)
        subfinder_names, subfinder_warning = subfinder(target)
        if subfinder_warning:
            warnings.append(subfinder_warning)
    if not args.no_brute:
        wildcard = resolver.wildcard(target)
        if wildcard:
            warnings.append("wildcard DNS detected; DNS brute force skipped")
        brute_names, brute_warning = brute_subdomains(
            target, resolver, words, workers=min(20, max(4, args.threads * 3)),
            wildcard=wildcard,
        )
        if brute_warning:
            warnings.append(brute_warning)

    hosts: list[str] = []

    def add_host(name: str | None) -> None:
        if not name:
            return
        name = name.lower().rstrip(".")
        if name and in_scope(name, scopes) and name not in hosts:
            hosts.append(name)

    add_host(target)
    add_host(f"www.{target}")
    for name in crt_names + subfinder_names + brute_names:
        add_host(name)
    if len(hosts) > args.max_hosts:
        warnings.append(f"host list truncated to {args.max_hosts}")
        hosts = hosts[:args.max_hosts]

    _say(quiet, f"[4/7] http     probing {len(hosts)} hosts")
    probes = probe_hosts(hosts, client, workers=min(12, max(2, args.threads)))

    san_hosts: list[str] = []
    for probe in probes:
        if probe.result and probe.result.tls:
            for name in probe.result.tls.san:
                lowered = name.lower().lstrip("*.").rstrip(".")
                if lowered and in_scope(lowered, scopes) and lowered not in hosts \
                        and lowered not in san_hosts:
                    san_hosts.append(lowered)
    san_hosts = san_hosts[:40]
    if san_hosts:
        _say(quiet, f"       san      probing {len(san_hosts)} certificate names")
        probes.extend(probe_hosts(san_hosts, client,
                                  workers=min(12, max(2, args.threads))))
        hosts.extend(san_hosts)

    crawl_data = crawl(probes, client, scopes)

    _say(quiet, "[5/7] ports    scanning the apex address")
    if args.no_ports:
        port_data = {"addresses": [], "ports": [], "skipped": "disabled with --no-ports"}
    else:
        port_data = scan_ports(target, addresses, ports, timeout=0.8)
        if port_data.get("skipped"):
            warnings.append(port_data["skipped"])

    _say(quiet, f"[6/7] checks   {len(crawl_data['urls'])} URLs")
    findings = []
    bypass_meta: dict = {
        "enabled": bool(args.bypass), "attempts": [], "bypasses": 0,
    }
    takeover_meta: dict = {
        "enabled": False, "hosts_checked": 0, "candidates": [],
        "takeovers": 0, "note": "",
    }
    header_meta: dict = {"matrix": [], "security_txt": {}}
    client_meta: dict = {
        "files_scanned": 0, "secrets": 0, "source_maps": [], "url_tokens": 0,
        "robots_paths": bool(args.robots_paths),
        "secrets_enabled": not args.no_secrets,
        "bundles_enabled": not args.no_bundles,
    }
    bundle_meta: dict = {
        "enabled": False, "hosts": [], "assets_fetched": 0, "drift": 0,
        "missing_chunks": 0, "note": "",
    }
    injection_meta: dict = {
        "enabled": False, "candidate_urls": 0, "parameters": 0, "requests": 0,
        "checks": {}, "findings": 0, "note": "",
    }
    backdoor_meta: dict = {
        "enabled": False, "hosts": 0, "paths_tested": 0, "requests": 0,
        "findings": 0, "note": "",
    }
    waf_meta: dict = {"checked_hosts": 0, "providers": [], "note": ""}
    disclosure_meta: dict = {
        "enabled": not args.recon_only,
        "page_budget": max(0, args.pages),
        "pages_scanned": 0, "fetched": 0, "errors": 0, "json": 0,
    }
    if not args.recon_only:
        checker = Checker(
            client,
            probes,
            crawl_data["urls"],
            auth_a=auth_a,
            auth_b=auth_b,
            auth_host=auth_host,
            bypass=args.bypass,
            bypass_max_paths=args.bypass_paths,
            bypass_max_variants=args.bypass_variants,
            evidence_dir=outdir / "evidence",
            evidence_bytes=args.evidence_bytes,
            robots=crawl_data["robots"],
            robots_paths=args.robots_paths,
            secrets=not args.no_secrets,
            bundles=not args.no_bundles,
            injection=not args.no_injection,
            backdoors=not args.no_backdoors,
            page_requests=max(0, args.pages),
        )
        findings = checker.run()
        if checker.bundle_meta:
            bundle_meta = checker.bundle_meta
        if checker.injection_meta:
            injection_meta = checker.injection_meta
        if checker.backdoor_meta:
            backdoor_meta = checker.backdoor_meta
        if checker.waf_meta:
            waf_meta = checker.waf_meta
        disclosure_meta.update({
            "pages_scanned": checker.pages_scanned,
            "fetched": checker.page_fetches,
            "errors": checker.error_page_hits,
            "json": checker.json_endpoint_hits,
        })
        for probe_meta in (injection_meta, backdoor_meta):
            for warning in probe_meta.get("warnings") or []:
                warnings.append(warning)
        header_meta = {
            "matrix": checker.header_matrix,
            "security_txt": checker.security_txt,
        }
        client_meta.update({
            "files_scanned": checker.secret_files,
            "secrets": len(checker.secret_hits),
            "secret_hits": checker.secret_hits,
            "source_maps": checker.source_maps,
            "url_tokens": checker.url_token_count,
        })
        bypass_meta = {
            "enabled": bool(args.bypass),
            "attempts": checker.bypass_attempts,
            "bypasses": sum(
                1 for attempt in checker.bypass_attempts
                if attempt.get("bypass")
            ),
        }
        if args.no_takeover:
            takeover_meta["note"] = "disabled with --no-takeover"
        else:
            takeover_findings, takeover_meta = detect_takeovers(
                probes, resolver, scopes
            )
            _merge_findings(findings, takeover_findings)
            if takeover_meta.get("takeovers"):
                warnings.append(
                    f"{takeover_meta['takeovers']} possible subdomain takeover(s); "
                    "verify claimability manually before reporting"
                )
    else:
        warnings.append("vulnerability checks skipped (--recon-only)")
        bypass_meta["note"] = "skipped with --recon-only"
        takeover_meta["note"] = "skipped with --recon-only"
        injection_meta["note"] = "skipped with --recon-only"
        backdoor_meta["note"] = "skipped with --recon-only"

    versions: dict = {}
    cve_meta: dict = {"components": {}, "queries": 0, "candidates": 0}
    nuclei_meta: dict = {
        "enabled": False, "installed": False, "engine": None,
        "templates": None, "targets": 0, "matches": 0, "note": "",
    }
    if not args.recon_only:
        _say(quiet, "[7/7] cve      template matches and NVD candidates")
        status = nuclei_availability(templates=args.nuclei_templates)
        nuclei_meta.update({
            "installed": status.installed,
            "engine": status.version,
            "templates": status.templates,
        })
        if args.nuclei:
            nuclei_urls = [
                probe.url for probe in probes if probe.live and probe.url
            ]
            nuclei_urls.extend(crawl_data["urls"])
            nuclei_findings, run_meta = run_nuclei(
                nuclei_urls,
                scopes,
                templates=args.nuclei_templates,
                timeout=max(30.0, args.nuclei_timeout),
                rate=max(10, min(50, int(args.rate * 5))),
            )
            nuclei_meta.update(run_meta)
            if run_meta.get("note"):
                warnings.append(run_meta["note"])
            _merge_findings(findings, nuclei_findings)
        else:
            nuclei_meta["note"] = (
                "not requested; add --nuclei for template-based CVE detection"
            )
            if status.installed and status.templates:
                warnings.append(
                    "nuclei templates are installed; add --nuclei to run them"
                )
            elif status.installed:
                warnings.append(status.note)

        if args.nvd:
            versions = extract_versions(probes)
            if not args.no_bundles and checker.bundle_reports:
                for name, info in bundle_recon.version_hints(
                        checker.bundle_reports).items():
                    versions.setdefault(name, info)
            if versions:
                nvd_findings, nvd_warnings, cve_meta = lookup_versions(
                    versions,
                    timeout=max(5.0, args.nvd_timeout),
                    api_key=args.nvd_api_key or os.environ.get("NVD_API_KEY"),
                )
                warnings.extend(nvd_warnings)
                _merge_findings(findings, nvd_findings)
            else:
                cve_meta["note"] = "no versioned components were detected"
        else:
            cve_meta["note"] = "disabled with --no-nvd"
    else:
        nuclei_meta["note"] = "skipped with --recon-only"
        cve_meta["note"] = "skipped with --recon-only"
        warnings.append("CVE enrichment skipped (--recon-only)")

    if args.auth_a and not args.allow_auth_http:
        auth_https = any(
            probe.result and probe.result.auth_used for probe in probes
        )
        if not auth_https:
            warnings.append("auth header was not sent over plain HTTP; "
                            "use https or --allow-auth-http")

    chains: list = []
    if not args.recon_only:
        chains = chain_engine.build_chains(findings, {"bundles": bundle_meta})
        chain_engine.apply_chain_ids(chains, findings)
    chain_meta = chain_engine.chains_meta(
        chains, enabled=not args.recon_only)

    subdomains = {
        "crtsh": crt_names,
        "subfinder": subfinder_names,
        "brute": brute_names,
        "san": san_hosts,
        "total": hosts,
    }
    cve_refs = [cve for finding in findings for cve in finding.cves]
    stats = {
        "subdomains": len(hosts),
        "live_hosts": sum(1 for probe in probes if probe.live),
        "open_ports": len(port_data.get("ports", [])),
        "urls": len(crawl_data["urls"]),
        "findings": len(findings),
        "verified": sum(1 for finding in findings if finding.verified),
        "cves": len(cve_refs),
        "cve_candidates": sum(
            1 for cve in cve_refs if cve.status.startswith("candidate")
        ),
        "nuclei_matches": int(nuclei_meta.get("matches") or 0),
        "bypass_attempts": len(bypass_meta.get("attempts") or []),
        "bypasses": int(bypass_meta.get("bypasses") or 0),
        "takeovers": int(takeover_meta.get("takeovers") or 0),
        "header_endpoints": len(header_meta.get("matrix") or []),
        "security_txt": sum(
            1 for entry in (header_meta.get("security_txt") or {}).values()
            if entry.get("valid")
        ),
        "client_files": int(client_meta.get("files_scanned") or 0),
        "secrets": int(client_meta.get("secrets") or 0),
        "source_maps": len(client_meta.get("source_maps") or []),
        "url_tokens": int(client_meta.get("url_tokens") or 0),
        "bundle_assets": int(bundle_meta.get("assets_fetched") or 0),
        "bundle_drift": int(bundle_meta.get("drift") or 0),
        "bundle_missing": int(bundle_meta.get("missing_chunks") or 0),
        "injection_findings": sum(
            1 for finding in findings
            if finding.category in ("sqli", "ssti", "xss", "lfi")
        ),
        "injection_requests": int(injection_meta.get("requests") or 0),
        "backdoor_findings": sum(
            1 for finding in findings if finding.category == "backdoor"),
        "backdoor_paths": int(backdoor_meta.get("paths_tested") or 0),
        "chains": len(chains),
        "chains_observed": int(chain_meta.get("observed") or 0),
        "chains_partial": int(chain_meta.get("partial") or 0),
        "chains_blocked": int(chain_meta.get("blocked") or 0),
        "decoys": sum(
            1 for finding in findings if finding.decoy_suspected),
        "requests": budget.used,
    }
    recon = {
        "addresses": {"A": addresses, "AAAA": addresses_v6},
        "dns_integrity": integrity.to_dict(),
        "dns": dns_records,
        "whois": whois,
        "subdomains": subdomains,
        "hosts": [probe.to_dict() for probe in probes],
        "ports": port_data,
        "urls": crawl_data["urls"],
        "robots": crawl_data["robots"],
        "sitemaps": crawl_data["sitemaps"],
        "components": versions,
        "nuclei": nuclei_meta,
        "nvd": cve_meta,
        "bypass": bypass_meta,
        "takeover": takeover_meta,
        "headers": header_meta,
        "client": client_meta,
        "bundles": bundle_meta,
        "injection": injection_meta,
        "backdoors": backdoor_meta,
        "waf": waf_meta,
        "disclosure": disclosure_meta,
        "chains": chain_meta,
        "ai": {
            "requested": args.ai_audit,
            "provider": None,
            "model": None,
            "note": "",
        },
    }
    result = ScanResult(
        target=target,
        scopes=scopes,
        version=__version__,
        started_at=started,
        finished_at=iso_now(),
        authorized=True,
        stats=stats,
        recon=recon,
        findings=findings,
        warnings=warnings,
    )
    if args.ai_audit == "off":
        recon["ai"]["note"] = "disabled with --ai-audit off"
    else:
        _say(quiet, "[8/8] audit    ranking findings")
        audit_result = run_audit(
            result,
            provider=args.ai_audit,
            model=args.ai_model,
            endpoint=args.ai_endpoint,
            timeout=max(5.0, args.ai_timeout),
            allow_remote=bool(args.ai_allow_remote),
            lang=getattr(args, "lang", "id"),
        )
        result.audit = audit_result.to_dict()
        stats["risk_score"] = audit_result.risk_score
        stats["risk_band"] = audit_result.risk_band
        recon["ai"].update({
            "provider": audit_result.provider,
            "model": audit_result.model,
            "risk_score": audit_result.risk_score,
            "risk_band": audit_result.risk_band,
            "note": "; ".join(audit_result.notes[:2]),
        })

    _stamp_license(result, args)
    paths = write_report(result, outdir, getattr(args, "lang", "id"))
    counts = result.severity_counts()
    audit.write(
        "scan_finished",
        hosts=stats["subdomains"],
        live_hosts=stats["live_hosts"],
        findings=stats["findings"],
        verified=stats["verified"],
        cves=stats["cves"],
        nuclei_matches=stats["nuclei_matches"],
        bypasses=stats["bypasses"],
        takeovers=stats.get("takeovers", 0),
        chains=stats.get("chains", 0),
        bundle_drift=stats.get("bundle_drift", 0),
        decoys=stats.get("decoys", 0),
        risk_score=stats.get("risk_score"),
        requests=stats["requests"],
    )

    print("")
    print(f"target      {target}")
    print(f"hosts       {stats['subdomains']} ({stats['live_hosts']} live)")
    print(f"open ports  {stats['open_ports']}")
    print(f"requests    {stats['requests']}")
    print(
        "findings    "
        + ", ".join(f"{name} {counts[name]}" for name in
                    ("critical", "high", "medium", "low", "info"))
    )
    print(f"verified    {stats['verified']}/{stats['findings']} reproduced")
    print(
        f"cves        {stats['cves']} "
        f"(template {stats['cves'] - stats['cve_candidates']}, "
        f"NVD candidates {stats['cve_candidates']})"
    )
    if result.audit:
        print(
            f"risk        {result.audit.get('risk_score', 0)}/100 "
            f"({result.audit.get('risk_band', 'unknown')}) via "
            f"{result.audit.get('provider', 'local')}"
        )
    if args.bypass:
        print(
            f"bypass      {stats['bypasses']} verified / "
            f"{stats['bypass_attempts']} paths tested"
        )
    if not args.recon_only and not args.no_secrets:
        print(
            f"client      {stats['client_files']} files scanned, "
            f"{stats['secrets']} secret hit(s), "
            f"{stats['source_maps']} source map(s), "
            f"{stats['url_tokens']} credential-like URL parameter(s)"
        )
    if not args.recon_only and not args.no_takeover:
        print(
            f"takeover    {stats.get('takeovers', 0)} candidate(s) / "
            f"{takeover_meta.get('hosts_checked', 0)} hosts checked"
        )
    if not args.recon_only and not args.no_bundles:
        print(
            f"bundles     {stats['bundle_assets']} asset(s), "
            f"{stats['bundle_drift']} drift signal(s), "
            f"{stats['bundle_missing']} missing chunk(s)"
        )
    if chains:
        print(
            f"chains      {stats['chains_observed']} observed / "
            f"{stats['chains_partial']} partial / "
            f"{stats['chains_blocked']} blocked"
        )
    if stats["decoys"]:
        print(
            f"decoys      {stats['decoys']} finding(s) carry decoy/canary "
            "markers and are not counted as impact"
        )
    if warnings:
        print("warnings")
        for warning in warnings:
            print(f"  - {warning}")
    print("")
    print(f"report      {paths['markdown']}")
    print(f"html        {paths['html']}")
    if paths.get("audit"):
        print(f"audit       {paths['audit']}")
    print(f"findings    {paths['findings']}")
    print(f"raw scan    {paths['scan']}")
    print(f"poc         {paths['poc']}")
    if findings:
        print("")
        print("top findings")
        for finding in result.sorted_findings()[:8]:
            verified = " (verified)" if finding.verified else ""
            print(f"  [{finding.severity.upper():<8}] {finding.title} — "
                  f"{finding.url}{verified}")
    print("")
    print("Review findings marked \"needs manual verification\" before submitting.")
    if not args.recon_only and not args.nuclei:
        if result.recon.get("nuclei", {}).get("templates"):
            print("For template-based CVE detection, rerun with --nuclei.")
        else:
            print("For template-based CVE detection, install templates with "
                  "`nuclei -update-templates`, then rerun with --nuclei.")
    print("")
    print("next")
    print(f"  open report   {paths['html']}")
    print(f"  re-audit      webwarden audit {paths['scan']} --ai-audit local")
    print(f"  compare later webwarden diff {paths['scan']} <new>/scan.json")
    print("  all options   webwarden scan -h")
    return 0


def cmd_audit(args) -> int:
    path = Path(args.scan_file).expanduser()
    if not path.is_file():
        _error(f"scan file not found: {path}")
        return 2
    try:
        result = load_scan_result(path)
    except (OSError, ValueError) as exc:
        _error(f"cannot read scan file: {exc}")
        return 2
    outdir = Path(args.out).expanduser() if args.out else path.parent
    quiet = bool(args.quiet)
    _say(quiet, f"auditing {result.target} ({len(result.findings)} findings)")
    audit_result = run_audit(
        result,
        provider=args.ai_audit,
        model=args.ai_model,
        endpoint=args.ai_endpoint,
        timeout=max(5.0, args.ai_timeout),
        allow_remote=bool(args.ai_allow_remote),
        lang=getattr(args, "lang", "id"),
    )
    result.audit = audit_result.to_dict()
    result.version = __version__
    result.stats["risk_score"] = audit_result.risk_score
    result.stats["risk_band"] = audit_result.risk_band
    result.recon.setdefault("ai", {}).update({
        "requested": args.ai_audit,
        "provider": audit_result.provider,
        "model": audit_result.model,
        "risk_score": audit_result.risk_score,
        "risk_band": audit_result.risk_band,
        "note": "; ".join(audit_result.notes[:2]),
    })
    _stamp_license(result, args)
    paths = write_report(result, outdir, getattr(args, "lang", "id"))
    source_evidence = path.parent / "evidence"
    target_evidence = outdir / "evidence"
    if source_evidence.is_dir() and source_evidence.resolve() != target_evidence.resolve():
        target_evidence.mkdir(parents=True, exist_ok=True)
        for item in source_evidence.iterdir():
            if item.is_file() and item.name != "index.json":
                shutil.copy2(item, target_evidence / item.name)
    counts = result.severity_counts()
    print("")
    print(f"target      {result.target}")
    print(
        "findings    "
        + ", ".join(f"{name} {counts[name]}" for name in
                    ("critical", "high", "medium", "low", "info"))
    )
    print(
        f"risk        {audit_result.risk_score}/100 "
        f"({audit_result.risk_band}) via {audit_result.provider}"
    )
    for note in audit_result.notes:
        print(f"  note      {note}")
    print(f"audit       {paths['audit']}")
    print(f"report      {paths['markdown']}")
    print(f"html        {paths['html']}")
    return 0


def cmd_diff(args) -> int:
    try:
        old_target, old_findings = load_findings(args.old)
        new_target, new_findings = load_findings(args.new)
    except (OSError, ValueError) as exc:
        _error(f"cannot read scan files: {exc}")
        return 2
    diff = compare(old_target, old_findings, new_target, new_findings)
    outdir = Path(args.out).expanduser() if args.out else (
        Path(args.new).expanduser().parent / f"diff-{utc_stamp()}"
    )
    paths = write_diff(diff, outdir)
    if not args.quiet:
        print("")
        print(f"old         {old_target} ({len(old_findings)} findings)")
        print(f"new         {new_target} ({len(new_findings)} findings)")
        print(f"new         {len(diff.new)}")
        print(f"fixed       {len(diff.fixed)}")
        print(f"persisting  {len(diff.persisting)}")
        print(f"severity    {len(diff.severity_changed)} changed")
        print("")
        for finding in diff.new[:10]:
            print(
                f"  [NEW {finding.severity.upper():<8}] {finding.title} — "
                f"{finding.url}"
            )
        print("")
        print(f"diff        {paths['markdown']}")
        print(f"json        {paths['json']}")
    if args.fail_on_new and diff.new:
        return 1
    return 0


def cmd_upload_audit(args) -> int:
    print(f"webwarden {__version__} upload-audit")
    print(LAB_NOTICE)
    print("")
    if not args.lab:
        _error("upload-audit requires --lab: it only runs on an isolated lab "
               "you own, and public hosts are refused")
        return 2
    try:
        result = audit_lab_upload_surface(args.target, timeout=args.timeout)
    except LabScopeError as exc:
        _error(str(exc))
        return 3
    except LabAuditError as exc:
        _error(str(exc))
        return 1
    paths = write_upload_audit(result, args.out,
                               getattr(args, "lang", "id"))
    findings = result["findings"]
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(
        f"{counts[severity]} {severity}"
        for severity in ("critical", "high", "medium", "low", "info")
        if counts.get(severity)
    )
    sapi = result["sapi"]
    print(f"{'target':<11} {result['target']}")
    print(f"{'lab gate':<11} loopback/private only - passed")
    print(f"{'sapi':<11} {sapi['sapi']} (header-only), "
          f"PHP {sapi['php_version'] or 'unknown'}")
    print(f"{'forms':<11} {len(result['forms'])} upload form(s)")
    print(f"{'requests':<11} {result['request_count']} GET, 0 uploads")
    print(f"{'findings':<11} {len(findings)} ({summary or 'none'})")
    print(f"{'report':<11} {paths['markdown']}")
    print(f"{'json':<11} {paths['json']}")
    if not args.quiet:
        print("")
        for finding in findings[:8]:
            print(
                f"  [{finding.severity.upper():<6}] {finding.title} - "
                f"{finding.url}"
            )
    print("")
    print("read-only   GET/HEAD only; nothing uploaded; no PHP executed")
    return 0


def cmd_access_audit(args) -> int:
    print(f"webwarden {__version__} access-audit")
    print(ACCESS_NOTICE)
    print("")
    if not args.i_am_authorized:
        _error("access-audit requires --i-am-authorized: it only tests a scope "
               "you have written permission to assess")
        return 2
    if not args.accounts_owned:
        _error("access-audit requires --accounts-owned: both sessions must be "
               "test accounts you own")
        return 2
    try:
        auth_a = _parse_auth(args.auth_a, "--auth-a")
        auth_b = _parse_auth(args.auth_b, "--auth-b")
        urls = parse_object_urls(args.url, args.urls)
    except (ValueError, AccessAuditError) as exc:
        _error(str(exc))
        return 2
    if not urls:
        _error("no object URLs supplied; use --url or --urls")
        return 2
    host = (urlsplit(args.target).hostname or "").lower()
    if not host:
        _error(f"target must be an http(s) URL: {args.target}")
        return 2
    scopes = [host]
    plain_http = [u for u in urls if urlsplit(u).scheme == "http"]
    if plain_http and not args.allow_auth_http:
        _error(f"{len(plain_http)} URL(s) use plain HTTP; credentials are held "
               "back by default. Use https, or pass --allow-auth-http for a "
               "local lab")
        return 2
    if plain_http:
        print(f"warning    session headers will be sent over plain HTTP to "
              f"{len(plain_http)} local URL(s)")
    try:
        assert_scope(urls, scopes)
    except AccessScopeError as exc:
        _error(str(exc))
        return 3
    try:
        result = audit_cross_account(
            target=args.target,
            urls=urls,
            auth_a=auth_a,
            auth_b=auth_b,
            scopes=scopes,
            timeout=args.timeout,
            rate=args.rate,
            check_anonymous=not args.no_anon,
            allow_auth_http=bool(args.allow_auth_http),
        )
    except AccessAuditError as exc:
        _error(str(exc))
        return 1
    paths = write_access_audit(result, args.out)
    counts = result.counts()
    print(f"{'target':<11} {result.target}")
    print(f"{'scope':<11} {', '.join(result.scopes)}")
    print(f"{'accounts':<11} 2 operator-owned sessions (values not shown)")
    print(f"{'objects':<11} {len(result.checks)}")
    print(f"{'requests':<11} {result.requests} GET")
    print(f"{'verdicts':<11} "
          f"{counts.get('cross-account', 0)} cross-account, "
          f"{counts.get('cross-account-partial', 0)} possible, "
          f"{counts.get('unauthenticated', 0)} unauthenticated, "
          f"{counts.get('denied', 0)} denied")
    print(f"{'report':<11} {paths['markdown']}")
    print(f"{'json':<11} {paths['json']}")
    if not args.quiet:
        print("")
        for check in result.checks[:20]:
            print(f"  [{check.severity.upper():<6}] {check.verdict:<24} "
                  f"{check.url}")
    print("")
    print("read-only   GET/HEAD only; no login; no sharing/permission changes")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["-h"]
    elif argv[0] == "help":
        argv = (argv[1:] + ["-h"]) if len(argv) > 1 else ["-h"]
    elif not argv[0].startswith("-") and argv[0] not in (
        "scan", "doctor", "audit", "diff", "upload-audit", "access-audit",
        "license",
    ):
        argv.insert(0, "scan")
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "license":
        return licensing.run_license_command(args, licensing.PRODUCT_WEBWARDEN)
    if args.command in LICENSED_COMMANDS:
        try:
            args.license_decision = licensing.enforce(
                licensing.PRODUCT_WEBWARDEN, args.command)
        except licensing.LicenseError as exc:
            _error(str(exc))
            return 3
    if args.command == "audit":
        return cmd_audit(args)
    if args.command == "diff":
        return cmd_diff(args)
    if args.command == "upload-audit":
        return cmd_upload_audit(args)
    if args.command == "access-audit":
        return cmd_access_audit(args)
    if args.command != "scan":
        parser.print_help()
        return 0
    try:
        return cmd_scan(args)
    except KeyboardInterrupt:
        _error("interrupted by user")
        return 130
    except BudgetExceeded as exc:
        _error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
