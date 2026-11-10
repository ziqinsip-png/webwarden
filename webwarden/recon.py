"""Recon: DNS, WHOIS, subdomains, HTTP probing, ports, and light crawling."""

from __future__ import annotations

import html
import json
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .dnsq import Resolver
from .httpclient import HttpClient, HttpResult
from .util import in_scope, strip_fragment

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".mp4", ".mp3",
    ".webm", ".avi", ".mov", ".exe", ".dmg", ".iso", ".apk",
}

CDN_MARKERS = (
    "cloudflare", "cloudfront", "akamai", "fastly", "azureedge",
    "herokuapp", "github.io", "netlify", "vercel", "pages.dev",
    "workers.dev", "googleusercontent", "trafficmanager",
)

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

DEFAULT_PORTS = sorted(SERVICE_NAMES)
DEFAULT_HTTP_PORTS = (80, 443, 8000, 8080, 8081, 8443, 8888, 9000)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#][^"']*)["']""", re.IGNORECASE)
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


@dataclass
class Probe:
    host: str
    url: str | None = None
    status: int | None = None
    result: HttpResult | None = None
    error: str | None = None
    title: str | None = None
    server: str | None = None
    tech: list[str] = field(default_factory=list)

    @property
    def live(self) -> bool:
        return self.status is not None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "url": self.url,
            "status": self.status,
            "title": self.title,
            "server": self.server,
            "tech": list(self.tech),
            "tls": self.result.tls.to_dict() if self.result and self.result.tls else None,
            "error": self.error,
        }


def extract_title(text: str) -> str | None:
    match = TITLE_RE.search(text or "")
    if not match:
        return None
    title = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
    return title[:160] if title else None


def detect_tech(result: HttpResult) -> list[str]:
    found: list[str] = []
    headers = {key.lower(): value for key, value in result.headers.items()}
    body = result.text[:400000].lower()
    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()

    def add(name: str) -> None:
        if name not in found:
            found.append(name)

    if "cloudflare" in server or "cf-ray" in headers:
        add("Cloudflare")
    if "nginx" in server:
        add("nginx")
    if "apache" in server:
        add("Apache")
    if "microsoft-iis" in server:
        add("IIS")
    if "php" in powered or "phpsessid" in headers.get("set-cookie", "").lower():
        add("PHP")
    if "asp.net" in powered or "x-aspnet-version" in headers or "__viewstate" in body:
        add("ASP.NET")
    if "express" in powered:
        add("Express")
    if "laravel_session" in body or "xsrf-token" in body:
        add("Laravel")
    if "wp-content" in body or "wp-json" in body:
        add("WordPress")
    if "drupal" in body:
        add("Drupal")
    if "joomla" in body:
        add("Joomla")
    if "csrftoken" in body and "django" in body:
        add("Django")
    if "__next_data__" in body or "/_next/static" in body:
        add("Next.js")
    if "data-v-" in body:
        add("Vue")
    if "react" in body and "data-reactroot" in body:
        add("React")
    if "swagger-ui" in body:
        add("Swagger UI")
    if "graphql" in body:
        add("GraphQL")
    if "jenkins" in server or "x-jenkins" in headers:
        add("Jenkins")
    if "gitlab" in body and "gitlab" in server:
        add("GitLab")
    return found[:10]


def external_get(url: str, timeout: float = 30.0, max_bytes: int = 8_000_000,
                 headers: dict[str, str] | None = None) -> bytes:
    merged = {
        "User-Agent": "webwarden/0.2 (+authorized bug bounty recon)",
        "Accept": "application/json,text/plain,*/*",
    }
    if headers:
        merged.update(headers)
    request = urllib.request.Request(url, headers=merged)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read(max_bytes)


def crt_sh(domain: str, timeout: float = 30.0) -> tuple[list[str], str | None]:
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    url = "https://crt.sh/?" + query
    try:
        payload = external_get(url, timeout=timeout)
        rows = json.loads(payload.decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return [], f"crt.sh lookup failed: {exc}"
    if not isinstance(rows, list):
        return [], "crt.sh returned an unexpected payload"

    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("name_value", "common_name"):
            value = row.get(key)
            if not value:
                continue
            for name in str(value).splitlines():
                name = name.strip().lower().lstrip("*.").rstrip(".")
                if name and in_scope(name, [domain]):
                    names.add(name)
    return sorted(names)[:2000], None


def certspotter(domain: str, timeout: float = 30.0,
                limit: int = 4000) -> tuple[list[str], str | None]:
    """Second Certificate Transparency source, independent of crt.sh."""
    url = ("https://api.certspotter.com/v1/issuances?domain="
           + urllib.parse.quote_plus(domain)
           + "&include_subdomains=true&expand=dns_names")
    try:
        rows = json.loads(external_get(url, timeout=timeout).decode(
            "utf-8", "replace").strip() or "[]")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return [], f"certspotter lookup failed: {exc}"
    if not isinstance(rows, list):
        return [], "certspotter returned an unexpected payload"

    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for value in row.get("dns_names") or []:
            name = str(value).strip().lower().lstrip("*.").rstrip(".")
            if name and in_scope(name, [domain]):
                names.add(name)
    return sorted(names)[:limit], None


def subfinder(domain: str, timeout: float = 180.0) -> tuple[list[str], str | None]:
    executable = shutil.which("subfinder")
    if not executable:
        return [], "subfinder not installed (using crt.sh + DNS brute)"
    try:
        result = subprocess.run(
            [executable, "-d", domain, "-silent", "-timeout", "15"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"subfinder failed: {exc}"
    names = {
        line.strip().lower().rstrip(".")
        for line in result.stdout.splitlines()
        if line.strip()
    }
    return sorted(name for name in names if in_scope(name, [domain]))[:2000], None


def brute_subdomains(
    domain: str,
    resolver: Resolver,
    words: list[str],
    workers: int = 20,
    wildcard: bool = False,
    limit: int = 400,
) -> tuple[list[str], str | None]:
    if wildcard:
        return [], "wildcard DNS detected; DNS brute force skipped"
    words = [word.strip().lower() for word in words if word.strip()][:limit]

    def check(word: str) -> str | None:
        candidate = f"{word}.{domain}"
        try:
            return candidate if resolver.exists(candidate) else None
        except Exception:
            return None

    found: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 40))) as pool:
        futures = {pool.submit(check, word): word for word in words}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception:
                result = None
            if result:
                found.append(result)
    return sorted(set(found)), None


def probe_hosts(hosts: list[str], client: HttpClient, workers: int = 6) -> list[Probe]:
    def probe(host: str) -> Probe:
        last_error = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            result = client.get(url)
            if result.ok and result.status is not None:
                return Probe(
                    host=host,
                    url=result.final_url,
                    status=result.status,
                    result=result,
                    title=extract_title(result.text),
                    server=result.headers.get("server"),
                    tech=detect_tech(result),
                )
            last_error = result.error or f"HTTP {result.status}"
            if result.status is not None:
                return Probe(
                    host=host,
                    url=result.final_url,
                    status=result.status,
                    result=result,
                    title=extract_title(result.text),
                    server=result.headers.get("server"),
                    tech=detect_tech(result),
                )
        return Probe(host=host, error=last_error)

    probes: list[Probe] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(probe, host) for host in hosts]
        for future in as_completed(futures):
            try:
                probes.append(future.result())
            except Exception as exc:
                probes.append(Probe(host="?", error=str(exc)))
    probes.sort(key=lambda item: (item.status is None, item.host))
    return probes


def _same_scope_url(url: str, scopes: list[str]) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower().rstrip(".")
    return bool(host) and in_scope(host, scopes)


def crawl(probes: list[Probe], client: HttpClient, scopes: list[str],
          max_hosts: int = 10) -> dict:
    urls: set[str] = set()
    robots: dict[str, list[str]] = {}
    sitemaps: list[str] = []
    errors: list[str] = []

    for probe in probes[:max_hosts]:
        if not probe.live or not probe.result:
            continue
        base = probe.result.final_url
        parsed = urlsplit(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        robots_result = client.get(urljoin(origin, "/robots.txt"))
        if robots_result.ok and robots_result.status == 200 and robots_result.text:
            disallow = []
            for line in robots_result.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        disallow.append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap = line.split(":", 1)[1].strip()
                    if sitemap:
                        sitemaps.append(sitemap)
            robots[probe.host] = sorted(set(disallow))[:50]
            for path in robots[probe.host][:20]:
                candidate = urljoin(origin, path)
                if _same_scope_url(candidate, scopes):
                    urls.add(strip_fragment(candidate))

        sitemap_result = client.get(urljoin(origin, "/sitemap.xml"))
        if sitemap_result.ok and sitemap_result.status == 200:
            for loc in LOC_RE.findall(sitemap_result.text)[:300]:
                if _same_scope_url(loc, scopes):
                    urls.add(strip_fragment(loc))

        for href in HREF_RE.findall(probe.result.text)[:300]:
            candidate = urljoin(base, href.strip())
            if not _same_scope_url(candidate, scopes):
                continue
            parsed_candidate = urlsplit(candidate)
            extension = "." + parsed_candidate.path.rsplit(".", 1)[-1].lower() \
                if "." in parsed_candidate.path.rsplit("/", 1)[-1] else ""
            if extension in STATIC_EXTENSIONS:
                continue
            urls.add(strip_fragment(candidate))

        urls.add(strip_fragment(base))

    return {
        "urls": sorted(urls)[:500],
        "robots": robots,
        "sitemaps": sorted(set(sitemaps))[:20],
        "errors": errors,
    }


def is_cdn_host(host: str) -> bool:
    lowered = host.lower()
    return any(marker in lowered for marker in CDN_MARKERS)


def _builtin_scan(ip: str, ports: list[int], timeout: float,
                  workers: int = 64) -> list[dict]:
    def check(port: int) -> int | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return port if sock.connect_ex((ip, port)) == 0 else None
        finally:
            sock.close()

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(check, port) for port in ports]
        for future in as_completed(futures):
            try:
                port = future.result()
            except Exception:
                port = None
            if port:
                open_ports.append(port)
    return [
        {"port": port, "service": SERVICE_NAMES.get(port, "unknown")}
        for port in sorted(open_ports)
    ]


def _nmap_scan(ip: str, ports: list[int], timeout: float) -> tuple[list[dict], str | None]:
    executable = shutil.which("nmap")
    if not executable:
        return [], "nmap not installed; using built-in connect scan"
    spec = ",".join(str(port) for port in ports)
    try:
        result = subprocess.run(
            [executable, "-Pn", "-n", "-sT", "--open", "-T3", "--max-rate",
             "150", "-p", spec, "-oG", "-", ip],
            capture_output=True, text=True, timeout=max(60.0, timeout), check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"nmap failed: {exc}"
    found: list[dict] = []
    for line in result.stdout.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        payload = line.split("Ports:", 1)[1]
        for item in payload.split(","):
            fields = item.strip().split("/")
            if len(fields) >= 5 and fields[1] == "open":
                port = int(fields[0])
                service = fields[4] or SERVICE_NAMES.get(port, "unknown")
                found.append({"port": port, "service": service})
    if not found and result.returncode != 0:
        return [], f"nmap exited with {result.returncode}"
    return found, None


def scan_ports(
    host: str,
    addresses: list[str],
    ports: list[int],
    timeout: float = 0.8,
    prefer_nmap: bool = True,
) -> dict:
    if is_cdn_host(host):
        return {
            "addresses": [],
            "ports": [],
            "skipped": "hostname points at a shared CDN; port scanning skipped",
        }
    result = {"addresses": addresses[:2], "ports": [], "skipped": None, "note": None}
    for address in result["addresses"]:
        if ":" in address:
            continue
        warning = None
        found: list[dict] = []
        if prefer_nmap:
            found, warning = _nmap_scan(address, ports, timeout=180.0)
        if not found:
            builtin = _builtin_scan(address, ports, timeout)
            found = builtin or found
        for item in found:
            item["ip"] = address
            result["ports"].append(item)
        if warning and not result["note"]:
            result["note"] = warning
    result["ports"].sort(key=lambda item: (item["ip"], item["port"]))
    return result
