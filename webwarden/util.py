"""Scope, URL, rate limiting, and redaction helpers."""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from urllib.parse import urlsplit

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

PUBLIC_SUFFIXES = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "mobi", "asia", "tel", "travel", "jobs", "cat", "museum", "aero",
    "coop", "io", "ai", "app", "dev", "cloud", "site", "online", "store",
    "tech", "xyz", "top", "club", "shop", "blog", "page", "space", "website",
    "live", "news", "media", "agency", "digital", "network", "solutions",
    "me", "tv", "cc", "ws", "fm", "gg", "to", "ly", "sh", "ac", "is", "it",
    "de", "fr", "nl", "be", "eu", "uk", "us", "ca", "au", "nz", "jp", "kr",
    "cn", "hk", "tw", "sg", "my", "ph", "th", "vn", "id", "in", "pk", "bd",
    "br", "mx", "ar", "cl", "co", "pe", "ve", "ru", "ua", "pl", "cz", "sk",
    "hu", "ro", "bg", "gr", "tr", "il", "sa", "ae", "za", "ng", "ke", "eg",
    "co.id", "ac.id", "or.id", "web.id", "sch.id", "go.id", "mil.id",
    "biz.id", "my.id", "ponpes.id", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "com.sg", "com.my", "com.ph", "co.jp",
    "co.kr", "com.cn", "com.hk", "com.tw", "co.in", "com.br", "com.mx",
    "com.ar", "co.za", "com.tr", "com.sa", "co.ae", "com.ng", "co.ke",
}

SECRET_HEADERS = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
}


class ScopeError(ValueError):
    pass


class BudgetExceeded(RuntimeError):
    pass


def strip_host(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if "://" in value:
        host = urlsplit(value).hostname or ""
    else:
        host = value.split("/")[0].split("?")[0]
        if host.startswith("["):
            host = host.split("]")[0].lstrip("[")
        else:
            host = host.split(":")[0]
    return host.rstrip(".").lower()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_hostname(host: str) -> bool:
    if len(host) > 253 or "." not in host:
        return False
    return all(LABEL_RE.match(label) for label in host.split("."))


def normalize_target(value: str) -> str:
    host = strip_host(value)
    if not host:
        raise ScopeError("empty target")
    if is_ip(host):
        raise ScopeError(
            "target must be a domain name, not an IP address "
            "(use the bug bounty domain within your scope)"
        )
    if host in PUBLIC_SUFFIXES or not _valid_hostname(host):
        raise ScopeError(f"refusing to scan {host!r}: not a registrable domain")
    return host


def normalize_scope(value: str) -> str:
    raw = value.strip()
    wildcard = raw.startswith("*.")
    host = strip_host(raw[2:] if wildcard else raw)
    if not host:
        raise ScopeError("empty scope entry")
    if is_ip(host):
        return host
    if host in PUBLIC_SUFFIXES or not _valid_hostname(host):
        raise ScopeError(f"refusing scope {value!r}: not a registrable domain")
    return ("*." if wildcard else "") + host


def in_scope(host: str, scopes: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    if is_ip(host):
        return host in scopes
    for scope in scopes:
        scope = scope.lower()
        if is_ip(scope):
            continue
        if scope.startswith("*."):
            base = scope[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == scope or host.endswith("." + scope):
            return True
    return False


def host_of(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    host = parsed.hostname
    return host.lower().rstrip(".") if host else None


def strip_fragment(url: str) -> str:
    parsed = urlsplit(url)
    return parsed._replace(fragment="").geturl()


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        str(name): ("<redacted>" if str(name).lower() in SECRET_HEADERS else str(value))
        for name, value in headers.items()
    }


def is_secret_header(name: str) -> bool:
    return name.lower() in SECRET_HEADERS


def format_headers(headers: dict[str, str], limit: int = 25) -> str:
    lines = []
    for index, (name, value) in enumerate(redact_headers(headers).items()):
        if index >= limit:
            lines.append("...")
            break
        lines.append(f"{name}: {value}")
    return "\n".join(lines)


def sha_prefix(data: bytes, length: int = 16) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()[:length]


def content_looks_like_login(text: str) -> bool:
    lowered = text[:20000].lower()
    markers = (
        "type=\"password\"", "type='password'", "name=\"password\"",
        "sign in", "log in", "login", "masuk", "unauthorized", "forbidden",
        "access denied", "<form",
    )
    return any(marker in lowered for marker in markers)


def similar_length(first: int, second: int, tolerance: float = 0.15) -> bool:
    if first <= 0 or second <= 0:
        return False
    return abs(first - second) / max(first, second) <= tolerance


class RateLimiter:
    """Per-host pacing that still allows concurrency across hosts."""

    def __init__(self, rate: float) -> None:
        self.rate = max(0.1, float(rate))
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}

    def wait(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            at = max(now, self._next.get(key, now))
            self._next[key] = at + 1.0 / self.rate
            delay = at - now
        if delay > 0:
            time.sleep(delay)


class Budget:
    """Global request budget so a run cannot turn into a mass scan."""

    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self.used = 0
        self._lock = threading.Lock()

    def take(self, count: int = 1) -> None:
        with self._lock:
            if self.used + count > self.limit:
                raise BudgetExceeded(
                    f"request budget of {self.limit} exhausted; stopping to stay gentle"
                )
            self.used += count

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.limit - self.used)


def parse_ports(spec: str | None, default: list[int], limit: int = 2000) -> list[int]:
    if not spec:
        return sorted(set(default))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            first, last = int(start), int(end)
            if first > last:
                first, last = last, first
            if last - first > 5000:
                raise ValueError("port range too large")
            ports.update(range(first, last + 1))
        else:
            ports.add(int(part))
    ports = {port for port in ports if 1 <= port <= 65535}
    if not ports:
        raise ValueError("no valid ports")
    if len(ports) > limit:
        raise ValueError(f"too many ports (max {limit})")
    return sorted(ports)


def sanitize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-") or "target"


def utc_stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
