"""Scope-aware, rate-limited HTTP client. Only GET and HEAD are allowed."""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .util import (
    Budget,
    BudgetExceeded,
    RateLimiter,
    in_scope,
)

DEFAULT_UA = "webwarden/0.1 (+authorized bug bounty testing; GET/HEAD only)"
ALLOWED_METHODS = ("GET", "HEAD")


@dataclass
class TlsInfo:
    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    san: list[str] = field(default_factory=list)
    verify_error: str | None = None

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "cipher": self.cipher,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_after": self.not_after,
            "san": list(self.san),
            "verify_error": self.verify_error,
        }


@dataclass
class HttpResult:
    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    body: bytes = b""
    elapsed: float = 0.0
    chain: list[tuple[str, int | None]] = field(default_factory=list)
    tls: TlsInfo | None = None
    error: str | None = None
    auth_used: bool = False
    auth_skipped: str | None = None
    ok: bool = False
    truncated: bool = False

    @property
    def text(self) -> str:
        if not self.body:
            return ""
        content_type = self.headers.get("content-type", "")
        charset = "utf-8"
        for part in content_type.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip().strip("\"'")
                break
        try:
            return self.body.decode(charset, "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def final_url(self) -> str:
        return self.chain[-1][0] if self.chain else self.url


def _format_dn(pairs) -> str:
    parts = []
    for rdn in pairs or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _decode_pem_cert(pem: str) -> dict:
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        pass
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

    executable = None
    try:
        import shutil

        executable = shutil.which("openssl")
    except Exception:
        executable = None
    if not executable:
        return {}
    try:
        result = subprocess.run(
            [executable, "x509", "-noout", "-subject", "-issuer", "-enddate",
             "-ext", "subjectAltName"],
            input=pem, capture_output=True, text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    decoded: dict = {"subject": (), "issuer": (), "subjectAltName": ()}
    san: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        if line.startswith("subject="):
            decoded["subject"] = ((("subject", line.split("=", 1)[1].strip()),),)
        elif line.startswith("issuer="):
            decoded["issuer"] = ((("issuer", line.split("=", 1)[1].strip()),),)
        elif line.startswith("notAfter="):
            decoded["notAfter"] = line.split("=", 1)[1].strip()
        elif "DNS:" in line:
            for item in line.split("DNS:"):
                name = item.split(",")[0].strip()
                if name and "." in name:
                    san.append(("DNS", name))
    if san:
        decoded["subjectAltName"] = tuple(san)
    return decoded


class HttpClient:
    def __init__(
        self,
        scopes: list[str] | None = None,
        rate: float = 5.0,
        timeout: float = 8.0,
        max_bytes: int = 262144,
        budget: Budget | None = None,
        user_agent: str = DEFAULT_UA,
        auth_headers: dict[str, str] | None = None,
        auth_host: str | None = None,
        allow_auth_http: bool = False,
    ) -> None:
        self.scopes = [scope.lower() for scope in (scopes or [])]
        self.timeout = max(1.0, float(timeout))
        self.max_bytes = max(1024, int(max_bytes))
        self.budget = budget or Budget(4000)
        self.user_agent = user_agent
        self.auth_headers = dict(auth_headers or {})
        self.auth_host = (auth_host or "").lower()
        self.allow_auth_http = allow_auth_http
        self.limiter = RateLimiter(rate)
        self._tls_cache: dict[tuple[str, int], TlsInfo] = {}
        self._tls_lock = threading.Lock()

    def get(self, url: str, **kwargs) -> HttpResult:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> HttpResult:
        return self.request("HEAD", url, **kwargs)

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        follow: bool = True,
        max_redirects: int = 5,
        read_limit: int | None = None,
        max_bytes: int | None = None,
        auth: bool = False,
        auth_headers: dict[str, str] | None = None,
    ) -> HttpResult:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ValueError("webwarden only sends GET and HEAD")
        result = HttpResult(url=url)
        if not url.lower().startswith(("http://", "https://")):
            result.error = "unsupported URL scheme"
            return result

        current = url
        for hop in range(max_redirects + 1):
            parsed = urlsplit(current)
            host = (parsed.hostname or "").lower().rstrip(".")
            if not host:
                result.error = "invalid URL"
                break
            if self.scopes and not in_scope(host, self.scopes):
                result.error = f"out of scope: {host}"
                break

            request_headers = self._base_headers(headers)
            active_auth = auth_headers or self.auth_headers
            if auth and active_auth:
                if self.auth_host and host != self.auth_host:
                    result.auth_skipped = "credentials kept off non-auth hosts"
                elif parsed.scheme != "https" and not self.allow_auth_http:
                    result.auth_skipped = "credentials not sent over plain HTTP"
                else:
                    request_headers.update(active_auth)
                    result.auth_used = True

            self.limiter.wait(host)
            try:
                self.budget.take()
            except BudgetExceeded as exc:
                result.error = str(exc)
                break

            status, response_headers, cookies, body, elapsed, tls, error, \
                truncated = self._fetch(
                    method, current, request_headers, read_limit, max_bytes
                )
            result.chain.append((current, status))
            result.elapsed += elapsed
            if error:
                result.error = error
                break
            result.status = status
            result.headers = response_headers
            result.set_cookies = cookies
            result.body = body
            result.tls = tls or result.tls
            result.truncated = truncated
            result.ok = status is not None

            location = response_headers.get("location")
            if follow and status in (301, 302, 303, 307, 308) and location \
                    and hop < max_redirects:
                target = urljoin(current, location)
                target_host = (urlsplit(target).hostname or "").lower()
                if self.scopes and not in_scope(target_host, self.scopes):
                    result.headers["x-webwarden-redirect"] = target
                    break
                current = target
                if status == 303:
                    method = "GET"
                continue
            break

        if read_limit is not None and len(result.body) > read_limit:
            result.body = result.body[:read_limit]
        return result

    def _base_headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        merged = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if headers:
            merged.update(headers)
        return merged

    def _fetch(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        read_limit: int | None,
        max_bytes: int | None = None,
    ):
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        started = time.monotonic()
        connection = None
        try:
            if scheme == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = http.client.HTTPSConnection(
                    host, port, timeout=self.timeout, context=context
                )
            else:
                connection = http.client.HTTPConnection(host, port, timeout=self.timeout)
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            response_headers: dict[str, str] = {}
            cookies: list[str] = []
            for name, value in response.getheaders():
                lowered = name.lower()
                response_headers.setdefault(lowered, value)
                if lowered == "set-cookie":
                    cookies.append(value)
            limit = self.max_bytes if read_limit is None else min(self.max_bytes, read_limit)
            if max_bytes is not None:
                override = max(1024, int(max_bytes))
                limit = override if read_limit is None else min(override, read_limit)
            expected = None
            try:
                raw_length = response.getheader("Content-Length")
                if raw_length is not None:
                    expected = int(raw_length)
            except (TypeError, ValueError):
                expected = None
            raw = b"" if method == "HEAD" else response.read(limit + 1)
            body = raw[:limit]
            truncated = len(raw) > limit or bool(
                expected is not None and len(raw) < expected
            )
            tls = self._tls_info(host, port) if scheme == "https" else None
            return (
                response.status, response_headers, cookies, body,
                time.monotonic() - started, tls, None, truncated,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            return None, {}, [], b"", time.monotonic() - started, None, str(exc), False
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    def _tls_info(self, host: str, port: int) -> TlsInfo:
        key = (host.lower(), int(port))
        with self._tls_lock:
            cached = self._tls_cache.get(key)
        if cached is not None:
            return cached

        info = TlsInfo()
        der = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    info.protocol = tls.version()
                    cipher = tls.cipher()
                    info.cipher = cipher[0] if cipher else None
                    der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError, ValueError) as exc:
            info.verify_error = str(exc)

        if der:
            try:
                pem = ssl.DER_cert_to_PEM_cert(der)
                decoded = _decode_pem_cert(pem)
                info.subject = _format_dn(decoded.get("subject"))
                info.issuer = _format_dn(decoded.get("issuer"))
                info.not_after = decoded.get("notAfter")
                san = []
                for kind, value in decoded.get("subjectAltName", ()):
                    if kind == "DNS" and value not in san:
                        san.append(value)
                info.san = san[:50]
            except Exception:
                pass

        try:
            verified = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as raw:
                with verified.wrap_socket(raw, server_hostname=host) as tls:
                    tls.getpeercert()
            info.verify_error = None
        except ssl.SSLCertVerificationError as exc:
            info.verify_error = exc.verify_message or str(exc)
        except (OSError, ssl.SSLError, ValueError) as exc:
            if not info.verify_error:
                info.verify_error = str(exc)

        with self._tls_lock:
            self._tls_cache[key] = info
        return info
