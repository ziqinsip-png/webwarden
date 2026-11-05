"""WHOIS lookup with the system client and a raw port-43 fallback."""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from urllib.parse import quote

IANA_SERVER = "whois.iana.org"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _parse(text: str) -> dict:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("%", "#", ">>>")):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key and value:
            fields.setdefault(key, []).append(value)

    def first(*keys: str) -> str | None:
        for key in keys:
            values = fields.get(key)
            if values:
                return values[0]
        return None

    return {
        "fields": {key: values[:8] for key, values in fields.items()},
        "registrar": first("registrar", "sponsoring registrar", "registrar name"),
        "created": first("creation date", "created", "registered on", "registration time"),
        "updated": first("updated date", "last updated", "last modified", "changed"),
        "expires": first("registry expiry date", "expiry date", "expiration date",
                         "paid-till", "expire date"),
        "org": first("registrant organization", "registrant org", "org", "owner"),
        "country": first("registrant country", "country"),
        "name_servers": sorted({
            value.lower() for value in
            fields.get("name server", []) + fields.get("nserver", [])
        })[:10],
        "status": sorted({
            value.split()[0] for value in fields.get("domain status", [])
        })[:10],
        "emails": sorted(set(EMAIL_RE.findall(text)))[:5],
    }


def _socket_query(server: str, query: str, timeout: float, cap: int = 262144) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "replace"))
        chunks = []
        size = 0
        while size < cap:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
            size += len(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _raw_lookup(domain: str, timeout: float) -> str:
    try:
        first = _socket_query(IANA_SERVER, domain, timeout)
    except OSError as exc:
        raise RuntimeError(f"whois port 43 unreachable: {exc}") from exc
    refer = None
    for line in first.splitlines():
        if line.lower().startswith("refer:"):
            refer = line.split(":", 1)[1].strip()
            break
    if refer:
        try:
            return _socket_query(refer, domain, timeout)
        except OSError:
            return first
    return first


def lookup(domain: str, timeout: float = 20.0) -> dict:
    executable = shutil.which("whois")
    raw = ""
    error = None
    if executable:
        try:
            result = subprocess.run(
                [executable, domain],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
            raw = result.stdout or ""
            if not raw.strip() and result.stderr:
                error = result.stderr.strip()[:300]
        except (OSError, subprocess.SubprocessError) as exc:
            error = str(exc)
    if not raw.strip():
        try:
            raw = _raw_lookup(domain, min(timeout, 15.0))
        except RuntimeError as exc:
            error = error or str(exc)

    parsed = _parse(raw) if raw else {}
    parsed["query"] = domain
    parsed["error"] = error if not raw else None
    parsed["source"] = (
        "whois binary" if executable and raw and not error else
        ("port 43" if raw else "unavailable")
    )
    return parsed


def search_url(domain: str) -> str:
    return "https://www.whois.com/whois/" + quote(domain)
