"""Preflight detection of DNS interception and ISP block pages."""

from __future__ import annotations

import http.client
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .dnsq import Resolver

BLOCK_MARKERS = (
    "safesurf",
    "biznetnetworks.com/safesurf",
    "internetpositif",
    "internet-positif",
    "trustpositif",
    "blockpage",
    "block-page",
    "rpz.",
)
DOH_RESOLVERS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)


@dataclass
class DnsIntegrity:
    blocked: bool = False
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "blocked": self.blocked,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            **self.details,
        }


def _marker(text: str) -> str | None:
    lowered = (text or "").lower()
    for marker in BLOCK_MARKERS:
        if marker in lowered:
            return marker
    return None


def _is_ipv4(value: object) -> bool:
    try:
        return isinstance(value, str) and "." in value and len(value.split(".")) == 4
    except (AttributeError, TypeError):
        return False


def _doh_a(domain: str, timeout: float) -> list[str]:
    name = urllib.parse.quote(domain.rstrip("."), safe="")
    for endpoint in DOH_RESOLVERS:
        request = urllib.request.Request(
            f"{endpoint}?name={name}&type=A",
            headers={
                "accept": "application/dns-json",
                "user-agent": "webwarden-preflight",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.load(response)
        except (OSError, ValueError, urllib.error.URLError):
            continue
        answers = payload.get("Answer") if isinstance(payload, dict) else None
        values = sorted({
            str(answer.get("data"))
            for answer in answers or []
            if isinstance(answer, dict)
            and answer.get("type") == 1
            and _is_ipv4(answer.get("data"))
        })
        if values:
            return values
    return []


def _block_page(
    domain: str, addresses: list[str], timeout: float
) -> dict | None:
    for address in addresses[:3]:
        connection = None
        try:
            connection = http.client.HTTPConnection(address, 80, timeout=timeout)
            connection.request(
                "GET", "/",
                headers={"Host": domain, "User-Agent": "webwarden-preflight"},
            )
            response = connection.getresponse()
            headers = {name.lower(): value for name, value in response.getheaders()}
            body = response.read(8192)
        except (OSError, http.client.HTTPException):
            continue
        finally:
            if connection is not None:
                connection.close()
        location = headers.get("location", "")
        marker = _marker(location) or _marker(
            body.decode("utf-8", "replace")
        )
        if marker:
            return {
                "address": address,
                "status": response.status,
                "location": location,
                "marker": marker,
            }
    return None


def preflight(
    domain: str, resolver: Resolver, timeout: float = 4.0
) -> DnsIntegrity:
    report = DnsIntegrity()
    apex_a = resolver.query(domain, "A")
    nameservers = resolver.query(domain, "NS")
    report.details["system_a"] = apex_a
    report.details["ns"] = nameservers

    for name in nameservers:
        if _marker(name):
            report.reasons.append(
                f"authoritative NS name matches a DNS filter: {name}"
            )
            break

    wildcard_name = f"wa-{secrets.token_hex(4)}.{domain}"
    wildcard_a = resolver.query(wildcard_name, "A")
    report.details["wildcard_name"] = wildcard_name
    report.details["wildcard_a"] = wildcard_a
    wildcard_same = bool(wildcard_a) and set(wildcard_a) == set(apex_a)

    doh_a = _doh_a(domain, timeout)
    report.details["doh_a"] = doh_a
    mismatch = bool(apex_a and doh_a and set(apex_a).isdisjoint(doh_a))
    if mismatch:
        message = f"system DNS A {apex_a} differs from DoH A {doh_a}"
        if wildcard_same:
            report.reasons.append(
                f"{message}; wildcard {wildcard_name} resolves to the same address"
            )
        else:
            report.warnings.append(message)
    elif wildcard_same and not doh_a:
        report.warnings.append(
            f"wildcard DNS: {wildcard_name} resolves to the apex address"
        )

    page = _block_page(domain, apex_a, timeout=timeout)
    if page:
        report.details["block_page"] = page
        report.reasons.append(
            f"HTTP response from {page['address']} is a block page "
            f"(marker {page['marker']!r}, location {page['location']!r})"
        )

    report.blocked = bool(report.reasons)
    return report
