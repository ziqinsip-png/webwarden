"""Small dependency-free DNS client (A, AAAA, CNAME, NS, MX, TXT, SOA, CAA)."""

from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
import threading
import time
from pathlib import Path

QTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
    "TXT": 16, "AAAA": 28, "CAA": 257,
}
RTYPES = {value: key for key, value in QTYPES.items()}
TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA = 1, 2, 5, 6
TYPE_MX, TYPE_TXT, TYPE_AAAA, TYPE_CAA = 15, 16, 28, 257


def _encode_name(name: str) -> bytes:
    parts = [part for part in name.rstrip(".").split(".") if part]
    out = bytearray()
    for part in parts:
        raw = part.encode("idna")
        if not raw or len(raw) > 63:
            raise ValueError(f"bad DNS label in {name!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end: int | None = None
    jumps = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated DNS name")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            offset = pointer
            jumps += 1
            if jumps > 20:
                raise ValueError("DNS compression loop")
            continue
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), (end if end is not None else offset)


def build_query(name: str, qtype: int, qid: int) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", qtype, 1)
    return header + question


def parse_response(data: bytes, qid: int) -> list[tuple[int, str, int]]:
    if len(data) < 12:
        raise ValueError("short DNS response")
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        raise ValueError("DNS transaction id mismatch")
    if flags & 0x000F:
        return []
    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4
    answers: list[tuple[int, str, int]] = []
    for _ in range(ancount):
        _, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        rdata_offset = offset
        offset += rdlength
        value: str | None = None
        try:
            if rtype == TYPE_A and len(rdata) == 4:
                value = socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == TYPE_AAAA and len(rdata) == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (TYPE_NS, TYPE_CNAME):
                value, _ = _decode_name(data, rdata_offset)
            elif rtype == TYPE_MX:
                preference = struct.unpack(">H", rdata[:2])[0]
                exchange, _ = _decode_name(data, rdata_offset + 2)
                value = f"{preference} {exchange}"
            elif rtype == TYPE_TXT:
                chunks = []
                index = 0
                while index < len(rdata):
                    size = rdata[index]
                    chunks.append(rdata[index + 1:index + 1 + size].decode("utf-8", "replace"))
                    index += 1 + size
                value = "".join(chunks)
            elif rtype == TYPE_CAA and len(rdata) >= 2:
                tag_len = rdata[1]
                tag = rdata[2:2 + tag_len].decode("ascii", "replace")
                caa_value = rdata[2 + tag_len:].decode("ascii", "replace")
                value = f"{tag} {caa_value}".strip()
        except (ValueError, struct.error, UnicodeDecodeError):
            value = None
        if value is not None:
            answers.append((rtype, value, ttl))
    return answers


def _system_servers() -> list[str]:
    servers: list[str] = []
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    address = ipaddress.ip_address(parts[1])
                except ValueError:
                    continue
                if address.version == 4:
                    servers.append(str(address))
    return servers or ["1.1.1.1", "8.8.8.8"]


class Resolver:
    def __init__(self, servers: list[str] | None = None, timeout: float = 3.0,
                 ttl: float = 300.0) -> None:
        self.servers = servers or _system_servers()
        self.timeout = max(0.5, float(timeout))
        self.ttl = ttl
        self._cache: dict[tuple[str, str], tuple[float, list[str]]] = {}
        self._lock = threading.Lock()

    def _cached(self, key: tuple[str, str]) -> list[str] | None:
        with self._lock:
            hit = self._cache.get(key)
        if hit and hit[0] > time.time():
            return list(hit[1])
        return None

    def _store(self, key: tuple[str, str], values: list[str]) -> None:
        with self._lock:
            self._cache[key] = (time.time() + self.ttl, list(values))

    def query(self, name: str, qtype: str = "A", tries: int = 2) -> list[str]:
        qtype = qtype.upper()
        if qtype not in QTYPES:
            raise ValueError(f"unsupported DNS type {qtype}")
        name = name.rstrip(".")
        key = (name.lower(), qtype)
        cached = self._cached(key)
        if cached is not None:
            return cached

        values: list[str] = []
        cnames: list[str] = []
        for _ in range(max(1, tries)):
            for server in self.servers:
                try:
                    answers = self._udp(server, name, QTYPES[qtype])
                except (OSError, ValueError):
                    continue
                values = [value for rtype, value, _ in answers if rtype == QTYPES[qtype]]
                cnames = [value for rtype, value, _ in answers if rtype == TYPE_CNAME]
                if values:
                    break
            if values:
                break

        if not values and cnames:
            target = cnames[0].rstrip(".")
            if target and target.lower() != name.lower():
                values = self.query(target, qtype, tries=1)

        if not values and qtype in ("A", "AAAA"):
            values = self._system(name, qtype)

        self._store(key, values)
        return values

    def _udp(self, server: str, name: str, qtype: int) -> list[tuple[int, str, int]]:
        qid = secrets.randbits(16)
        packet = build_query(name, qtype, qid)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        return parse_response(data, qid)

    def _system(self, name: str, qtype: str) -> list[str]:
        family = socket.AF_INET if qtype == "A" else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        values = []
        for info in infos:
            address = info[4][0]
            if address not in values:
                values.append(address)
        return values

    def resolve_all(self, name: str) -> list[str]:
        addresses = list(self.query(name, "A"))
        for address in self.query(name, "AAAA"):
            if address not in addresses:
                addresses.append(address)
        return addresses

    def exists(self, name: str) -> bool:
        return bool(self.query(name, "A") or self.query(name, "AAAA"))

    def wildcard(self, domain: str) -> bool:
        probe = f"ww-{secrets.token_hex(4)}.{domain}"
        return bool(self.query(probe, "A") or self.query(probe, "AAAA"))
