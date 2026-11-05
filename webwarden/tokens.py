"""Offline cookie and JWT inspection. Tokens are never verified or used."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

SENSITIVE_HINTS = (
    "session", "sessid", "sid", "auth", "token", "jwt", "login", "refresh",
    "access", "credential", "remember", "phpsessid", "jsessionid",
)
PUBLIC_HINTS = (
    "anon", "anonymous", "visitor", "guest", "locale", "lang", "consent",
    "theme", "currency", "cart", "preference", "abtest", "device",
)
FLAG_NAMES = {"secure": "Secure", "httponly": "HttpOnly", "samesite": "SameSite"}


def _b64(part: str) -> bytes:
    padding = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + padding)


@dataclass
class JwtView:
    alg: str = ""
    typ: str = ""
    claims: dict = field(default_factory=dict)
    error: str = ""

    @property
    def purpose(self) -> str:
        return str(self.claims.get("purpose") or self.claims.get("token_use") or "")

    @property
    def scope(self) -> str:
        return str(self.claims.get("scope") or self.claims.get("scp") or "")

    @property
    def subject(self) -> str:
        return str(self.claims.get("sub") or self.claims.get("user_id") or "")

    @property
    def expires(self) -> str:
        value = self.claims.get("exp")
        if not isinstance(value, (int, float)):
            return ""
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return ""

    @property
    def is_public(self) -> bool:
        text = f"{self.purpose} {self.scope}".lower()
        return "public" in text or "anonymous" in text or "guest" in text

    def summary(self) -> str:
        parts = []
        if self.alg:
            parts.append(f"alg={self.alg}")
        if self.purpose:
            parts.append(f"purpose={self.purpose}")
        if self.scope:
            parts.append(f"scope={self.scope}")
        if self.subject:
            parts.append("sub=present")
        if self.expires:
            parts.append(f"exp={self.expires}")
        return ", ".join(parts)


@dataclass
class CookieView:
    name: str
    present: set[str] = field(default_factory=set)
    domain: str = ""
    path: str = ""
    jwt: JwtView | None = None
    sensitive: bool = False
    anonymous: bool = False
    reason: str = ""

    def missing(self, secure_required: bool = True) -> list[str]:
        missing = []
        if secure_required and "Secure" not in self.present:
            missing.append("Secure")
        if "HttpOnly" not in self.present:
            missing.append("HttpOnly")
        if "SameSite" not in self.present:
            missing.append("SameSite")
        return missing

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "present": sorted(self.present),
            "domain": self.domain,
            "path": self.path,
            "sensitive": self.sensitive,
            "anonymous": self.anonymous,
            "reason": self.reason,
            "jwt": self.jwt.summary() if self.jwt else "",
        }


def decode_jwt(value: str) -> JwtView | None:
    if not value or value.count(".") not in (1, 2):
        return None
    parts = value.split(".")
    try:
        header = json.loads(_b64(parts[0]))
        claims = json.loads(_b64(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    if not header and not claims:
        return None
    return JwtView(
        alg=str(header.get("alg") or ""),
        typ=str(header.get("typ") or ""),
        claims=claims,
    )


def _segments(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(";") if part.strip()]


def parse_cookie(raw: str) -> CookieView:
    segments = _segments(raw)
    head = segments[0] if segments else ""
    name, _, value = head.partition("=")
    name = name.strip() or "cookie"
    present: set[str] = set()
    domain = ""
    path = ""
    for segment in segments[1:]:
        key, _, attr_value = segment.partition("=")
        lowered = key.strip().lower()
        if lowered in FLAG_NAMES:
            present.add(FLAG_NAMES[lowered])
        elif lowered == "domain":
            domain = attr_value.strip()
        elif lowered == "path":
            path = attr_value.strip()

    view = CookieView(
        name=name, present=present, domain=domain, path=path,
        jwt=decode_jwt(value.strip()),
    )
    lowered = name.lower()
    public_hint = any(hint in lowered for hint in PUBLIC_HINTS)
    sensitive_hint = any(hint in lowered for hint in SENSITIVE_HINTS)
    if view.jwt is not None:
        if view.jwt.is_public:
            view.anonymous = True
            view.reason = "JWT claims indicate a public/anonymous scope"
        elif sensitive_hint or view.jwt.subject or view.jwt.scope:
            view.sensitive = True
            view.reason = "JWT claims indicate an authenticated/session token"
        else:
            view.reason = "JWT present; claims do not indicate a privileged session"
    elif public_hint:
        view.anonymous = True
        view.reason = "cookie name indicates anonymous/preference data"
    elif sensitive_hint:
        view.sensitive = True
        view.reason = "cookie name indicates session/authentication data (opaque value)"
    else:
        view.reason = "no token/session indicators"
    return view


def parse_cookies(raws: list[str]) -> list[CookieView]:
    return [parse_cookie(raw) for raw in raws]


def cookie_summary(view: CookieView, secure_required: bool = True) -> str:
    parts = [view.name]
    if view.domain:
        parts.append(f"domain={view.domain}")
    if view.jwt is not None:
        parts.append(view.jwt.summary() or "JWT (claims unreadable)")
    missing = view.missing(secure_required)
    if missing:
        parts.append("missing " + ", ".join(missing))
    if view.reason:
        parts.append(view.reason)
    return "; ".join(parts)
