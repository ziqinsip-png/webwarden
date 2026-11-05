"""Ed25519-signed license keys and the 14-day trial gate shared by DATZ tools.

Stdlib only, so the tools keep their single-file zipapp delivery. The
verification public key is embedded below; the signing key never ships and
lives with the publisher.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

__all__ = [
    "Decision",
    "LicenseError",
    "PRODUCT_DATZ",
    "PRODUCT_NETWARDEN",
    "PRODUCT_WEBWARDEN",
    "TRIAL_DAYS",
    "add_license_parser",
    "enforce",
    "issue_license",
    "new_keypair",
    "record",
    "run_license_command",
    "status",
    "verify_license",
]

TRIAL_DAYS = 14
PURCHASE_URL = "https://portofolio.ziqintzy.my.id/"
PREFIX = "DATZ1"
PRODUCT_WEBWARDEN = "webwarden"
PRODUCT_NETWARDEN = "netwarden"
PRODUCT_DATZ = "datz"
VERSION_FIELD = "v"
PRODUCT_FIELD = "p"
TIER_FIELD = "t"
CUSTOMER_FIELD = "c"
ISSUED_FIELD = "i"
EXPIRES_FIELD = "e"
KEYID_FIELD = "k"
HOSTS_FIELD = "h"

STATE_DIR_ENV = "DATZ_HOME"
LICENSE_ENV = "DATZ_LICENSE"
LICENSE_FILE_ENV = "DATZ_LICENSE_FILE"

PUBLIC_KEY_HEX = "aa77d5b184ae4ea01b5b04584b07910afd2a8427769db9ecbd5cb7a983274c49"

_EDWARDS_Q = 2**255 - 19
_EDWARDS_L = 2**252 + 27742317777372353535851937790883648493
_EDWARDS_D = -121665 * pow(121666, _EDWARDS_Q - 2, _EDWARDS_Q) % _EDWARDS_Q


def _inv(x: int) -> int:
    return pow(x, _EDWARDS_Q - 2, _EDWARDS_Q)


def _recover_x(y: int, sign: int = 0) -> int | None:
    if y >= _EDWARDS_Q:
        return None
    xx = (y * y - 1) * _inv(_EDWARDS_D * y * y + 1) % _EDWARDS_Q
    x = pow(xx, (_EDWARDS_Q + 3) // 8, _EDWARDS_Q)
    if (x * x - xx) % _EDWARDS_Q != 0:
        x = x * pow(2, (_EDWARDS_Q - 1) // 4, _EDWARDS_Q) % _EDWARDS_Q
    if (x * x - xx) % _EDWARDS_Q != 0:
        return None
    if x == 0 and sign:
        return None
    return _EDWARDS_Q - x if x % 2 != sign else x


_BASE_Y = 4 * _inv(5) % _EDWARDS_Q
_BASE_X = _recover_x(_BASE_Y)
assert _BASE_X is not None
_BASEPOINT = (_BASE_X, _BASE_Y)


def _edwards_add(p, q):
    x1, y1 = p
    x2, y2 = q
    k = _EDWARDS_D * x1 * x2 * y1 * y2 % _EDWARDS_Q
    a = x1 * y2 + y1 * x2
    b = y1 * y2 + x1 * x2
    denom = (1 - k * k) % _EDWARDS_Q
    if denom == 0:
        raise ValueError("ed25519: penjumlahan titik tidak terdefinisi")
    inv = _inv(denom)
    return (a * (1 - k) * inv % _EDWARDS_Q, b * (1 + k) * inv % _EDWARDS_Q)


def _scalar_mult(point, scalar: int):
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = _edwards_add(result, point)
        point = _edwards_add(point, point)
        scalar >>= 1
    return result


def _encode_point(point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(data: bytes):
    if len(data) != 32:
        raise ValueError("ed25519: point must be 32 bytes")
    raw = int.from_bytes(data, "little")
    y = raw & (2**255 - 1)
    x = _recover_x(y, (raw >> 255) & 1)
    if x is None:
        raise ValueError("ed25519: point is not on the curve")
    return (x, y)


def _hash_int(*chunks: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(chunks)).digest(), "little")


def _clamp(secret: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def new_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex) for a freshly generated key."""
    secret = os.urandom(32).hex()
    return secret, public_key_hex(secret)


def public_key_hex(secret_hex: str) -> str:
    a, _ = _clamp(bytes.fromhex(secret_hex))
    return _encode_point(_scalar_mult(_BASEPOINT, a)).hex()


def sign_hex(message: bytes, secret_hex: str) -> str:
    secret = bytes.fromhex(secret_hex)
    a, prefix = _clamp(secret)
    pub = _encode_point(_scalar_mult(_BASEPOINT, a))
    r = _hash_int(prefix, message) % _EDWARDS_L
    big_r = _encode_point(_scalar_mult(_BASEPOINT, r))
    k = _hash_int(big_r, pub, message) % _EDWARDS_L
    s = (r + k * a) % _EDWARDS_L
    return (big_r + s.to_bytes(32, "little")).hex()


def verify_hex(message: bytes, signature_hex: str, public_hex: str) -> bool:
    try:
        sig = bytes.fromhex(signature_hex)
        pk = bytes.fromhex(public_hex)
        if len(sig) != 64 or len(pk) != 32:
            return False
        s_int = int.from_bytes(sig[32:], "little")
        if s_int >= _EDWARDS_L:
            return False
        big_r = _decode_point(sig[:32])
        point_a = _decode_point(pk)
        k = _hash_int(sig[:32], pk, message) % _EDWARDS_L
        left = _scalar_mult(_BASEPOINT, s_int)
        right = _edwards_add(big_r, _scalar_mult(point_a, k))
        return _encode_point(left) == _encode_point(right)
    except (ValueError, TypeError):
        return False


class LicenseError(Exception):
    """Raised when a license key is missing, malformed, forged, or expired."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def issue_license(
    product: str,
    customer: str,
    *,
    secret_hex: str,
    tier: str = "pro",
    days: int | None = None,
    max_hosts: int | None = None,
    key_id: str | None = None,
) -> str:
    """Mint a signed license string. Requires the publisher's private key."""
    if product != "*" and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", product):
        raise ValueError("product must be a short identifier or '*'")
    today = date.today()
    payload = {
        VERSION_FIELD: 1,
        PRODUCT_FIELD: product,
        TIER_FIELD: tier,
        CUSTOMER_FIELD: customer,
        ISSUED_FIELD: today.isoformat(),
        EXPIRES_FIELD: (today + timedelta(days=days)).isoformat() if days else None,
        KEYID_FIELD: key_id or _b64(hashlib.sha256(_canonical({"c": customer, "p": product})).digest()[:6]),
    }
    if max_hosts is not None:
        payload[HOSTS_FIELD] = int(max_hosts)
    body = _canonical(payload)
    return f"{PREFIX}.{_b64(body)}.{sign_hex(body, secret_hex)}"


def decode_license(license_str: str) -> dict:
    parts = license_str.strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise LicenseError("lisensi tidak dikenali formatnya")
    try:
        body = _unb64(parts[1])
    except Exception as exc:
        raise LicenseError("lisensi tidak bisa dibaca") from exc
    if not verify_hex(body, parts[2], PUBLIC_KEY_HEX):
        raise LicenseError("tanda tangan lisensi tidak valid")
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise LicenseError("isi lisensi rusak") from exc
    if not isinstance(payload, dict):
        raise LicenseError("isi lisensi rusak")
    return payload


def verify_license(license_str: str, product: str) -> dict:
    """Return the payload when the key is signed by us and valid for `product`."""
    payload = decode_license(license_str)
    scoped = payload.get(PRODUCT_FIELD)
    if scoped not in ("*", product):
        raise LicenseError(f"lisensi ini bukan untuk {product}")
    expires = payload.get(EXPIRES_FIELD)
    if expires:
        try:
            end = date.fromisoformat(expires)
        except ValueError as exc:
            raise LicenseError("tanggal kedaluwarsa lisensi tidak sah") from exc
        if date.today() > end:
            raise LicenseError(f"lisensi {payload.get(CUSTOMER_FIELD)} kedaluwarsa pada {expires}")
    return payload


def _state_dir() -> Path:
    override = os.environ.get(STATE_DIR_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".datz"


def _state_file() -> Path:
    return _state_dir() / "state.json"


def _read_state() -> dict:
    try:
        raw = json.loads(_state_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _write_state(state: dict) -> None:
    folder = _state_dir()
    try:
        folder.mkdir(parents=True, exist_ok=True)
        _state_file().write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(_state_file(), stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def candidate_license_paths(product: str) -> list[Path]:
    paths: list[Path] = []
    env_file = os.environ.get(LICENSE_FILE_ENV)
    if env_file:
        paths.append(Path(env_file).expanduser())
    if product:
        paths.append(Path("/etc/datz") / f"{product}.key")
        paths.append(Path("/etc/datz/license.key"))
    paths.append(_state_dir() / "license.key")
    return paths


def resolve_license(product: str) -> tuple[str, dict | None]:
    """Find a usable license from env, standard files, or the tool config."""
    inline = os.environ.get(LICENSE_ENV)
    if inline:
        return "env", verify_license(inline, product)
    for path in candidate_license_paths(product):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if text.strip():
            return str(path), verify_license(text, product)
    return "", None


ACTIVATE_COMMANDS = {
    PRODUCT_WEBWARDEN: "webwarden license activate <kunci>",
    PRODUCT_NETWARDEN: "netwarden license activate <kunci>",
    PRODUCT_DATZ: "python3 datz.py --license <kunci>",
}


def activate_hint_for(product: str) -> str:
    command = ACTIVATE_COMMANDS.get(
        product, f"{product or 'datz'} license activate <kunci>")
    return f"beli kunci lalu jalankan: {command} (info: {PURCHASE_URL})"


@dataclass(frozen=True)
class Decision:
    tier: str
    label: str
    source: str
    days_left: int | None
    customer: str | None
    key_id: str | None
    max_hosts: int | None
    product: str = ""

    @property
    def trial(self) -> bool:
        return self.tier == "trial"

    @property
    def watermark(self) -> str:
        if self.trial:
            left = "?" if self.days_left is None else str(self.days_left)
            return f"TRIAL / {left} hari tersisa / belum terdaftar"
        return f"PRO / {self.customer} / key {self.key_id}"

    @property
    def badge(self) -> str:
        if not self.trial:
            return self.tier.upper()
        if self.days_left is None:
            return "TRIAL"
        return f"TRIAL {self.days_left}h"

    @property
    def activate_hint(self) -> str:
        return activate_hint_for(self.product)

    def banner(self) -> str:
        if self.trial:
            return (f"MODE UJI COBA {TRIAL_DAYS} HARI - {self.days_left} hari tersisa. "
                    f"{self.activate_hint}")
        return (f"Lisensi {self.tier.upper()} aktif untuk {self.customer} "
                f"(key {self.key_id}, sumber {self.source})")


def record(decision: Decision) -> dict:
    """Machine-readable licence stamp for a report/scan artifact."""
    return {
        "tier": decision.tier,
        "watermark": decision.watermark,
        "days_left": decision.days_left,
        "customer": decision.customer,
        "key_id": decision.key_id,
        "trial_days": TRIAL_DAYS,
    }


def _trial_decision(days_left: int, product: str) -> Decision:
    return Decision(
        tier="trial",
        label=f"trial {days_left} hari tersisa",
        source="",
        days_left=days_left,
        customer=None,
        key_id=None,
        max_hosts=None,
        product=product,
    )


def evaluate(product: str) -> Decision:
    """Decide the tier without raising: license first, then the trial window."""
    source, payload = "", None
    try:
        source, payload = resolve_license(product)
    except LicenseError:
        payload = None
    if payload is not None:
        return Decision(
            tier=payload.get(TIER_FIELD, "pro"),
            label="berlisensi",
            source=source,
            days_left=None,
            customer=payload.get(CUSTOMER_FIELD),
            key_id=payload.get(KEYID_FIELD),
            max_hosts=payload.get(HOSTS_FIELD),
            product=product,
        )

    today = date.today()
    state = _read_state()
    first = _as_date(state.get("first_run"))
    seen = _as_date(state.get("last_seen"))
    if first is None:
        _write_state({"first_run": today.isoformat(), "last_seen": today.isoformat(), "product": product})
        return _trial_decision(TRIAL_DAYS - 1, product)
    if seen is not None and today < seen:
        raise LicenseError(
            "jam sistem dimundurkan dari tanggal yang pernah dilihat; uji coba ditutup. "
            "Pasang lisensi untuk melanjutkan."
        )
    left = TRIAL_DAYS - 1 - (today - first).days
    _write_state({"first_run": first.isoformat(), "last_seen": max(today, seen or today).isoformat(), "product": product})
    if left < 0:
        raise LicenseError(
            f"uji coba {TRIAL_DAYS} hari berakhir pada "
            f"{(first + timedelta(days=TRIAL_DAYS - 1)).isoformat()}. "
            f"{product} ini berbayar. " + activate_hint_for(product)
        )
    return _trial_decision(left, product)


def _as_date(text: object) -> date | None:
    if not isinstance(text, str):
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def enforce(product: str, command: str | None = None, *, exempt: frozenset[str] = frozenset()) -> Decision:
    """Gate a run. `exempt` names subcommands that must always work (help, license)."""
    if command in exempt:
        return Decision("license", "tidak perlu lisensi", "", None, None, None,
                        None, product)
    if not PUBLIC_KEY_HEX:
        raise LicenseError("public key lisensi belum ditanam di build ini")
    decision = evaluate(product)
    if os.environ.get("DATZ_QUIET") != "1":
        stream = sys.stderr
        stream.write(f"[datz] {decision.banner()}\n")
    return decision


def add_license_parser(sub, *, product: str, blurb: str = ""):
    """Attach the shared `license` subcommand to a tool's argparse tree."""
    parser = sub.add_parser(
        "license",
        help="status uji coba, verifikasi, atau pasang kunci lisensi",
        description=blurb or "Kelola lisensi DATZ untuk perkakas ini.",
    )
    actions = parser.add_subparsers(dest="license_action")
    actions.add_parser("status", help="tampilkan sisa masa uji atau detail lisensi")
    activate = actions.add_parser("activate", help="simpan kunci dan aktifkan Pro")
    activate.add_argument("key", help="string lisensi atau path berkas kunci")
    verify = actions.add_parser("verify", help="periksa kunci tanpa memasangnya")
    verify.add_argument("key", help="string lisensi atau path berkas kunci")
    parser.set_defaults(product=product)
    return parser


def run_license_command(args, product: str | None = None) -> int:
    """Handle the `license` subcommand. Returns a process exit code."""
    product = product or getattr(args, "product", None) or "*"
    action = getattr(args, "license_action", None) or "status"
    if action == "activate":
        text = _read_key_argument(args.key)
        try:
            payload = verify_license(text, product)
        except LicenseError as exc:
            print(f"lisensi ditolak: {exc}", file=sys.stderr)
            return 3
        target = _state_dir() / "license.key"
        _write_state(_read_state())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text.strip() + "\n", encoding="utf-8")
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        tier = payload.get(TIER_FIELD, "pro")
        expires = payload.get(EXPIRES_FIELD)
        validity = f"berlaku sampai {expires}" if expires else "berlaku selamanya"
        print(f"lisensi {tier} aktif untuk {payload.get(CUSTOMER_FIELD)} "
              f"(key {payload.get(KEYID_FIELD)}, {validity})")
        print(f"tersimpan di {target}")
        return 0
    if action == "verify":
        try:
            payload = verify_license(_read_key_argument(args.key), product)
        except LicenseError as exc:
            print(f"lisensi tidak valid: {exc}", file=sys.stderr)
            return 3
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    report = status(product)
    if report.get("tier") == "trial" and report.get("first_run"):
        print(f"mode uji coba: {report['days_left']} dari {TRIAL_DAYS} hari tersisa "
              f"(jalan pertama {report['first_run']}, berakhir {report['trial_expires']})")
    elif report.get("tier") == "trial":
        print(f"belum pernah dijalankan; mode uji coba {TRIAL_DAYS} hari dimulai "
              "saat perkakas dipakai")
    elif report.get("tier") == "invalid":
        print(f"lisensi tidak valid: {report.get('error')}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    if report.get("tier") != "pro":
        print(activate_hint_for(product))
    return 0


def _read_key_argument(value: str) -> str:
    path = Path(value).expanduser()
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8").strip()
    return value.strip()


def status(product: str) -> dict:
    today = date.today()
    state = _read_state()
    first = _as_date(state.get("first_run"))
    out = {
        "product": product,
        "public_key": (PUBLIC_KEY_HEX[:16] + "...") if PUBLIC_KEY_HEX else "(belum ditanam)",
        "trial_days": TRIAL_DAYS,
        "first_run": first.isoformat() if first else None,
        "trial_expires": (first + timedelta(days=TRIAL_DAYS - 1)).isoformat() if first else None,
        "license_file": None,
        "tier": "trial",
        "customer": None,
        "key_id": None,
    }
    if first:
        out["days_left"] = max(0, TRIAL_DAYS - (today - first).days)
    else:
        out["days_left"] = TRIAL_DAYS
    try:
        source, payload = resolve_license(product)
    except LicenseError as exc:
        out.update({"tier": "invalid", "license_file": str(source), "error": str(exc)})
        return out
    if payload:
        out.update(
            {
                "tier": payload.get(TIER_FIELD, "pro"),
                "license_file": source,
                "customer": payload.get(CUSTOMER_FIELD),
                "key_id": payload.get(KEYID_FIELD),
                "expires": payload.get(EXPIRES_FIELD),
                "days_left": None,
            }
        )
    return out


def _main(argv: list[str]) -> int:
    from argparse import ArgumentParser

    parser = ArgumentParser(prog="datz-licensing", description="periksa dan pasang lisensi DATZ")
    parser.add_argument("action", choices=["keygen", "issue", "verify", "status", "activate"])
    parser.add_argument("--product", default="*")
    parser.add_argument("--customer", default="")
    parser.add_argument("--days", type=int, default=None)
    parser.add_argument("--tier", default="pro")
    parser.add_argument("--key", dest="secret_hex", help="private key hex (hanya untuk penerbit)")
    parser.add_argument("license", nargs="?", help="string lisensi atau path berkas")
    args = parser.parse_args(argv)

    if args.action == "keygen":
        secret, public = new_keypair()
        print(f"private={secret}")
        print(f"public={public}")
        return 0
    if args.action == "issue":
        if not args.secret_hex:
            raise SystemExit("--key wajib diisi untuk menerbitkan lisensi")
        print(
            issue_license(
                args.product,
                args.customer or "unassigned",
                secret_hex=args.secret_hex,
                tier=args.tier,
                days=args.days,
            )
        )
        return 0
    if args.action == "activate":
        if not args.license:
            raise SystemExit("berikan string lisensi atau path berkasnya")
        text = _read_key_argument(args.license)
        payload = verify_license(text, args.product)
        target = _state_dir() / "license.key"
        _write_state(_read_state())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text.strip() + "\n", encoding="utf-8")
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        print(f"lisensi aktif untuk {payload[CUSTOMER_FIELD]} -> {target}")
        return 0
    if args.action == "verify":
        payload = verify_license(args.license or "", args.product)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(json.dumps(status(args.product), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except LicenseError as exc:
        print(f"lisensi ditolak: {exc}", file=sys.stderr)
        raise SystemExit(3)
