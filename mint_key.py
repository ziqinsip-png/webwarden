#!/usr/bin/env python3
"""Mint a signed DATZ license key. Publisher-only.

The private half of the signing key is never stored in a repository or in the
shipped product. It is read from the DATZ_SIGNING_KEY environment variable, held
for one signature, and dropped when the process exits. Customers only ever
receive the resulting key string; the public key inside licensing.py is what the
tools use to verify it.

    export DATZ_SIGNING_KEY=<64 hex chars>
    python3 mint_key.py --customer "Nama Pembeli" --days 365
    python3 mint_key.py --customer "PT X" --product netwarden --max-hosts 25
    python3 mint_key.py --selftest        # no secret needed
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:  # both repositories ship the same module under their own package name
    from webwarden import licensing
except ImportError:  # pragma: no cover - depends on which tree this copy sits in
    from netwarden import licensing  # noqa: E402

SECRET_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def read_secret(provided: str | None) -> str:
    if provided:
        return provided.strip()
    from_env = os.environ.get("DATZ_SIGNING_KEY", "").strip()
    if from_env:
        return from_env
    return getpass.getpass("DATZ_SIGNING_KEY (tersembunyi): ").strip()


def issue(args) -> int:
    secret = read_secret(args.secret)
    if not SECRET_RE.fullmatch(secret):
        print("error: kunci privat harus 64 karakter hex", file=sys.stderr)
        return 2
    days = args.days if args.days and args.days > 0 else None
    key = licensing.issue_license(
        args.product,
        args.customer,
        secret_hex=secret,
        days=days,
        max_hosts=args.max_hosts,
        key_id=args.key_id,
    )
    try:
        payload = licensing.decode_license(key)
    except licensing.LicenseError:
        print(
            "error: kunci sudah ditandatangani tetapi tidak lolos verifikasi dengan "
            "public key yang terpasang di produk — DATZ_SIGNING_KEY bukan pasangan "
            "kunci publik itu. Tidak ada file yang ditulis.",
            file=sys.stderr,
        )
        print(f"public key produk: {licensing.PUBLIC_KEY_HEX}", file=sys.stderr)
        return 2
    if args.out:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(key + "\n", encoding="utf-8", newline="\n")
        os.chmod(target, 0o600)
        print(f"tertulis: {target}")
    else:
        print(key)
    if not args.quiet:
        print(
            f"produk={payload['p']} tier={payload['t']} "
            f"pelanggan={payload['c']} id={payload['k']} "
            f"dikeluarkan={payload['i']} "
            f"kedaluwarsa={payload.get('e') or 'selamanya'} "
            f"host={payload.get('h') or 'tanpa batas'}",
            file=sys.stderr,
        )
    return 0


def selftest(args) -> int:
    """Round-trip a signature with a throwaway keypair. Needs no secret."""
    secret, public = licensing.new_keypair()
    key = licensing.issue_license(
        "*", "Selftest", secret_hex=secret, days=1, max_hosts=3, key_id="selftest"
    )
    _prefix, body_b64, signature_hex = key.split(".")
    body = licensing._unb64(body_b64)
    ok = licensing.verify_hex(body, signature_hex, public)
    print(f"throwaway public key: {public}")
    print(f"round-trip verify: {'OK' if ok else 'GAGAL'}")
    print("contoh kunci di bawah TIDAK akan diterima produk mana pun "
          "karena publik key-nya bukan yang terpasang di kode:")
    print(key)
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Terbitkan kunci lisensi DATZ1 (khusus penerbit).")
    parser.add_argument("--customer", help="nama pelanggan, tercetak di laporan")
    parser.add_argument("--product", default="*",
                        help="webwarden | netwarden | datz | * (default: * = semua)")
    parser.add_argument("--days", type=int, default=365,
                        help="masa berlaku dalam hari, 0 = selamanya (default 365)")
    parser.add_argument("--max-hosts", type=int, default=None,
                        help="batas perangkat/host yang boleh dikelola")
    parser.add_argument("--key-id", default=None, help="penanda kunci (opsional)")
    parser.add_argument("--out", help="tulis kunci ke file, mode 0600")
    parser.add_argument("--secret", help="hindari; isi DATZ_SIGNING_KEY saja")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--selftest", action="store_true",
                        help="uji round-trip dengan pasangan kunci sementara")
    args = parser.parse_args()
    if args.selftest:
        return selftest(args)
    if not args.customer:
        parser.error("--customer wajib (atau pakai --selftest)")
    if args.secret:
        print("warning: kunci privat di baris perintah bisa terbaca dari riwayat "
              "shell; lebih baik export DATZ_SIGNING_KEY", file=sys.stderr)
    return issue(args)


if __name__ == "__main__":
    raise SystemExit(main())
