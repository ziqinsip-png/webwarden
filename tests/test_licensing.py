from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import date, timedelta
from unittest import mock

from webwarden import licensing


class KeyPairTests(unittest.TestCase):
    def test_keypair_roundtrip(self):
        secret, public = licensing.new_keypair()
        self.assertEqual(len(secret), 64)
        self.assertEqual(len(public), 64)
        self.assertEqual(licensing.public_key_hex(secret), public)

    def test_public_key_is_stable_for_a_seed(self):
        secret = "00" * 32
        self.assertEqual(licensing.public_key_hex(secret), licensing.public_key_hex(secret))


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.secret, self.public = licensing.new_keypair()
        self.message = b"webwarden payload under test"

    def test_signature_verifies(self):
        sig = licensing.sign_hex(self.message, self.secret)
        self.assertEqual(len(sig), 128)
        self.assertTrue(licensing.verify_hex(self.message, sig, self.public))

    def test_tampered_message_is_rejected(self):
        sig = licensing.sign_hex(self.message, self.secret)
        self.assertFalse(licensing.verify_hex(self.message + b"!", sig, self.public))

    def test_tampered_signature_is_rejected(self):
        sig = bytearray(bytes.fromhex(licensing.sign_hex(self.message, self.secret)))
        sig[0] ^= 0x01
        self.assertFalse(licensing.verify_hex(self.message, bytes(sig).hex(), self.public))

    def test_other_key_is_rejected(self):
        sig = licensing.sign_hex(self.message, self.secret)
        _, other = licensing.new_keypair()
        self.assertFalse(licensing.verify_hex(self.message, sig, other))

    def test_malformed_inputs_do_not_raise(self):
        self.assertFalse(licensing.verify_hex(self.message, "zz", self.public))
        self.assertFalse(licensing.verify_hex(self.message, "00" * 64, self.public))
        self.assertFalse(licensing.verify_hex(self.message, "00" * 64, "nothex"))

    def test_malleable_scalar_is_rejected(self):
        sig = licensing.sign_hex(self.message, self.secret)
        raw = bytearray(bytes.fromhex(sig))
        raw[32:] = (1 << 253).to_bytes(32, "little")
        self.assertFalse(licensing.verify_hex(self.message, bytes(raw).hex(), self.public))


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class OpenSSLPairTests(unittest.TestCase):
    """Interop proof in both directions against a trusted implementation."""

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.msg = os.path.join(self.folder, "msg")
        with open(self.msg, "wb") as handle:
            handle.write(b"interop check")

    def tearDown(self):
        shutil.rmtree(self.folder, ignore_errors=True)

    def path(self, name: str) -> str:
        return os.path.join(self.folder, name)

    def test_python_signature_verifies_with_openssl(self):
        secret, public = licensing.new_keypair()
        signature = bytes.fromhex(licensing.sign_hex(b"interop check", secret))
        with open(self.path("pub.der"), "wb") as handle:
            handle.write(bytes.fromhex("302a300506032b6570032100") + bytes.fromhex(public))
        with open(self.path("sig"), "wb") as handle:
            handle.write(signature)
        subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", self.path("pub.der"), "-out", self.path("pub.pem")],
            check=True,
            capture_output=True,
        )
        done = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", self.path("pub.pem"),
                "-rawin", "-in", self.path("msg"), "-sigfile", self.path("sig"),
            ],
            capture_output=True,
        )
        self.assertEqual(done.returncode, 0, done.stderr.decode())

    def test_openssl_signature_verifies_in_python(self):
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", self.path("priv.pem")],
            check=True,
            capture_output=True,
        )
        with open(self.path("pub.der"), "wb") as out:
            subprocess.run(
                ["openssl", "pkey", "-in", self.path("priv.pem"), "-pubout", "-outform", "DER"],
                check=True,
                stdout=out,
                stderr=subprocess.DEVNULL,
            )
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", self.path("priv.pem"), "-rawin", "-in", self.path("msg"), "-out", self.path("sig")],
            check=True,
            capture_output=True,
        )
        with open(self.path("pub.der"), "rb") as handle:
            public = handle.read()[-32:].hex()
        with open(self.path("sig"), "rb") as handle:
            signature = handle.read().hex()
        self.assertTrue(licensing.verify_hex(b"interop check", signature, public))


class LicenseTests(unittest.TestCase):
    def setUp(self):
        self.secret, self.public = licensing.new_keypair()
        self.patch = mock.patch.object(licensing, "PUBLIC_KEY_HEX", self.public)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def issue(self, product="webwarden", customer="Ahmad Roziqin", **kwargs):
        return licensing.issue_license(product, customer, secret_hex=self.secret, **kwargs)

    def test_open_ended_license_verifies(self):
        key = self.issue()
        payload = licensing.verify_license(key, "webwarden")
        self.assertEqual(payload[licensing.CUSTOMER_FIELD], "Ahmad Roziqin")
        self.assertIsNone(payload[licensing.EXPIRES_FIELD])
        self.assertEqual(payload[licensing.TIER_FIELD], "pro")

    def test_universal_product_key_is_accepted(self):
        key = self.issue(product="*")
        self.assertTrue(licensing.verify_license(key, "netwarden"))

    def test_wrong_product_is_rejected(self):
        key = self.issue(product="webwarden")
        with self.assertRaises(licensing.LicenseError):
            licensing.verify_license(key, "netwarden")

    def test_datz_frontend_accepts_webwarden_key(self):
        key = self.issue(product="webwarden")
        products = (licensing.PRODUCT_WEBWARDEN, licensing.PRODUCT_DATZ)
        payload = licensing.verify_license(key, products)
        self.assertEqual(payload[licensing.PRODUCT_FIELD], "webwarden")

    def test_datz_frontend_accepts_datz_key(self):
        key = self.issue(product="datz")
        products = (licensing.PRODUCT_WEBWARDEN, licensing.PRODUCT_DATZ)
        self.assertTrue(licensing.verify_license(key, products))

    def test_datz_frontend_accepts_universal_key(self):
        key = self.issue(product="*")
        products = (licensing.PRODUCT_WEBWARDEN, licensing.PRODUCT_DATZ)
        self.assertTrue(licensing.verify_license(key, products))

    def test_datz_frontend_rejects_netwarden_key(self):
        key = self.issue(product="netwarden")
        products = (licensing.PRODUCT_WEBWARDEN, licensing.PRODUCT_DATZ)
        with self.assertRaises(licensing.LicenseError) as ctx:
            licensing.verify_license(key, products)
        self.assertIn("webwarden/datz", str(ctx.exception))

    def test_activate_hint_for_product_tuple(self):
        hint = licensing.activate_hint_for(
            (licensing.PRODUCT_WEBWARDEN, licensing.PRODUCT_DATZ))
        self.assertIn("webwarden license activate", hint)

    def test_status_product_label_for_tuple(self):
        with mock.patch.object(licensing, "resolve_license", return_value=("", None)):
            report = licensing.status(
                (licensing.PRODUCT_WEBWARDEN, licensing.PRODUCT_DATZ))
        self.assertEqual(report["product"], "webwarden/datz")

    def test_status_survives_invalid_license_file(self):
        with mock.patch.object(
                licensing, "resolve_license",
                side_effect=licensing.LicenseError("tanda tangan lisensi tidak valid")):
            report = licensing.status("webwarden")
        self.assertEqual(report["tier"], "invalid")
        self.assertIn("tidak valid", report["error"])

    def test_expired_license_is_rejected(self):
        key = self.issue(days=-1)
        with self.assertRaises(licensing.LicenseError):
            licensing.verify_license(key, "webwarden")

    def test_future_license_is_accepted(self):
        key = self.issue(days=30)
        self.assertTrue(licensing.verify_license(key, "webwarden"))

    def test_forged_payload_is_rejected(self):
        other_secret, _ = licensing.new_keypair()
        attacker = licensing.issue_license("webwarden", "penyusup", secret_hex=other_secret)
        with self.assertRaises(licensing.LicenseError):
            licensing.verify_license(attacker, "webwarden")

    def test_reissued_payload_cannot_be_relabeled(self):
        key = self.issue(customer="pembeli-a")
        parts = key.split(".")
        payload = json.loads(licensing._unb64(parts[1]))
        payload[licensing.CUSTOMER_FIELD] = "pembeli-b"
        tampered = f"{parts[0]}.{licensing._b64(licensing._canonical(payload))}.{parts[2]}"
        with self.assertRaises(licensing.LicenseError):
            licensing.verify_license(tampered, "webwarden")

    def test_garbage_license_string(self):
        for bad in ("", "DATZ1..", "hello.world.foo", "DATZ1.****.00"):
            with self.assertRaises(licensing.LicenseError):
                licensing.verify_license(bad, "webwarden")

    def test_invalid_product_identifier(self):
        with self.assertRaises(ValueError):
            licensing.issue_license("web wardens!", "x", secret_hex=self.secret)


class TrialGateTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"DATZ_HOME": self.folder, "DATZ_QUIET": "1"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.secret, self.public = licensing.new_keypair()
        self.patch = mock.patch.object(licensing, "PUBLIC_KEY_HEX", self.public)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def state(self) -> dict:
        return json.loads((licensing._state_dir() / "state.json").read_text(encoding="utf-8"))

    def test_first_run_grants_full_window(self):
        decision = licensing.enforce("webwarden", "scan")
        self.assertEqual(decision.tier, "trial")
        self.assertEqual(decision.days_left, licensing.TRIAL_DAYS - 1)
        self.assertIn("UJI COBA", decision.banner())

    def test_state_survives_second_run(self):
        first = licensing.enforce("webwarden", "scan")
        again = licensing.enforce("webwarden", "scan")
        self.assertEqual(first.days_left, again.days_left)
        self.assertEqual(self.state()["first_run"], date.today().isoformat())

    def test_trial_ends_after_the_window(self):
        past = (date.today() - timedelta(days=licensing.TRIAL_DAYS)).isoformat()
        (licensing._state_dir()).mkdir(parents=True, exist_ok=True)
        (licensing._state_dir() / "state.json").write_text(
            json.dumps({"first_run": past, "last_seen": past}), encoding="utf-8"
        )
        with self.assertRaises(licensing.LicenseError) as caught:
            licensing.enforce("webwarden", "scan")
        self.assertIn("berakhir", str(caught.exception))

    def test_clock_rollback_is_refused(self):
        today = date.today()
        (licensing._state_dir()).mkdir(parents=True, exist_ok=True)
        (licensing._state_dir() / "state.json").write_text(
            json.dumps({"first_run": today.isoformat(), "last_seen": (today + timedelta(days=3)).isoformat()}),
            encoding="utf-8",
        )
        with self.assertRaises(licensing.LicenseError) as caught:
            licensing.enforce("webwarden", "scan")
        self.assertIn("dimundurkan", str(caught.exception))

    def test_license_overrides_the_trial(self):
        key = licensing.issue_license("webwarden", "pembeli", secret_hex=self.secret, days=90)
        (licensing._state_dir()).mkdir(parents=True, exist_ok=True)
        (licensing._state_dir() / "license.key").write_text(key + "\n", encoding="utf-8")
        decision = licensing.enforce("webwarden", "scan")
        self.assertEqual(decision.tier, "pro")
        self.assertEqual(decision.customer, "pembeli")
        self.assertIn("PRO", decision.watermark)

    def test_exempt_command_needs_no_license(self):
        decision = licensing.enforce("webwarden", "license", exempt=frozenset({"license", "help"}))
        self.assertEqual(decision.tier, "license")

    def test_bad_license_falls_back_to_trial_instead_of_crashing(self):
        (licensing._state_dir()).mkdir(parents=True, exist_ok=True)
        (licensing._state_dir() / "license.key").write_text("DATZ1.junk.junk\n", encoding="utf-8")
        self.assertEqual(licensing.enforce("webwarden", "scan").tier, "trial")

    def test_status_reports_state(self):
        licensing.enforce("webwarden", "scan")
        report = licensing.status("webwarden")
        self.assertEqual(report["product"], "webwarden")
        self.assertEqual(report["trial_days"], licensing.TRIAL_DAYS)
        self.assertEqual(report["days_left"], licensing.TRIAL_DAYS)

    def test_env_license_is_read(self):
        key = licensing.issue_license("webwarden", "lewat-env", secret_hex=self.secret)
        with mock.patch.dict(os.environ, {"DATZ_LICENSE": key}):
            self.assertEqual(licensing.enforce("webwarden", "scan").customer, "lewat-env")

    def test_public_key_guard_blocks_unsigned_build(self):
        with mock.patch.object(licensing, "PUBLIC_KEY_HEX", ""):
            with self.assertRaises(licensing.LicenseError):
                licensing.enforce("webwarden", "scan")


class ShippedKeyTests(unittest.TestCase):
    def test_verification_key_is_embedded(self):
        self.assertRegex(licensing.PUBLIC_KEY_HEX, r"^[0-9a-f]{64}$")

    def test_shipped_key_is_not_the_test_key(self):
        self.assertNotEqual(licensing.PUBLIC_KEY_HEX, "00" * 32)


if __name__ == "__main__":
    unittest.main()
