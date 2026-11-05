"""Tests for the two-session access-control audit."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from webwarden import cli
from webwarden.access_audit import (
    audit_cross_account,
    render_access_markdown,
    write_access_audit,
)

SESS_A = {"Cookie": "sessA=v"}
SESS_B = {"Cookie": "sessB=v"}


class AccessHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    vulnerable = True
    methods: list[str] = []

    def do_GET(self):  # noqa: N802
        type(self).methods.append("GET")
        cookie = self.headers.get("Cookie", "")
        is_b = "sessB=v" in cookie
        is_a = "sessA=v" in cookie
        if self.path.startswith("/b/sheet/"):
            if is_b:
                return self._send(200, "B private sheet 42", "text/html")
            if is_a and type(self).vulnerable:
                return self._send(200, "B private sheet 42", "text/html")
            if is_a:
                return self._send(403, "Forbidden", "text/plain")
            return self._send(401, "Unauthorized", "text/plain")
        if self.path.startswith("/b/attach/"):
            if is_b:
                return self._send(200, "B attachment bytes", "application/pdf")
            return self._send(403, "Forbidden", "text/plain")
        if self.path.startswith("/b/anon-leak/"):
            if is_b or not cookie:
                return self._send(200, "B leaked data", "text/html")
            return self._send(403, "Forbidden", "text/plain")
        if self.path.startswith("/b/login-wall/"):
            if is_b:
                return self._send(200, "B data behind login", "text/html")
            return self._send(
                200, "<html><form>login</form><input type=password></html>",
                "text/html")
        return self._send(404, "not found", "text/plain")

    def _send(self, status: int, body: str, ctype: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # noqa: D401
        pass


class AccessServer:
    def __init__(self, vulnerable: bool = True) -> None:
        self.handler = type("Handler", (AccessHandler,), {
            "vulnerable": vulnerable, "methods": []})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.base = f"http://{host}:{port}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        return False


class AccessAuditTests(unittest.TestCase):
    def audit(self, base: str, paths: list[str], **kwargs):
        return audit_cross_account(
            target=base,
            urls=[base + path for path in paths],
            auth_a=SESS_A,
            auth_b=SESS_B,
            scopes=[base.split("//", 1)[1].split(":")[0]],
            timeout=5.0,
            rate=50.0,
            allow_auth_http=True,
            **kwargs,
        )

    def test_confirmed_cross_account_read(self):
        with AccessServer(vulnerable=True) as lab:
            result = self.audit(lab.base, ["/b/sheet/42"])
        check = result.checks[0]
        self.assertEqual(check.verdict, "cross-account")
        self.assertEqual(check.severity, "high")
        self.assertTrue(check.stable)
        self.assertEqual(check.reproductions, 2)
        self.assertEqual(check.owner_sha, check.other_sha)
        self.assertNotIn("sessB", json.dumps(result.to_dict()))

    def test_denied_control_passes(self):
        with AccessServer(vulnerable=False) as lab:
            result = self.audit(lab.base, ["/b/sheet/42"])
        check = result.checks[0]
        self.assertEqual(check.verdict, "denied")
        self.assertEqual(check.other_status, 403)
        self.assertEqual(result.findings(), [])

    def test_anonymous_read_is_critical(self):
        with AccessServer(vulnerable=False) as lab:
            result = self.audit(lab.base, ["/b/anon-leak/1"])
        check = result.checks[0]
        self.assertEqual(check.verdict, "unauthenticated")
        self.assertEqual(check.severity, "critical")
        self.assertEqual(check.anon_status, 200)

    def test_login_wall_is_not_a_finding(self):
        with AccessServer(vulnerable=False) as lab:
            result = self.audit(lab.base, ["/b/login-wall/1"])
        self.assertEqual(result.checks[0].verdict, "denied")

    def test_owner_baseline_failure_is_inconclusive(self):
        with AccessServer(vulnerable=True) as lab:
            result = self.audit(lab.base, ["/b/missing/1"])
        check = result.checks[0]
        self.assertEqual(check.verdict, "inconclusive")
        self.assertEqual(check.owner_status, 404)

    def test_only_get_is_sent(self):
        with AccessServer(vulnerable=True) as lab:
            self.audit(lab.base, ["/b/sheet/42"])
            methods = set(lab.handler.methods)
        self.assertEqual(methods, {"GET"})

    def test_report_hides_session_values(self):
        with AccessServer(vulnerable=True) as lab:
            result = self.audit(lab.base, ["/b/sheet/42"])
            with tempfile.TemporaryDirectory() as tmp:
                paths = write_access_audit(result, tmp)
                markdown = paths["markdown"].read_text(encoding="utf-8")
                payload = paths["json"].read_text(encoding="utf-8")
                evidence = Path(tmp, "evidence", "index.json")
                self.assertTrue(evidence.exists())
        self.assertIn("Audit access-control", markdown)
        self.assertIn("Akses lintas akun (IDOR/BOLA)", markdown)
        self.assertIn("Skenario attacker", markdown)
        self.assertIn("Checklist SSO/OAuth", markdown)
        for text in (markdown, payload):
            self.assertNotIn("sessA=v", text)
            self.assertNotIn("sessB=v", text)
            self.assertNotIn("sessA", text)
            self.assertNotIn("sessB", text)

    def test_render_without_findings(self):
        with AccessServer(vulnerable=False) as lab:
            result = self.audit(lab.base, ["/b/sheet/42"])
        markdown = render_access_markdown(result)
        self.assertIn("Tidak ada akses lintas akun", markdown)


class AccessCliTests(unittest.TestCase):
    def parse(self, argv):
        return cli.build_parser().parse_args(argv)

    def test_requires_authorization_and_ownership(self):
        base = ["access-audit", "https://app.example.com",
                "--auth-a", "Cookie: a=1", "--auth-b", "Cookie: b=2",
                "--url", "https://app.example.com/sheets/1"]
        args = self.parse(base + ["--accounts-owned"])
        self.assertEqual(cli.cmd_access_audit(args), 2)
        args = self.parse(base + ["--i-am-authorized"])
        self.assertEqual(cli.cmd_access_audit(args), 2)

    def test_out_of_scope_url_is_refused(self):
        args = self.parse([
            "access-audit", "https://app.example.com",
            "--auth-a", "Cookie: a=1", "--auth-b", "Cookie: b=2",
            "--url", "https://other.example.net/sheets/1",
            "--accounts-owned", "--i-am-authorized",
        ])
        self.assertEqual(cli.cmd_access_audit(args), 3)

    def test_bad_auth_header_is_rejected(self):
        args = self.parse([
            "access-audit", "https://app.example.com",
            "--auth-a", "not-a-header", "--auth-b", "Cookie: b=2",
            "--url", "https://app.example.com/sheets/1",
            "--accounts-owned", "--i-am-authorized",
        ])
        self.assertEqual(cli.cmd_access_audit(args), 2)

    def test_plain_http_needs_allow_flag(self):
        base = ["access-audit", "http://127.0.0.1:8099",
                "--auth-a", "Cookie: a=1", "--auth-b", "Cookie: b=2",
                "--url", "http://127.0.0.1:8099/sheets/1",
                "--accounts-owned", "--i-am-authorized"]
        self.assertEqual(cli.cmd_access_audit(self.parse(base)), 2)
        self.assertTrue(self.parse(base + ["--allow-auth-http"]).allow_auth_http)

    def test_command_is_dispatched(self):
        args = self.parse([
            "access-audit", "https://app.example.com",
            "--auth-a", "Cookie: a=1", "--auth-b", "Cookie: b=2",
            "--url", "https://app.example.com/sheets/1",
        ])
        self.assertEqual(args.command, "access-audit")
        self.assertEqual(args.url, ["https://app.example.com/sheets/1"])


if __name__ == "__main__":
    unittest.main()
