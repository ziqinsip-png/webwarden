"""Tests for the read-only lab upload-surface audit."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from webwarden import upload_audit
from webwarden.cli import main

PAGE = b"""<!doctype html><html><body>
<h1>Upload lab</h1>
<form action="/upload.php" method="post" enctype="multipart/form-data">
<input type="hidden" name="csrf" value="x">
<input type="text" name="title">
<input type="file" name="avatar" accept="image/png,image/jpeg">
<button type="submit">Upload</button>
</form>
</body></html>"""

LISTING = (
    b"<html><title>Index of /uploads</title><body><h1>Index of /uploads</h1>"
    b"<a href='shell.phtml'>shell.phtml</a></body></html>"
)
HTACCESS = b"AddType application/x-httpd-php .jpg\nOptions -Indexes\n"
PHPINFO = (
    b"<html><body><h1>PHP Version 8.2.29</h1>"
    b"<p>Configuration File (php.ini) Path</p></body></html>"
)


class LabHandler(BaseHTTPRequestHandler):
    methods: list[str] = []
    catch_all = False

    def _send(self, status: int, body: bytes, ctype: str, extra=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        type(self).methods.append("GET")
        path = self.path.split("?")[0]
        if self.catch_all:
            self._send(200, LISTING, "text/html")
            return
        if path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8", {
                "Server": "Apache/2.4.57 (Debian)",
                "X-Powered-By": "PHP/8.2.29",
                "Set-Cookie": "PHPSESSID=lab; path=/",
            })
        elif path == "/uploads/":
            self._send(200, LISTING, "text/html")
        elif path == "/.htaccess":
            self._send(200, HTACCESS, "text/plain")
        elif path == "/phpinfo.php":
            self._send(200, PHPINFO, "text/html")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        type(self).methods.append("POST")
        self._send(405, b"no", "text/plain")

    def do_HEAD(self) -> None:
        type(self).methods.append("HEAD")
        self._send(200, b"", "text/html")

    def log_message(self, *args) -> None:
        pass


class LabServer:
    def __init__(self, catch_all: bool = False) -> None:
        LabHandler.methods = []
        self.handler = type("Handler", (LabHandler,), {"catch_all": catch_all})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "LabServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/"

    @property
    def methods(self) -> list[str]:
        return list(self.handler.methods)


class LabGateTests(unittest.TestCase):
    def test_loopback_is_allowed(self):
        self.assertEqual(upload_audit.assert_lab_url("http://127.0.0.1:8080/"),
                         "127.0.0.1")
        self.assertEqual(upload_audit.assert_lab_url("localhost"), "localhost")

    def test_private_range_is_allowed(self):
        self.assertEqual(upload_audit.assert_lab_url("http://10.0.0.5:8080/"),
                         "10.0.0.5")

    def test_public_address_is_refused(self):
        with self.assertRaises(upload_audit.LabScopeError):
            upload_audit.assert_lab_url("http://1.1.1.1/")

    def test_bad_scheme_is_refused(self):
        with self.assertRaises(upload_audit.LabScopeError):
            upload_audit.assert_lab_url("ftp://127.0.0.1/")


class ParserTests(unittest.TestCase):
    def test_upload_form_is_detected(self):
        forms = upload_audit.parse_upload_forms(PAGE.decode())
        self.assertEqual(len(forms), 1)
        form = forms[0]
        self.assertEqual(form.action, "/upload.php")
        self.assertEqual(form.method, "post")
        self.assertEqual(form.file_fields, ["avatar"])
        self.assertEqual(form.accepts, ["image/png,image/jpeg"])
        self.assertEqual(form.hidden, 1)

    def test_form_without_file_input_is_ignored(self):
        html = '<form action="/x"><input type="text" name="q"></form>'
        self.assertEqual(upload_audit.parse_upload_forms(html), [])

    def test_sapi_profile_reads_headers_only(self):
        profile = upload_audit.sapi_profile(
            {"server": "Apache/2.4.57", "x-powered-by": "PHP/8.2.29"},
            ["PHPSESSID=abc; path=/"],
        )
        self.assertEqual(profile["php_version"], "8.2.29")
        self.assertTrue(profile["php_session_cookie"])
        self.assertIn("php", profile["sapi"])


class AuditTests(unittest.TestCase):
    def test_audit_maps_the_lab_surface(self):
        with LabServer() as lab:
            result = upload_audit.audit_lab_upload_surface(lab.url, rate=50)
            titles = {finding.title for finding in result["findings"]}
            self.assertIn("Upload form discovered", titles)
            self.assertIn("Client-side upload restriction declared", titles)
            self.assertIn("Upload directory is listable", titles)
            self.assertIn("Apache .htaccess is publicly readable", titles)
            self.assertIn("phpinfo() page is exposed", titles)
            self.assertIn("PHP runtime fingerprint", titles)
            self.assertEqual(result["sapi"]["php_version"], "8.2.29")
            self.assertEqual(len(result["forms"]), 1)

    def test_audit_never_sends_post_or_upload(self):
        with LabServer() as lab:
            upload_audit.audit_lab_upload_surface(lab.url, rate=50)
            methods = set(lab.methods)
            self.assertNotIn("POST", methods)
            self.assertTrue(methods <= {"GET", "HEAD"})

    def test_control_path_suppresses_catch_all_listing(self):
        with LabServer(catch_all=True) as lab:
            result = upload_audit.audit_lab_upload_surface(lab.url, rate=50)
            titles = {finding.title for finding in result["findings"]}
            self.assertNotIn("Upload directory is listable", titles)

    def test_reports_are_written(self):
        with LabServer() as lab, tempfile.TemporaryDirectory() as tmp:
            result = upload_audit.audit_lab_upload_surface(lab.url, rate=50)
            paths = upload_audit.write_upload_audit(result, tmp)
            markdown = Path(paths["markdown"]).read_text(encoding="utf-8")
            payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
            self.assertIn("LAB ONLY", markdown)
            self.assertIn("## Upload forms", markdown)
            self.assertTrue(payload["lab_only"])
            self.assertEqual(payload["forms"][0]["file_fields"], ["avatar"])
            self.assertTrue(payload["findings"])


class CliTests(unittest.TestCase):
    def test_lab_flag_is_required(self):
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(stderr):
            code = main(["upload-audit", "http://127.0.0.1:9/"])
        self.assertEqual(code, 2)
        self.assertIn("--lab", stderr.getvalue())

    def test_public_target_is_refused_even_with_lab(self):
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(stderr), \
                tempfile.TemporaryDirectory() as tmp:
            code = main(["upload-audit", "http://1.1.1.1/", "--lab", "--out", tmp])
        self.assertEqual(code, 3)
        self.assertIn("refusing", stderr.getvalue())

    def test_cli_writes_audit_outputs(self):
        with LabServer() as lab, tempfile.TemporaryDirectory() as tmp:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main([
                    "upload-audit", lab.url, "--lab", "--out", tmp, "--quiet",
                ])
            self.assertEqual(code, 0)
            self.assertTrue((Path(tmp) / "upload-audit.md").is_file())
            self.assertTrue((Path(tmp) / "upload-audit.json").is_file())
            self.assertIn("loopback/private only - passed", out.getvalue())


if __name__ == "__main__":
    unittest.main()
