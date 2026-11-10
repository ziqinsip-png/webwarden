from __future__ import annotations

import base64
import contextlib
import hashlib
import html
import io
import json
import re
import socket
import struct
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from webwarden import bundles as bundle_mod
from webwarden import backdoors as backdoor_mod
from webwarden import chains as chain_mod
from webwarden import cli, decoy as decoy_mod, netcheck, whoisq
from webwarden import disclosure
from webwarden import injection as injection_mod
from webwarden.audit import (
    AUDIT_SCHEMA,
    _audit_payload,
    _parse_json_object,
    _scrub,
    heuristic_audit,
    load_scan_result,
    run_audit,
)
from webwarden.checks import (
    FILE_CHECKS,
    Checker,
    _looks_like_not_found,
    _parse_expiry,
    waf_fingerprint,
)
from webwarden.diffing import compare, render_markdown as render_diff, write_diff
from webwarden.dnsq import _encode_name, parse_response
from webwarden.evidence import write_evidence_index
from webwarden.html import render_html
from webwarden.httpclient import HttpClient, HttpResult
from webwarden.models import Finding, ScanResult
from webwarden import recon as recon_mod
from webwarden import sarif as sarif_mod
from webwarden.recon import Probe
from webwarden.report import render_markdown, write_report
from webwarden.secrets import scan_text
from webwarden.takeover import detect_takeovers, match_provider
from webwarden.tokens import cookie_summary, parse_cookie
from webwarden.util import (
    Budget,
    ScopeError,
    in_scope,
    normalize_scope,
    normalize_target,
    parse_ports,
    redact_headers,
)


HOME_HTML = """<html><head><title>Test Site</title></head><body>
<a href="/user/1">profile</a>
<a href="/redirect?url=https%3A%2F%2Fexample.org%2F">go</a>
<a href="/dir/">dir</a>
<script src="/assets/app.js"></script>
</body></html>"""

APP_JS = """(function () {
  var awsKey = "AKIAIOSFODNN7REALKEY";
  var endpoint = "https://api.acme.internal/v1";
  window.cfg = { key: awsKey, endpoint: endpoint };
})();
//# sourceMappingURL=app.js.map
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body=b"", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        origin = self.headers.get("Origin")
        if path == "/":
            headers = {"Content-Type": "text/html; charset=utf-8",
                       "Set-Cookie": "sid=topsecret; Path=/"}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send(200, HOME_HTML, headers)
        elif path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", {"Content-Type": "text/plain"})
        elif path == "/.env":
            self._send(200, "APP_KEY=base64:secret\nDB_PASSWORD=hunter2\n",
                       {"Content-Type": "text/plain"})
        elif path == "/config.php.bak":
            self._send(200, "Forbidden. Password required.",
                       {"Content-Type": "text/plain"})
        elif path == "/user/1":
            self._send(200, '{"id":1,"email":"alice@example.com"}',
                       {"Content-Type": "application/json"})
        elif path == "/dir/":
            self._send(200, "<title>Index of /dir</title>", {"Content-Type": "text/html"})
        elif path == "/redirect":
            target = parse_qs(parsed.query).get("url", ["/"])[0]
            self._send(302, b"", {"Location": target})
        elif path == "/out":
            self._send(302, b"", {"Location": "https://example.org/"})
        elif path == "/echo":
            payload = json.dumps({"cookie": self.headers.get("Cookie", "")})
            self._send(200, payload, {"Content-Type": "application/json"})
        elif path == "/.well-known/security.txt":
            self._send(200, (
                "Contact: mailto:security@example.com\n"
                "Expires: 2030-01-01T00:00:00Z\n"
                "Preferred-Languages: en\n"
            ), {"Content-Type": "text/plain; charset=utf-8"})
        elif path == "/assets/app.js":
            self._send(200, APP_JS,
                       {"Content-Type": "application/javascript"})
        elif path == "/assets/app.js.map":
            self._send(200, json.dumps({
                "version": 3,
                "sources": ["webpack:///src/app.ts", "webpack:///src/api.ts"],
                "mappings": "AAAA,CAAC",
            }), {"Content-Type": "application/json"})
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /hidden/\n",
                       {"Content-Type": "text/plain"})
        elif path == "/hidden/":
            self._send(200, (
                "<html><head><title>Internal staging notes</title></head>"
                "<body>Staging deployment checklist for the billing service.</body>"
                "</html>"
            ), {"Content-Type": "text/html"})
        elif path == "/.htpasswd":
            self._send(200, "admin:$apr1$abcdefgh$0123456789abcdefghij\n",
                       {"Content-Type": "text/plain"})
        elif path == "/dump.sql":
            self._send(200, (
                "CREATE TABLE users (id INT, email TEXT);\n"
                "INSERT INTO users VALUES (1, 'alice@example.com');\n"
            ), {"Content-Type": "text/plain"})
        else:
            self._send(404, "not found", {"Content-Type": "text/plain"})


class CatchAllHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    real_env = False

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.path == "/.env" and self.real_env:
            body = b"APP_KEY=base64:secret\nDB_PASSWORD=hunter2\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        else:
            body = (
                "<html><head><title>Forbidden</title></head><body>"
                f"You don't have permission to access {self.path} on this "
                "server. Password required. Contact: admin@example.com. "
                "Index of /"
                f"<!-- {'notice ' * 100} -->"
                "</body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class SegmentCatchAllHandler(BaseHTTPRequestHandler):
    """One-segment paths 404; every two-segment path echoes its segments."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parts = [part for part in self.path.split("?")[0].split("/") if part]
        if len(parts) < 2:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        else:
            body = json.dumps({
                "code": parts[0],
                "location": parts[1],
                "page": "Merchant manager console",
                "engine": "Tomcat Manager",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class Soft404Handler(BaseHTTPRequestHandler):
    """Every path returns HTTP 200 with a per-path '404 Not Found' page.

    The body varies enough that the similarity-based catch-all guard alone
    would not suppress it; the explicit not-found title must.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        body = (
            "<html><head><title>404 - Page Not Found</title></head><body>"
            f"<h1>Page Not Found</h1><p>The requested URL {self.path} "
            "was not found on this server.</p>"
            f"<!-- {'padding ' * 200}{self.path} -->"
            "</body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class ServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def client(self, **kwargs) -> HttpClient:
        kwargs.setdefault("scopes", ["127.0.0.1"])
        kwargs.setdefault("rate", 100.0)
        kwargs.setdefault("timeout", 5.0)
        kwargs.setdefault("budget", Budget(1000))
        kwargs.setdefault("auth_host", "127.0.0.1")
        return HttpClient(**kwargs)

    def probe(self, client: HttpClient, url: str) -> Probe:
        result = client.get(url)
        return Probe(host="127.0.0.1", url=result.final_url,
                     status=result.status, result=result)


class UtilTests(unittest.TestCase):
    def test_target_normalization(self):
        self.assertEqual(normalize_target("https://Example.COM/path"), "example.com")
        self.assertEqual(normalize_target("example.com:443"), "example.com")
        for bad in ("127.0.0.1", "com", "co.id", "not a domain", ""):
            with self.assertRaises(ScopeError):
                normalize_target(bad)

    def test_scope_checks(self):
        scopes = [normalize_scope("*.example.com"), "127.0.0.1"]
        self.assertTrue(in_scope("app.example.com", scopes))
        self.assertTrue(in_scope("example.com", scopes))
        self.assertFalse(in_scope("example.net", scopes))
        self.assertTrue(in_scope("127.0.0.1", scopes))
        with self.assertRaises(ScopeError):
            normalize_scope("com")

    def test_redaction_and_ports(self):
        redacted = redact_headers({"Cookie": "sid=secret", "Server": "nginx"})
        self.assertEqual(redacted["Cookie"], "<redacted>")
        self.assertEqual(redacted["Server"], "nginx")
        self.assertEqual(parse_ports("80,443,8000-8002", [1]),
                         [80, 443, 8000, 8001, 8002])


class DnsTests(unittest.TestCase):
    def test_encode_name(self):
        self.assertEqual(_encode_name("example.com"),
                         b"\x07example\x03com\x00")

    def test_parse_a_record(self):
        qid = 0x1234
        question = _encode_name("example.com") + struct.pack(">HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + \
            socket.inet_aton("93.184.216.34")
        packet = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer
        self.assertEqual(parse_response(packet, qid),
                         [(1, "93.184.216.34", 300)])

    def test_transaction_mismatch(self):
        packet = struct.pack(">HHHHHH", 1, 0x8180, 0, 0, 0, 0)
        with self.assertRaises(ValueError):
            parse_response(packet, 2)


class NetcheckTests(unittest.TestCase):
    def _resolver(self, apex, ns=(), wildcard=()):
        answers = {
            ("example.com", "A"): list(apex),
            ("example.com", "NS"): list(ns),
            ("wildcard", "A"): list(wildcard),
        }

        class Resolver:
            def query(self, name, qtype="A"):
                key = (name, qtype)
                if key in answers:
                    return list(answers[key])
                if qtype == "A" and name.endswith(".example.com"):
                    return list(wildcard)
                return []

        return Resolver()

    def test_blocks_rpz_nameserver_and_block_page(self):
        resolver = self._resolver(
            ["202.169.44.80"],
            ns=["ns1.biznet.safesurf."],
            wildcard=["202.169.44.80"],
        )
        page = {"address": "202.169.44.80", "status": 302,
                "location": "https://www.biznetnetworks.com/safesurf",
                "marker": "safesurf"}
        with mock.patch.object(netcheck, "_doh_a",
                               return_value=["162.159.130.10"]), \
                mock.patch.object(netcheck, "_block_page", return_value=page):
            report = netcheck.preflight("example.com", resolver)
        self.assertTrue(report.blocked)
        self.assertTrue(any("safesurf" in item for item in report.reasons))
        self.assertTrue(any("block page" in item for item in report.reasons))
        self.assertEqual(report.details["block_page"]["marker"], "safesurf")

    def test_blocks_mismatch_plus_wildcard(self):
        resolver = self._resolver(
            ["202.169.44.80"], wildcard=["202.169.44.80"]
        )
        with mock.patch.object(netcheck, "_doh_a",
                               return_value=["162.159.130.10"]), \
                mock.patch.object(netcheck, "_block_page", return_value=None):
            report = netcheck.preflight("example.com", resolver)
        self.assertTrue(report.blocked)
        self.assertTrue(any("wildcard" in item for item in report.reasons))

    def test_mismatch_without_wildcard_is_only_a_warning(self):
        resolver = self._resolver(["198.51.100.10"])
        with mock.patch.object(netcheck, "_doh_a",
                               return_value=["203.0.113.20"]), \
                mock.patch.object(netcheck, "_block_page", return_value=None):
            report = netcheck.preflight("example.com", resolver)
        self.assertFalse(report.blocked)
        self.assertTrue(report.warnings)
        self.assertFalse(report.reasons)

    def test_clean_resolution_is_not_flagged(self):
        resolver = self._resolver(["93.184.216.34"])
        with mock.patch.object(netcheck, "_doh_a",
                               return_value=["93.184.216.34"]), \
                mock.patch.object(netcheck, "_block_page", return_value=None):
            report = netcheck.preflight("example.com", resolver)
        self.assertFalse(report.blocked)
        self.assertFalse(report.reasons)
        self.assertFalse(report.warnings)


class WhoisTests(unittest.TestCase):
    def test_parse_registry_text(self):
        sample = (
            "Domain Name: EXAMPLE.COM\n"
            "Registrar: RESERVED-Internet Assigned Numbers Authority\n"
            "Creation Date: 1995-08-14T04:00:00Z\n"
            "Registry Expiry Date: 2026-08-13T04:00:00Z\n"
            "Name Server: A.IANA-SERVERS.NET\n"
            "Name Server: B.IANA-SERVERS.NET\n"
            "Registrant Organization: Example Org\n"
            "Registrant Country: US\n"
        )
        parsed = whoisq._parse(sample)
        self.assertEqual(parsed["registrar"],
                         "RESERVED-Internet Assigned Numbers Authority")
        self.assertEqual(parsed["name_servers"],
                         ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertEqual(parsed["country"], "US")


class HttpClientTests(ServerTestCase):
    def test_scope_enforced(self):
        client = self.client(scopes=["example.com"])
        result = client.get(self.base)
        self.assertIn("out of scope", result.error or "")
        self.assertFalse(result.ok)

    def test_auth_not_sent_over_http_by_default(self):
        client = self.client(auth_headers={"Cookie": "sid=alice"},
                             allow_auth_http=False)
        result = client.get(self.base + "echo", auth=True)
        self.assertFalse(result.auth_used)
        self.assertIn("plain HTTP", result.auth_skipped or "")
        self.assertEqual(json.loads(result.text)["cookie"], "")

    def test_auth_sent_when_explicitly_allowed(self):
        client = self.client(auth_headers={"Cookie": "sid=alice"},
                             allow_auth_http=True)
        result = client.get(self.base + "echo", auth=True)
        self.assertTrue(result.auth_used)
        self.assertEqual(json.loads(result.text)["cookie"], "sid=alice")

    def test_read_limit_marks_truncation(self):
        client = self.client()
        short = client.get(self.base, read_limit=10)
        self.assertTrue(short.truncated)
        self.assertLessEqual(len(short.body), 10)
        full = client.get(self.base, read_limit=1024 * 1024,
                          max_bytes=1024 * 1024)
        self.assertFalse(full.truncated)
        self.assertIn(b"Test Site", full.body)

    def test_redirect_out_of_scope_not_followed(self):
        client = self.client()
        result = client.get(self.base + "out", follow=True)
        self.assertEqual(result.status, 302)
        self.assertIn("x-webwarden-redirect", result.headers)
        self.assertEqual(len(result.chain), 1)


class CheckerTests(ServerTestCase):
    def setUp(self):
        self.client = self.client(allow_auth_http=True,
                                  auth_headers={"Cookie": "session=alice"})
        self.base_probe = self.probe(self.client, self.base)
        self.dir_probe = self.probe(self.client, self.base + "dir/")
        urls = [
            self.base + "user/1",
            self.base + "redirect?url=https%3A%2F%2Fexample.org",
            self.base + "account?access_token=abc123secret",
        ]
        self.checker = Checker(
            self.client,
            [self.base_probe, self.dir_probe],
            urls,
            auth_a={"Cookie": "session=alice"},
            auth_host="127.0.0.1",
            robots={"127.0.0.1": ["/hidden/"]},
            robots_paths=True,
        )
        self.findings = self.checker.run()
        self.titles = {finding.title for finding in self.findings}

    def test_client_side_secrets_and_source_maps(self):
        self.assertIn("AWS access key ID exposed in client-side content",
                      self.titles)
        secret = next(f for f in self.findings
                      if f.title.startswith("AWS access key ID exposed"))
        self.assertEqual(secret.severity, "high")
        self.assertTrue(secret.verified)
        self.assertNotIn("AKIAIOSFODNN7REALKEY", secret.evidence)
        self.assertIn("<redacted>", secret.evidence)
        self.assertGreaterEqual(self.checker.secret_files, 2)
        self.assertEqual(len(self.checker.secret_hits), 1)
        self.assertEqual(self.checker.secret_hits[0]["kind"],
                         "AWS access key ID")
        self.assertIn("JavaScript source map published", self.titles)
        self.assertTrue(any(entry["url"].endswith("app.js.map")
                            for entry in self.checker.source_maps))

    def test_url_token_is_flagged_without_being_requested(self):
        finding = next(f for f in self.findings
                       if f.category == "url-tokens")
        self.assertEqual(finding.severity, "medium")
        self.assertFalse(finding.verified)
        self.assertNotIn("abc123secret", finding.url)
        self.assertNotIn("abc123secret", finding.evidence)
        self.assertIn("never replayed", finding.verification)
        self.assertEqual(self.checker.url_token_count, 1)

    def test_robots_paths_are_reported(self):
        finding = next(f for f in self.findings
                       if f.title.startswith("robots.txt Disallow paths"))
        self.assertEqual(finding.severity, "info")
        self.assertIn("/hidden/", finding.evidence)

    def test_new_exposure_checks(self):
        self.assertIn("Apache .htpasswd exposed", self.titles)
        self.assertIn("Database dump downloadable", self.titles)

    def test_headers_and_cookies(self):
        self.assertIn("Security headers not fully configured", self.titles)
        sid = next(f for f in self.findings
                   if f.title.startswith("Sensitive cookie sid"))
        self.assertEqual(sid.severity, "medium")
        self.assertIn("Session-like cookie transmitted over plaintext HTTP",
                      self.titles)
        matrix = self.checker.header_matrix
        self.assertGreaterEqual(len(matrix), 2)
        for entry in matrix:
            self.assertIn("present", entry)
            self.assertIn("url", entry)

    def test_security_txt_parsed(self):
        entry = self.checker.security_txt.get("127.0.0.1")
        self.assertIsNotNone(entry)
        self.assertTrue(entry["valid"])
        self.assertIn("mailto:security@example.com", entry["contacts"])
        self.assertFalse(entry["expired"])
        self.assertIn("security.txt published", self.titles)

    def test_exposed_files(self):
        self.assertIn("Exposed .git directory", self.titles)
        self.assertIn("Exposed .env file", self.titles)
        self.assertNotIn("PHP config backup exposed", self.titles)

    def test_cors(self):
        self.assertIn("CORS allows credentialed requests from any origin",
                      self.titles)

    def test_directory_listing(self):
        self.assertIn("Directory listing enabled", self.titles)

    def test_open_redirect(self):
        self.assertIn("Open redirect", self.titles)

    def test_possible_idor(self):
        self.assertTrue(any("possible IDOR" in title for title in self.titles))

    def test_evidence_is_verbatim_and_unredacted(self):
        blob = "\n".join(finding.evidence for finding in self.findings)
        self.assertIn("DB_PASSWORD=hunter2", blob)
        self.assertIn("APP_KEY=base64:secret", blob)
        self.assertIn("sid=topsecret", blob)
        env = next(f for f in self.findings if f.title == "Exposed .env file")
        self.assertEqual(len(env.evidence_sha256), 64)
        self.assertGreater(env.evidence_bytes, 0)
        self.assertFalse(env.evidence_truncated)

    def test_evidence_files_are_complete_and_poc_saves_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            checker = Checker(
                self.client,
                [self.base_probe, self.dir_probe],
                [self.base + "user/1"],
                auth_a={"Cookie": "session=alice"},
                auth_host="127.0.0.1",
                evidence_dir=Path(tmp) / "evidence",
            )
            findings = checker.run()
            env = next(f for f in findings if f.title == "Exposed .env file")
            self.assertTrue(env.evidence_file.startswith("evidence/"))
            raw_path = Path(tmp) / env.evidence_file
            self.assertTrue(raw_path.exists())
            raw = raw_path.read_bytes()
            self.assertIn(b"DB_PASSWORD=hunter2", raw)
            self.assertEqual(len(raw), env.evidence_bytes)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             env.evidence_sha256)
            poc = "\n".join(env.poc)
            self.assertIn("sha256sum", poc)
            self.assertIn("--max-time 30", poc)
            self.assertNotIn("head -c", poc)
            index = write_evidence_index(Path(tmp), findings)
            self.assertIsNotNone(index)
            payload = json.loads(index.read_text(encoding="utf-8"))
            self.assertTrue(payload["entries"])
            self.assertTrue(payload["entries"][0]["files"])

    def test_exposures_are_reverified(self):
        git = next(f for f in self.findings
                   if f.title == "Exposed .git directory")
        self.assertTrue(git.verified)
        self.assertIn("two independent requests", git.verification)

    def test_cors_and_redirect_are_reproduced(self):
        cors = next(f for f in self.findings if f.category == "cors")
        redirect = next(f for f in self.findings if f.category == "redirect")
        self.assertTrue(cors.verified)
        self.assertIn("two distinct origins", cors.verification)
        self.assertTrue(redirect.verified)
        self.assertIn("two distinct external hosts", redirect.verification)

    def test_poc_commands_are_read_only_and_secret_free(self):
        for finding in self.findings:
            for command in finding.poc:
                self.assertNotIn("topsecret", command)
                self.assertNotIn("session=alice", command)
                self.assertNotIn("--data", command)
                self.assertNotIn(" -X POST", command)
                self.assertNotIn(" -X PUT", command)
        idor = [f for f in self.findings if f.category == "access-control"]
        self.assertTrue(idor)
        self.assertTrue(any(
            "$SESSION_A" in command
            for finding in idor for command in finding.poc
        ))


class TokenTests(unittest.TestCase):
    @staticmethod
    def _jwt(claims: dict) -> str:
        def encode(value: dict) -> str:
            raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        return f"{encode({'alg': 'HS256', 'typ': 'JWT'})}.{encode(claims)}.c2ln"

    def test_public_jwt_is_classified_anonymous(self):
        token = self._jwt({"purpose": "access", "scope": "public",
                           "exp": 1900000000, "sub": "device-1"})
        view = parse_cookie(f"access_token_web={token}; Path=/; SameSite=Lax")
        self.assertTrue(view.anonymous)
        self.assertFalse(view.sensitive)
        self.assertIn("public", view.reason)
        self.assertIn("purpose=access", cookie_summary(view))

    def test_authenticated_jwt_is_sensitive(self):
        token = self._jwt({"purpose": "access", "scope": "read:profile",
                           "sub": "user-1"})
        view = parse_cookie(f"access_token_web={token}; Secure; HttpOnly")
        self.assertTrue(view.sensitive)
        self.assertFalse(view.anonymous)
        self.assertEqual(view.missing(), ["SameSite"])

    def test_opaque_session_cookie_is_sensitive(self):
        view = parse_cookie("sid=opaquevalue; Path=/")
        self.assertTrue(view.sensitive)
        self.assertEqual(view.missing(), ["Secure", "HttpOnly", "SameSite"])

    def test_summary_never_contains_the_value(self):
        token = self._jwt({"purpose": "access", "scope": "public"})
        view = parse_cookie(f"access_token_web={token}; Path=/")
        summary = cookie_summary(view)
        self.assertNotIn(token, summary)
        self.assertNotIn(token.split(".")[1], summary)
        self.assertNotIn("value", view.to_dict())

    def test_plaintext_findings_are_ranked_by_claims(self):
        sensitive = self._jwt({"purpose": "access", "scope": "read:profile",
                               "sub": "user-1"})
        public = self._jwt({"purpose": "access", "scope": "public"})
        cookies = [
            f"access_token_web={sensitive}; Path=/; SameSite=Lax",
            f"refresh_token_web={public}; Path=/; SameSite=Lax",
            "sid=opaque-session; Path=/",
        ]
        result = HttpResult(
            url="http://example.com/",
            status=200,
            ok=True,
            headers={"content-type": "text/html; charset=utf-8"},
            set_cookies=cookies,
            body=b"<html><body>cleartext</body></html>",
            chain=[("http://example.com/", 200)],
        )
        checker = Checker(mock.Mock(scopes=["example.com"]), [], [])
        checker._check_plaintext_tokens("example.com", result.url, result)
        by_severity = {}
        for finding in checker.findings:
            self.assertEqual(finding.category, "tokens")
            self.assertTrue(finding.verified)
            by_severity[finding.severity] = finding.title
        self.assertEqual(
            by_severity["high"],
            "Authenticated session token transmitted over plaintext HTTP")
        self.assertEqual(
            by_severity["medium"],
            "Session-like cookie transmitted over plaintext HTTP")
        self.assertEqual(
            by_severity["info"],
            "Anonymous/public token transmitted over plaintext HTTP")
        for finding in checker.findings:
            self.assertNotIn(sensitive, finding.evidence)
            self.assertNotIn(public, finding.evidence)
            self.assertIn("<redacted>", finding.evidence)
            self.assertIn("not decoded for", finding.evidence)


class HeaderAggregationTests(unittest.TestCase):
    FULL_HEADERS = {
        "content-type": "text/html; charset=utf-8",
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }

    @staticmethod
    def _result(url: str, headers: dict) -> HttpResult:
        return HttpResult(
            url=url, status=200, ok=True, headers=dict(headers),
            body=b"<html><body>page</body></html>",
            chain=[(url, 200)],
        )

    def test_partial_coverage_is_informational(self):
        checker = Checker(mock.Mock(scopes=["example.com"]), [], [])
        checker._record_headers(self._result("https://example.com/", self.FULL_HEADERS))
        checker._record_headers(self._result(
            "http://example.com/", {"content-type": "text/html"}))
        checker._finalize_headers()
        titles = {finding.title: finding for finding in checker.findings}
        self.assertIn("Security headers applied inconsistently across endpoints",
                      titles)
        self.assertEqual(
            titles["Security headers applied inconsistently across endpoints"]
            .severity, "info")
        self.assertNotIn("Security headers not fully configured", titles)

    def test_site_wide_gap_is_low(self):
        checker = Checker(mock.Mock(scopes=["example.com"]), [], [])
        headers = {"content-type": "text/html"}
        checker._record_headers(self._result("https://example.com/", headers))
        checker._record_headers(self._result("https://example.com/api", headers))
        checker._finalize_headers()
        finding = next(
            item for item in checker.findings
            if item.title == "Security headers not fully configured")
        self.assertEqual(finding.severity, "low")
        self.assertIn("all 2 HTML endpoint(s)", finding.description)

    def test_matrix_marks_each_header(self):
        checker = Checker(mock.Mock(scopes=["example.com"]), [], [])
        checker._record_headers(self._result("https://example.com/", self.FULL_HEADERS))
        entry = checker.header_matrix[0]
        self.assertTrue(entry["present"]["Strict-Transport-Security"])
        self.assertTrue(entry["present"]["Content-Security-Policy"])
        self.assertFalse(entry["missing"])


class SecurityTxtTests(unittest.TestCase):
    class StubClient:
        scopes = ["example.com"]

        def __init__(self, body: bytes, content_type: str = "text/plain"):
            self.body = body
            self.content_type = content_type

        def get(self, url, **kwargs):
            if url.endswith("security.txt"):
                return HttpResult(
                    url=url, status=200, ok=True,
                    headers={"content-type": self.content_type},
                    body=self.body, chain=[(url, 200)],
                )
            return HttpResult(url=url, status=404, ok=False, chain=[(url, 404)])

    def test_expired_security_txt_is_low(self):
        client = self.StubClient(
            b"Contact: mailto:security@example.com\n"
            b"Expires: 2020-01-01T00:00:00Z\n")
        checker = Checker(client, [], [])
        probe = Probe(host="example.com", url="https://example.com/", status=200)
        checker._check_security_txt(probe)
        entry = checker.security_txt["example.com"]
        self.assertTrue(entry["valid"])
        self.assertTrue(entry["expired"])
        finding = checker.findings[0]
        self.assertEqual(finding.title, "security.txt has expired")
        self.assertEqual(finding.severity, "low")

    def test_html_page_is_rejected(self):
        client = self.StubClient(b"<!doctype html><html>not a txt</html>",
                                 "text/html")
        checker = Checker(client, [], [])
        probe = Probe(host="example.com", url="https://example.com/", status=200)
        checker._check_security_txt(probe)
        entry = checker.security_txt["example.com"]
        self.assertFalse(entry["valid"])
        self.assertIn("HTML", entry["reason"])
        self.assertFalse(checker.findings)

    def test_missing_contact_is_rejected(self):
        client = self.StubClient(b"Expires: 2030-01-01T00:00:00Z\n")
        checker = Checker(client, [], [])
        probe = Probe(host="example.com", url="https://example.com/", status=200)
        checker._check_security_txt(probe)
        self.assertFalse(checker.security_txt["example.com"]["valid"])
        self.assertFalse(checker.findings)

    def test_expiry_parser(self):
        moment = _parse_expiry("2030-01-01T00:00:00Z")
        self.assertIsNotNone(moment)
        self.assertEqual(moment.year, 2030)
        self.assertIsNone(_parse_expiry("not-a-date"))


class DisclosureDetectorTests(unittest.TestCase):
    DJANGO = (
        b"<h1>DisallowedHost at /</h1>"
        b"<p>You're seeing this error because you have <code>DEBUG = True</code>"
        b" in your Django settings file.</p>"
    )

    def test_django_debug_page(self):
        self.assertEqual(disclosure.match_error(self.DJANGO)["kind"], "django")

    def test_php_fatal_error(self):
        body = (b"<b>Fatal error</b>: Uncaught Error: boom in "
                b"<b>/var/www/html/index.php</b> on line <b>12</b>")
        self.assertEqual(disclosure.match_error(body)["kind"], "php_fatal")

    def test_php_notice_is_low(self):
        body = (b"<b>Warning</b>: include(config.php): failed to open stream "
                b"in <b>/home/site/public_html/app.php</b> on line <b>7</b>")
        signature = disclosure.match_error(body)
        self.assertEqual(signature["kind"], "php_notice")
        self.assertEqual(signature["severity"], "low")

    def test_sql_error_page(self):
        body = (b"You have an error in your SQL syntax; check the manual that "
                b"corresponds to your MySQL server version at line 1")
        self.assertEqual(disclosure.match_error(body)["kind"], "sql_error")

    def test_python_traceback(self):
        body = (b'Traceback (most recent call last):\n  File "/srv/app/main.py", '
                b"line 42, in <module>\nValueError: boom")
        self.assertEqual(
            disclosure.match_error(body)["kind"], "python_traceback")

    def test_werkzeug_console_is_critical(self):
        body = (b"<title>Werkzeug Debugger</title><p>Console mode: active</p>"
                b"<p>Debugger PIN: 123-456-789</p>")
        signature = disclosure.match_error(body)
        self.assertEqual(signature["kind"], "werkzeug")
        self.assertEqual(signature["severity"], "critical")

    def test_plain_page_is_not_an_error(self):
        body = (b"<html><body><h1>Selamat datang</h1>"
                b"<p>Warning: pakai helm saat berkendara.</p></body></html>")
        self.assertIsNone(disclosure.match_error(body))

    def test_excerpt_is_a_single_line(self):
        signature = disclosure.match_error(self.DJANGO)
        excerpt = disclosure.error_excerpt(self.DJANGO, signature)
        self.assertIn("DEBUG = True", excerpt)
        self.assertNotIn("\n", excerpt)

    def test_json_array_of_records(self):
        body = json.dumps([
            {"id": 1, "email": "a@example.com", "name": "A"},
            {"id": 2, "email": "b@example.com", "name": "B"},
        ]).encode()
        info = disclosure.json_collection(
            body, {"content-type": "application/json; charset=utf-8"})
        self.assertEqual(info["count"], 2)
        self.assertEqual(info["shape"], "array")
        self.assertIn("email", info["sensitive"])

    def test_json_wrapped_collection(self):
        body = json.dumps({"data": [
            {"id": 1, "username": "a"},
            {"id": 2, "username": "b"},
        ]}).encode()
        info = disclosure.json_collection(
            body, {"content-type": "application/json"})
        self.assertEqual(info["shape"], "data")

    def test_single_record_is_not_a_collection(self):
        body = json.dumps({"id": 1, "email": "a@example.com"}).encode()
        self.assertIsNone(disclosure.json_collection(
            body, {"content-type": "application/json"}))

    def test_scalar_array_is_not_a_collection(self):
        body = json.dumps(["a", "b", "c"]).encode()
        self.assertIsNone(disclosure.json_collection(
            body, {"content-type": "application/json"}))

    def test_html_is_not_json(self):
        self.assertIsNone(disclosure.json_collection(
            b"<html><body>ok</body></html>", {"content-type": "text/html"}))


class DisclosureCheckerTests(unittest.TestCase):
    class Client:
        scopes = ["example.com"]

        def __init__(self, routes):
            self.routes = routes
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append(url)
            path = urlsplit(url).path
            if path in self.routes:
                status, headers, body = self.routes[path]
                return HttpResult(
                    url=url, status=status, ok=True, headers=headers,
                    body=body, chain=[(url, status)],
                )
            return HttpResult(url=url, status=404, ok=False, headers={},
                              body=b"not found", chain=[(url, 404)])

    def _result(self, path, body, status=200,
                content_type="text/html"):
        url = "https://example.com" + path
        return HttpResult(
            url=url, status=status, ok=True,
            headers={"content-type": content_type}, body=body,
            chain=[(url, status)],
        )

    def test_error_page_is_reported_and_reproduced(self):
        body = DisclosureDetectorTests.DJANGO
        client = self.Client({"/boom": (500, {"content-type": "text/html"}, body)})
        checker = Checker(client, [], [])
        result = self._result("/boom", body, status=500)
        checker._check_error_pages(
            [("example.com", "https://example.com/boom", result)])
        self.assertEqual(len(checker.findings), 1)
        finding = checker.findings[0]
        self.assertEqual(finding.severity, "high")
        self.assertTrue(finding.verified)
        self.assertIn("DEBUG = True", finding.evidence)

    def test_unstable_error_page_needs_manual_review(self):
        body = DisclosureDetectorTests.DJANGO
        client = self.Client({
            "/boom": (500, {"content-type": "text/html"}, body),
        })
        checker = Checker(client, [], [])
        result = self._result("/boom", body, status=500)

        original = client.get
        state = {"first": True}

        def flaky(url, **kwargs):
            state["first"] = False
            return HttpResult(url=url, status=200, ok=True,
                              headers={"content-type": "text/html"},
                              body=b"<html>selamat datang</html>",
                              chain=[(url, 200)])

        client.get = flaky
        checker._check_error_pages(
            [("example.com", "https://example.com/boom", result)])
        finding = checker.findings[0]
        self.assertFalse(finding.verified)
        self.assertEqual(finding.confidence, "needs manual verification")

    def test_json_collection_is_reported(self):
        body = json.dumps([
            {"id": 1, "email": "a@example.com"},
            {"id": 2, "email": "b@example.com"},
        ]).encode()
        client = self.Client({
            "/api/users": (200, {"content-type": "application/json"}, body),
        })
        checker = Checker(client, [], [])
        result = self._result("/api/users", body,
                              content_type="application/json")
        checker._check_json_collections(
            [("example.com", "https://example.com/api/users", result)])
        self.assertEqual(len(checker.findings), 1)
        finding = checker.findings[0]
        self.assertEqual(finding.severity, "high")
        self.assertTrue(finding.verified)
        self.assertIn("Fields:", finding.evidence)
        self.assertNotIn("a@example.com", finding.evidence)

    def test_catch_all_json_is_not_reported(self):
        body = json.dumps([
            {"id": 1, "email": "a@example.com"},
            {"id": 2, "email": "b@example.com"},
        ]).encode()
        client = self.Client({
            "/api/users": (200, {"content-type": "application/json"}, body),
        })
        original = client.get

        def everything(url, **kwargs):
            result = original(url, **kwargs)
            if result.status == 404:
                result.status = 200
                result.ok = True
                result.headers = {"content-type": "application/json"}
                result.body = body
            return result

        client.get = everything
        checker = Checker(client, [], [])
        result = self._result("/api/users", body,
                              content_type="application/json")
        checker._check_json_collections(
            [("example.com", "https://example.com/api/users", result)])
        self.assertFalse(checker.findings)


class SecretTests(unittest.TestCase):
    def test_high_confidence_patterns(self):
        text = (
            'var a = "AKIAIOSFODNN7REALKEY";\n'
            'var b = "ghp_' + "a" * 36 + '";\n'
            'var c = "sk_live_' + "Z" * 24 + '";\n'
        )
        hits = scan_text(text)
        kinds = {hit.kind for hit in hits}
        self.assertIn("AWS access key ID", kinds)
        self.assertIn("GitHub token", kinds)
        self.assertIn("Stripe secret key", kinds)
        self.assertEqual(len(hits), 3)

    def test_placeholders_are_ignored(self):
        text = (
            'var a = "AKIAIOSFODNN7EXAMPLE";\n'
            '// sample key below\n'
            'var b = "AKIAIOSFODNN7REALKEY";\n'
        )
        hits = scan_text(text)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].kind, "AWS access key ID")

    def test_document_slug_is_not_an_api_key(self):
        text = (
            "https://example.sch.id/files/"
            "sk-tugas-tambahan-sebagai-koordinator-dan-subkoordinator-"
            "kelompok-kerja-pokja.pdf\n"
            "Nama berkas: sk-tugas-tambahan-sebagai-koordinator-dan-"
            "subkoordinator-kelompok-kerja-pokja\n"
        )
        self.assertEqual(scan_text(text), [])

    def test_real_openai_keys_are_still_detected(self):
        project = "sk-proj-" + "Q2x9vL8mN4pR7tY1uI6oK3jH5gF0dS2aQ8wE4rT6yU1iO9pL3k"
        legacy = "sk-" + "Q2x9vL8mN4pR7tY1uI6oK3jH5gF0dS2aQ8wE4rT6yU1iO"
        hits = scan_text(f'const a = "{project}";\nconst b = "{legacy}";\n')
        self.assertEqual(len(hits), 2)
        self.assertEqual({hit.kind for hit in hits}, {"OpenAI API key"})

    def test_key_shaped_filename_is_ignored(self):
        text = '"sk-Q2x9vL8mN4pR7tY1uI6oK3jH5gF0dS2aQ8wE4rT6yU1iO.zip"'
        self.assertEqual(scan_text(text), [])

    def test_redaction_never_reveals_the_value(self):
        hit = scan_text('"AKIAIOSFODNN7REALKEY"')[0]
        self.assertNotIn("IOSFODNN7", hit.redacted)
        self.assertNotIn("IOSFODNN7", hit.context)
        self.assertEqual(len(hit.fingerprint), 12)
        payload = hit.to_dict()
        self.assertNotIn("value", payload)
        self.assertNotIn("AKIAIOSFODNN7REALKEY", json.dumps(payload))

    def test_url_token_severity(self):
        client = HttpClient(scopes=["example.com"], rate=100.0,
                            budget=Budget(10))
        checker = Checker(client, [], [])
        self.assertEqual(
            checker._url_token_severity("https", "access_token", "abc123"), "low")
        self.assertEqual(
            checker._url_token_severity("http", "access_token", "abc123"), "medium")
        self.assertEqual(
            checker._url_token_severity("https", "signature", "abc123"), "info")
        self.assertIsNone(
            checker._url_token_severity("https", "page", "abc123"))



class BypassHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body=b"", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlsplit(self.path).path
        trusted = self.headers.get("X-Forwarded-For") == "127.0.0.1"
        if path == "/":
            self._send(200, "<html><title>Test</title>home</html>",
                       {"Content-Type": "text/html"})
        elif path == "/.env" and trusted:
            self._send(200, "APP_KEY=base64:secret\nDB_PASSWORD=hunter2\n",
                       {"Content-Type": "text/plain"})
        elif path == "/admin/" and trusted:
            self._send(200, "<html><title>Admin</title>"
                            "Admin Dashboard logout users</html>",
                       {"Content-Type": "text/html"})
        elif path == "/phpmyadmin/" and trusted:
            self._send(200, "<html><title>phpMyAdmin</title>"
                            "phpMyAdmin login<form>password</form></html>",
                       {"Content-Type": "text/html"})
        elif path in ("/.env", "/admin/", "/phpmyadmin/"):
            self._send(403, "forbidden", {"Content-Type": "text/plain"})
        else:
            self._send(404, "not found", {"Content-Type": "text/plain"})


class ServerHarness(unittest.TestCase):
    handler = Handler

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), cls.handler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)


class CatchAllPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CatchAllHandler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def run_checker(self) -> set[str]:
        client = HttpClient(scopes=["127.0.0.1"], rate=100.0, timeout=5.0,
                            budget=Budget(1000), auth_host="127.0.0.1")
        result = client.get(self.base)
        probe = Probe(host="127.0.0.1", url=result.final_url,
                      status=result.status, result=result)
        return {finding.title for finding in Checker(client, [probe], []).run()}

    def test_catch_all_page_is_not_an_exposure(self):
        titles = self.run_checker()
        for title in (
            "PHP config backup exposed",
            "phpMyAdmin reachable",
            "Admin interface reachable",
            "WordPress admin reachable",
            "security.txt present",
            "Directory listing enabled",
            "Exposed .env file",
        ):
            self.assertNotIn(title, titles)

    def test_real_file_detected_on_catch_all_host(self):
        CatchAllHandler.real_env = True
        self.addCleanup(setattr, CatchAllHandler, "real_env", False)
        self.assertIn("Exposed .env file", self.run_checker())


class SegmentCatchAllTests(unittest.TestCase):
    """A two-segment echo route must not be reported as a Tomcat manager."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), SegmentCatchAllHandler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def run_checker(self) -> set[str]:
        client = HttpClient(scopes=["127.0.0.1"], rate=100.0, timeout=5.0,
                            budget=Budget(1000), auth_host="127.0.0.1")
        result = client.get(self.base)
        probe = Probe(host="127.0.0.1", url=result.final_url,
                      status=result.status, result=result)
        return {finding.title for finding in Checker(client, [probe], []).run()}

    def test_two_segment_echo_route_is_not_tomcat_manager(self):
        self.assertNotIn("Tomcat manager reachable", self.run_checker())

    def test_same_shape_control_path_returns_the_template(self):
        client = HttpClient(scopes=["127.0.0.1"], rate=100.0, timeout=5.0,
                            budget=Budget(1000), auth_host="127.0.0.1")
        control = client.get(
            self.base + "webwarden-missing-alpha/webwarden-missing-beta")
        self.assertEqual(control.status, 200)
        self.assertIn("Tomcat Manager", control.text)


class Soft404Tests(unittest.TestCase):
    """A 200 'not found' page must not be reported as an exposure."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Soft404Handler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def run_checker(self) -> set[str]:
        client = HttpClient(scopes=["127.0.0.1"], rate=100.0, timeout=5.0,
                            budget=Budget(1000), auth_host="127.0.0.1")
        result = client.get(self.base)
        probe = Probe(host="127.0.0.1", url=result.final_url,
                      status=result.status, result=result)
        return {finding.title for finding in Checker(client, [probe], []).run()}

    def test_soft_404_is_not_an_exposure(self):
        titles = self.run_checker()
        for title in (
            "Admin interface reachable",
            "WordPress admin reachable",
            "phpMyAdmin reachable",
            "Directory listing enabled",
            "Exposed .env file",
        ):
            self.assertNotIn(title, titles)

    def test_not_found_detector_positive(self):
        for body in (
            b"<html><head><title>404 - Page Not Found</title></head></html>",
            b"<html><head><title>Error 404</title></head><body>x</body></html>",
            b"<html><body><h1>Page Not Found</h1></body></html>",
            b"<html><head><title>Halaman Tidak Ditemukan</title></head></html>",
            b"<html><body><h1>404</h1></body></html>",
        ):
            self.assertTrue(_looks_like_not_found(body), body)

    def test_not_found_detector_negative(self):
        for body in (
            b"<html><head><title>Admin Login</title></head><body>404 users</body></html>",
            b"<html><head><title>Dashboard</title></head><body>error 404 logged</body></html>",
            b"APP_KEY=base64:secret\nDB_PASSWORD=hunter2\n",
            b"<html><head><title>Found Objects Gallery</title></head></html>",
            b"ref: refs/heads/main\n",
        ):
            self.assertFalse(_looks_like_not_found(body), body)


class BypassTests(ServerHarness):
    handler = BypassHandler

    def make_checker(self, bypass: bool = True) -> Checker:
        client = HttpClient(scopes=["127.0.0.1"], rate=100.0, timeout=5.0,
                            budget=Budget(1000), auth_host="127.0.0.1")
        result = client.get(self.base)
        probe = Probe(host="127.0.0.1", url=result.final_url,
                      status=result.status, result=result)
        return Checker(client, [probe], [], bypass=bypass,
                       bypass_max_paths=4, bypass_max_variants=10)

    def test_bypass_findings_are_reproduced(self):
        checker = self.make_checker()
        findings = checker.run()
        titles = {finding.title for finding in findings}
        self.assertIn("401/403 bypass: Exposed .env file", titles)
        self.assertIn("401/403 bypass: Admin interface reachable", titles)
        self.assertNotIn("401/403 bypass: phpMyAdmin reachable", titles)

        env = next(f for f in findings if "Exposed .env" in f.title)
        self.assertTrue(env.verified)
        self.assertEqual(env.confidence, "confirmed")
        self.assertIn("reproduced twice", env.verification)
        self.assertIn("still HTTP 403", env.verification)
        poc = "\n".join(env.poc)
        self.assertNotIn("hunter2", poc)
        self.assertIn("expect HTTP 401/403", poc)

        attempts = checker.bypass_attempts
        self.assertTrue(any(a["bypass"] for a in attempts))
        self.assertTrue(any(a["path"] == "/phpmyadmin/" and not a["bypass"]
                            for a in attempts))

    def test_bypass_is_opt_in(self):
        titles = {finding.title for finding in self.make_checker(False).run()}
        self.assertFalse(any("401/403 bypass" in title for title in titles))


class ReportTests(unittest.TestCase):
    def test_render_and_write(self):
        result = ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="0.1.0",
            started_at="2026-10-26T00:00:00Z",
            finished_at="2026-10-26T00:10:00Z",
            stats={"subdomains": 2, "live_hosts": 1, "open_ports": 1,
                   "urls": 3, "requests": 12},
            recon={"addresses": {"A": ["93.184.216.34"], "AAAA": []},
                   "dns": {"NS": ["a.iana-servers.net"]},
                   "whois": {"registrar": "RESERVED", "name_servers": []},
                   "subdomains": {"total": ["example.com"]},
                   "hosts": [], "ports": {"ports": [
                       {"ip": "93.184.216.34", "port": 443, "service": "https"}]},
                   "headers": {
                       "matrix": [{
                           "url": "https://example.com/", "status": 200,
                           "present": {"Strict-Transport-Security": True,
                                       "Content-Security-Policy": False},
                       }],
                       "security_txt": {"example.com": {
                           "valid": True, "contacts": ["mailto:sec@example.com"],
                           "expires": "2030-01-01T00:00:00Z", "expired": False,
                       }},
                   },
                   "client": {
                       "files_scanned": 4, "secrets": 1, "url_tokens": 2,
                       "source_maps": [{
                           "url": "https://example.com/app.js.map",
                           "script": "https://example.com/app.js",
                           "sources": 2, "mappings": True,
                       }],
                       "secret_hits": [{
                           "host": "example.com", "kind": "AWS access key ID",
                           "severity": "high", "redacted": "AKIA...MNOP (len 20)",
                           "files": ["https://example.com/app.js"],
                       }],
                       "robots_paths": True,
                   },
                   "urls": ["https://example.com/"]},
            findings=[Finding(
                title="Exposed .git directory",
                severity="high",
                category="exposure",
                host="example.com",
                url="https://example.com/.git/HEAD",
                description="Git metadata is readable.",
                remediation="Deny /.git/.",
                evidence="HTTP 200; ref: refs/heads/main",
                confidence="confirmed",
            )],
        )
        markdown = render_markdown(result)
        self.assertIn("Webwarden report — example.com", markdown)
        self.assertIn("Exposed .git directory", markdown)
        self.assertIn("| HIGH | 1 |", markdown)
        self.assertIn("## Executive summary", markdown)
        self.assertIn("## Grouped findings", markdown)
        self.assertIn("| Exposed .git directory | HIGH | exposure |", markdown)
        self.assertIn("### Security header coverage", markdown)
        self.assertIn("### security.txt", markdown)
        self.assertIn("mailto:sec@example.com", markdown)
        self.assertIn("## Submission readiness", markdown)
        self.assertIn("### Client-side exposure", markdown)
        self.assertIn("AKIA...MNOP (len 20)", markdown)
        self.assertIn("https://example.com/app.js.map", markdown)
        markup = render_html(result)
        self.assertIn("Security header coverage", markup)
        self.assertIn("mailto:sec@example.com", markup)
        self.assertIn("Submission readiness", markup)
        self.assertIn("Client-side exposure", markup)
        self.assertIn("AKIA...MNOP (len 20)", markup)

        with tempfile.TemporaryDirectory() as tmp:
            paths = write_report(result, Path(tmp))
            self.assertTrue(paths["markdown"].exists())
            payload = json.loads(paths["findings"].read_text(encoding="utf-8"))
            self.assertEqual(payload["findings"][0]["severity"], "high")
            self.assertTrue(paths["scan"].exists())
            self.assertTrue(paths["poc"].exists())
            self.assertIn("webwarden PoC script",
                          paths["poc"].read_text(encoding="utf-8"))

    def test_indonesian_report_language(self):
        result = ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="test",
            started_at="2026-01-01T00:00:00Z",
            findings=[Finding(
                title="Exposed .git directory",
                severity="high",
                category="exposure",
                host="example.com",
                url="https://example.com/.git/HEAD",
                description="Git metadata is readable.",
                confidence="confirmed",
            )],
        )
        markdown = render_markdown(result, "id")
        self.assertIn("Laporan webwarden — example.com", markdown)
        self.assertIn("## Ringkasan eksekutif", markdown)
        self.assertIn("## Temuan", markdown)
        self.assertIn("## Catatan validasi", markdown)
        self.assertIn("Exposed .git directory", markdown)
        english = render_markdown(result, "en")
        self.assertIn("## Executive summary", english)
        self.assertNotIn("## Ringkasan eksekutif", english)

    def test_attack_scenario_is_hypothetical_only(self):
        result = ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="test",
            started_at="2026-01-01T00:00:00Z",
            recon={"injection": {"enabled": True,
                                 "checks": {"sql_error": 1, "xss": 0}}},
            stats={"backdoor_findings": 0},
            findings=[Finding(
                title="SQL error signature on q",
                severity="high",
                category="sqli",
                host="example.com",
                url="https://example.com/search?q=1",
                description="Differential SQL error signature reproduced twice.",
                confidence="confirmed",
                verified=True,
            )],
        )
        markdown = render_markdown(result, "id")
        self.assertIn("## Skenario attacker (simulasi)", markdown)
        self.assertIn("## Cakupan deteksi", markdown)
        self.assertIn("SQL injection (error/boolean)", markdown)
        self.assertIn("SQL injection → data exposure", markdown)
        self.assertIn("Tidak ada payload", markdown)
        self.assertIn("sqlmap (hanya oleh pemilik scope, tidak dipakai di sini)",
                      markdown)
        self.assertNotIn("UNION SELECT", markdown)
        self.assertNotIn("## Skenario attacker (simulasi)",
                         render_markdown(result, "en"))

    def test_chain_flow_rendered_with_numbered_steps(self):
        item = {
            "id": "session-plaintext-example.com",
            "title": "Session hijacking via cleartext session token",
            "status": "partial", "severity": "medium",
            "summary": "cookie over http", "impact": "on-path read",
            "links": [
                {"role": "precondition", "title": "Cookie missing attributes",
                 "host": "example.com", "status": "observed",
                 "reproductions": 2, "evidence": "set-cookie observed"},
                {"role": "exposure", "title": "Session token over HTTP",
                 "host": "example.com", "status": "partial",
                 "reproductions": 1, "evidence": "token observed"},
            ],
            "proof": ["curl -sS -D - -o /dev/null http://example.com/"],
            "limitations": "no interception performed",
        }
        result = ScanResult(
            target="example.com", scopes=["example.com"], version="test",
            started_at="2026-01-01T00:00:00Z",
            recon={"chains": {"enabled": True, "total": 1, "items": [item]}},
        )
        markdown = render_markdown(result, "id")
        self.assertIn("**Alur exploit:**", markdown)
        self.assertIn("1. [prasyarat] Cookie missing attributes (observed)",
                      markdown)
        self.assertIn("2. [paparan] Session token over HTTP (partial)",
                      markdown)
        self.assertIn("**Dampak bila dikonfirmasi:** on-path read", markdown)
        self.assertIn("**Langkah bukti read-only**", markdown)
        self.assertIn("**Batas chain:** no interception performed", markdown)
        english = render_markdown(result, "en")
        self.assertIn("**Exploit flow:**", english)
        self.assertIn("**Impact if confirmed:**", english)

    def test_indonesian_html_report(self):
        result = ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="test",
            started_at="2026-01-01T00:00:00Z",
            findings=[Finding(
                title="SQL error signature on q",
                severity="high",
                category="sqli",
                host="example.com",
                url="https://example.com/search?q=1",
                description="Differential SQL error signature reproduced twice.",
                confidence="confirmed",
                verified=True,
            )],
        )
        markup = render_html(result, "id")
        self.assertIn('<html lang="id">', markup)
        self.assertIn("Ringkasan", markup)
        self.assertIn("Kesiapan lapor", markup)
        self.assertIn("Skenario attacker (simulasi)", markup)
        self.assertIn("Cerita exploitasi (hipotetis)", markup)
        self.assertIn("Titik henti", markup)
        self.assertNotIn("Submission readiness", markup)
        english = render_html(result, "en")
        self.assertIn('<html lang="en">', english)
        self.assertNotIn("Cerita exploitasi (hipotetis)", english)

    def test_full_evidence_is_rendered_and_indexed(self):
        result = ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="0.4.1",
            started_at="2026-10-26T00:00:00Z",
            finished_at="2026-10-26T00:10:00Z",
            findings=[Finding(
                title="Exposed .env file",
                severity="high",
                category="exposure",
                host="example.com",
                url="https://example.com/.env",
                description="Env file is readable.",
                remediation="Deny dotfiles.",
                evidence=(
                    "HTTP: 200\nSHA-256: " + "a" * 64 + "\n\n"
                    "DB_PASSWORD=hunter2\n"
                ),
                confidence="confirmed",
                verified=True,
                evidence_sha256="a" * 64,
                evidence_bytes=42,
                evidence_file="evidence/0001-env.body",
                evidence_files=["evidence/0001-env.body"],
                poc=["mkdir -p evidence", "curl -sS --max-time 30 'https://example.com/.env'"],
            )],
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            (root / "evidence" / "0001-env.body").write_bytes(b"DB_PASSWORD=hunter2\n")
            paths = write_report(result, root)
            markdown = paths["markdown"].read_text(encoding="utf-8")
            self.assertIn("DB_PASSWORD=hunter2", markdown)
            self.assertIn("Evidence SHA-256", markdown)
            page = paths["html"].read_text(encoding="utf-8")
            self.assertIn("PRIVATE — VERBATIM EVIDENCE", page)
            self.assertIn("DB_PASSWORD=hunter2", page)
            self.assertIn("evidence_index", paths)
            self.assertTrue(paths["evidence_index"].exists())

    def test_bypass_section(self):
        result = ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="0.3.0",
            started_at="2026-10-26T00:00:00Z",
            stats={"bypass_attempts": 1, "bypasses": 1},
            recon={"bypass": {
                "enabled": True,
                "bypasses": 1,
                "attempts": [{
                    "host": "example.com",
                    "path": "/.env",
                    "baseline": 403,
                    "variants": 4,
                    "bypass": True,
                    "technique": "header X-Forwarded-For",
                    "bypass_status": 200,
                }],
            }},
        )
        markdown = render_markdown(result)
        self.assertIn("## Access-control bypass checks", markdown)
        self.assertIn("BYPASS via header X-Forwarded-For", markdown)
        self.assertIn("Access-control bypass checks: **1** paths", markdown)


class SarifTests(unittest.TestCase):
    def _result(self) -> ScanResult:
        return ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="0.12.0",
            started_at="2026-11-10T00:00:00Z",
            finished_at="2026-11-10T00:05:00Z",
            findings=[
                Finding(
                    title="Exposed .env file", severity="high",
                    category="sensitive-path", host="example.com",
                    url="https://example.com/.env",
                    description="The deployment secret file is served publicly.",
                    remediation="Remove the file from the web root.",
                    evidence="APP_KEY=base64:abc", confidence="confirmed",
                    verified=True, reproductions=2,
                    evidence_sha256="deadbeef",
                ),
                Finding(
                    title="Open redirect candidate", severity="medium",
                    category="injection", host="example.com",
                    url="https://example.com/go?url=//evil.invalid",
                    description="Response jumped to an off-site host.",
                    confidence="needs manual verification",
                ),
            ],
        )

    def test_write_report_emits_valid_sarif(self):
        result = self._result()
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_report(result, Path(tmp))
            self.assertTrue(paths["sarif"].exists())
            payload = json.loads(paths["sarif"].read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0", payload["$schema"])
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "webwarden")
        self.assertEqual(run["tool"]["driver"]["version"], "0.12.0")
        self.assertEqual(len(run["results"]), 2)

    def test_levels_and_kinds_follow_verification(self):
        payload = sarif_mod.build_sarif(self._result())
        run = payload["runs"][0]
        by_rule = {rule["id"]: index
                   for index, rule in enumerate(run["tool"]["driver"]["rules"])}
        self.assertEqual(by_rule["sensitive-path"], 0)
        first, second = run["results"]
        self.assertEqual(first["level"], "error")
        self.assertEqual(first["kind"], "fail")
        self.assertTrue(first["properties"]["verified"])
        self.assertEqual(first["properties"]["evidenceSha256"], "deadbeef")
        self.assertEqual(second["level"], "warning")
        self.assertEqual(second["kind"], "open")
        self.assertNotIn("evidenceSha256", second["properties"])
        self.assertEqual(
            first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://example.com/.env")

    def test_out_of_scope_url_gets_no_location(self):
        result = self._result()
        result.findings[0].url = "https://not-in-scope.invalid/.env"
        result.findings[0].host = "not-in-scope.invalid"
        run = sarif_mod.build_sarif(result)["runs"][0]
        self.assertNotIn("locations", run["results"][0])


class CertspotterTests(unittest.TestCase):
    def test_names_are_scoped_normalised_and_deduped(self):
        rows = json.dumps([
            {"dns_names": ["*.example.com", "API.example.com", "example.com"]},
            {"dns_names": ["api.example.com"]},
            {"dns_names": ["evil.test", "sub.evil.test"]},
            {"dns_names": None},
            "not-a-row",
        ]).encode()
        with mock.patch.object(recon_mod, "external_get", return_value=rows):
            names, warning = recon_mod.certspotter("example.com")
        self.assertIsNone(warning)
        self.assertEqual(names, ["api.example.com", "example.com"])

    def test_network_failure_degrades_to_warning(self):
        with mock.patch.object(
                recon_mod, "external_get",
                side_effect=OSError("certspotter down")):
            names, warning = recon_mod.certspotter("example.com")
        self.assertEqual(names, [])
        self.assertIn("certspotter lookup failed", warning)

    def test_unexpected_payload_degrades_to_warning(self):
        with mock.patch.object(recon_mod, "external_get",
                               return_value=b'{"error": "boom"}'):
            names, warning = recon_mod.certspotter("example.com")
        self.assertEqual(names, [])
        self.assertIn("unexpected payload", warning)


class CliGateTests(unittest.TestCase):
    def test_requires_authorization(self):
        self.assertEqual(cli.main(["example.com"]), 2)

    def test_rejects_public_suffix(self):
        self.assertEqual(cli.main(["com", "--i-am-authorized"]), 2)

    def test_rejects_ip_target(self):
        self.assertEqual(cli.main(["127.0.0.1", "--i-am-authorized"]), 2)

    def test_rejects_out_of_scope(self):
        self.assertEqual(
            cli.main(["example.com", "--i-am-authorized",
                      "--scope", "other.com"]), 2)

    def test_parser_accepts_bare_target(self):
        args = cli.build_parser().parse_args(["scan", "example.com"])
        self.assertEqual(args.target, "example.com")
        self.assertFalse(args.allow_intercepted)

    def test_scan_aborts_on_dns_interception(self):
        blocked = netcheck.DnsIntegrity(
            blocked=True, reasons=["NS matches a DNS filter"]
        )
        with mock.patch.object(cli, "preflight", return_value=blocked):
            code = cli.main(["example.com", "--i-am-authorized"])
        self.assertEqual(code, 3)

    def test_full_profile_enables_read_only_modules(self):
        args = cli.build_parser().parse_args(["scan", "example.com", "--full"])
        self.assertFalse(args.bypass)
        self.assertFalse(args.robots_paths)
        with mock.patch.object(cli, "_authorized", return_value=False), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.cmd_scan(args), 2)
        self.assertTrue(args.bypass)
        self.assertTrue(args.robots_paths)

    def test_help_alias_prints_examples(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["-h"])
        self.assertIn("QUICK START", out.getvalue())
        self.assertIn("webwarden scan -h", out.getvalue())

        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["help", "scan"])
        self.assertIn("EXAMPLES", out.getvalue())
        self.assertIn("--full", out.getvalue())


def sample_audit_result():
    findings = [
        Finding(
            title="HTTPS not enforced",
            severity="medium",
            category="tls",
            host="a.example.com",
            url="http://a.example.com/",
            description="HTTP is served without a redirect.",
            remediation="Redirect HTTP to HTTPS.",
            confidence="confirmed",
            verified=True,
        ),
        Finding(
            title="Cookie missing security attributes",
            severity="low",
            category="cookies",
            host="a.example.com",
            url="https://a.example.com/",
            description="Cookie lacks Secure and HttpOnly.",
            remediation="Set Secure, HttpOnly, SameSite.",
            confidence="firm",
            verified=True,
        ),
        Finding(
            title="Directory listing enabled",
            severity="low",
            category="exposure",
            host="a.example.com",
            url="https://a.example.com/dir/",
            description="Autoindex is on.",
            remediation="Disable autoindex.",
            confidence="confirmed",
            verified=True,
        ),
        Finding(
            title="Possible subdomain takeover (GitHub Pages)",
            severity="high",
            category="takeover",
            host="old.example.com",
            url="https://old.example.com/",
            description="Dangling CNAME.",
            remediation="Remove the dangling CNAME.",
            confidence="needs manual verification",
            verified=False,
        ),
    ]
    return ScanResult(
        target="example.com",
        scopes=["example.com"],
        version="test",
        started_at="2026-10-26T00:00:00Z",
        finished_at="2026-10-26T00:01:00Z",
        findings=findings,
        stats={"live_hosts": 2, "requests": 10},
        recon={"bypass": {"enabled": False, "attempts": [], "bypasses": 0}},
    )


class AuditTests(unittest.TestCase):
    def test_local_audit_ranks_and_correlates(self):
        result = sample_audit_result()
        audit = heuristic_audit(result)
        self.assertGreater(audit.risk_score, 0)
        self.assertIn(audit.risk_band, ("moderate", "elevated"))
        self.assertEqual(audit.priorities[0]["title"],
                         "Possible subdomain takeover (GitHub Pages)")
        chain_titles = {item["title"] for item in audit.chains}
        self.assertIn("Cookie exposure over plaintext HTTP", chain_titles)
        self.assertTrue(any(
            item["title"].startswith("Possible subdomain takeover")
            for item in audit.manual_review
        ))
        self.assertTrue(any("--bypass" in step for step in audit.next_steps))
        self.assertFalse(audit.ai_generated)

    def test_scrub_removes_secrets(self):
        text = "DB_PASSWORD=hunter2 Cookie: sid=abcd1234 token=xyz"
        cleaned = _scrub(text)
        self.assertNotIn("hunter2", cleaned)
        self.assertNotIn("abcd1234", cleaned)
        self.assertIn("[redacted]", cleaned)

    def test_compact_payload_fits_ollama_context(self):
        result = sample_audit_result()
        for finding in result.findings:
            finding.description = "d" * 1200
            finding.evidence = "e" * 1200
        heuristic = heuristic_audit(result)
        full = _audit_payload(result, heuristic)
        compact = _audit_payload(result, heuristic, compact=True)
        self.assertIn("observed_chains", full)
        self.assertIn("manual_review", full)
        self.assertNotIn("observed_chains", compact)
        self.assertNotIn("manual_review", compact)
        self.assertLessEqual(len(compact["findings"]), 20)
        for row in compact["findings"]:
            self.assertLessEqual(len(row["description"]), 200)
            self.assertLessEqual(len(row["evidence"]), 240)
        for key in ("summary", "priorities", "chains", "manual_review",
                    "next_steps"):
            self.assertIn(key, AUDIT_SCHEMA["required"])

    def test_parse_fenced_json(self):
        parsed = _parse_json_object('```json\n{"summary": "ok"}\n```')
        self.assertEqual(parsed, {"summary": "ok"})
        self.assertIsNone(_parse_json_object("not json"))

    def test_ollama_unreachable_falls_back(self):
        result = sample_audit_result()
        audit = run_audit(
            result,
            provider="ollama",
            endpoint="http://127.0.0.1:9",
            timeout=0.4,
        )
        self.assertEqual(audit.provider, "local")
        self.assertTrue(any("Ollama" in note for note in audit.notes))

    def test_non_loopback_endpoint_is_refused(self):
        result = sample_audit_result()
        audit = run_audit(
            result,
            provider="ollama",
            endpoint="http://192.0.2.1:11434",
            timeout=0.2,
        )
        self.assertEqual(audit.provider, "local")
        self.assertTrue(any("non-loopback" in note for note in audit.notes))

    def test_report_writes_html_audit_and_reloads(self):
        result = sample_audit_result()
        result.audit = heuristic_audit(result).to_dict()
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_report(result, Path(tmp))
            self.assertTrue(paths["html"].exists())
            self.assertTrue(paths["audit"].exists())
            self.assertTrue(paths["audit_json"].exists())
            loaded = load_scan_result(paths["scan"])
            self.assertEqual(len(loaded.findings), len(result.findings))
            self.assertEqual(loaded.audit["risk_score"],
                             result.audit["risk_score"])

    def test_audit_out_copies_raw_evidence(self):
        result = sample_audit_result()
        finding = result.findings[2]
        finding.evidence_sha256 = hashlib.sha256(b"raw-body").hexdigest()
        finding.evidence_bytes = 8
        finding.evidence_file = "evidence/0001-directory-listing.body"
        finding.evidence_files = [finding.evidence_file]
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp) / "scan"
            out_dir = Path(tmp) / "audit"
            paths = write_report(result, scan_dir)
            (scan_dir / "evidence" / "0001-directory-listing.body").write_bytes(
                b"raw-body"
            )
            self.assertEqual(
                cli.main([
                    "audit", str(paths["scan"]),
                    "--ai-audit", "local",
                    "--out", str(out_dir),
                    "--quiet",
                ]),
                0,
            )
            copied = out_dir / "evidence" / "0001-directory-listing.body"
            self.assertTrue(copied.is_file())
            self.assertEqual(copied.read_bytes(), b"raw-body")
            self.assertTrue((out_dir / "evidence" / "index.json").is_file())


class TakeoverTests(unittest.TestCase):
    class FakeResolver:
        def __init__(self, mapping):
            self.mapping = mapping

        def query(self, name, qtype="A", tries=2):
            if qtype.upper() == "CNAME":
                value = self.mapping.get(name)
                return [value] if value else []
            return []

    def _probe(self, body, host="old.example.com"):
        return Probe(
            host=host,
            url=f"https://{host}/",
            status=404,
            result=HttpResult(
                url=f"https://{host}/",
                status=404,
                body=body.encode("utf-8"),
            ),
        )

    def test_dangling_cname_with_marker_is_a_candidate(self):
        resolver = self.FakeResolver({"old.example.com": "old.github.io"})
        findings, meta = detect_takeovers(
            [self._probe("There isn't a GitHub Pages site here")],
            resolver,
            ["example.com"],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "takeover")
        self.assertEqual(findings[0].severity, "high")
        self.assertFalse(findings[0].verified)
        self.assertIn("dig +short CNAME", findings[0].poc[0])
        self.assertEqual(meta["takeovers"], 1)

    def test_marker_is_required(self):
        resolver = self.FakeResolver({"old.example.com": "old.github.io"})
        findings, meta = detect_takeovers(
            [self._probe("Welcome to a normal site")],
            resolver,
            ["example.com"],
        )
        self.assertEqual(findings, [])
        self.assertEqual(meta["candidates"][0]["takeover"], False)

    def test_provider_match(self):
        self.assertEqual(match_provider("x.herokuapp.com").name, "Heroku")
        self.assertIsNone(match_provider("example.com"))


class HtmlDiffCliTests(unittest.TestCase):
    def test_html_escapes_findings_and_shows_audit(self):
        result = sample_audit_result()
        result.findings[0].title = "<script>alert(1)</script>"
        result.findings[0].evidence = "<img src=x onerror=alert(1)>"
        result.audit = heuristic_audit(result).to_dict()
        page = render_html(result)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", page)
        self.assertIn("AI-assisted audit", page)
        self.assertIn("Priority order", page)
        self.assertIn("Grouped findings", page)

    def test_diff_classifies_new_fixed_and_changed(self):
        def finding(title, severity, url):
            return Finding(
                title=title,
                severity=severity,
                category="headers",
                host="example.com",
                url=url,
                description="test",
                verified=True,
            )

        old = [
            finding("Exposed .env", "high", "https://example.com/.env"),
            finding("Missing header", "low", "https://example.com/"),
        ]
        new = [
            finding("Missing header", "medium", "https://example.com/"),
            finding("Directory listing", "low", "https://example.com/dir/"),
        ]
        diff = compare("example.com", old, "example.com", new)
        self.assertEqual([item.title for item in diff.new], ["Directory listing"])
        self.assertEqual([item.title for item in diff.fixed], ["Exposed .env"])
        self.assertEqual(len(diff.persisting), 1)
        self.assertEqual(len(diff.severity_changed), 1)
        markdown = render_diff(diff)
        self.assertIn("## New findings", markdown)
        self.assertIn("## Severity changes", markdown)
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_diff(diff, Path(tmp))
            self.assertTrue(paths["markdown"].exists())
            self.assertTrue(paths["json"].exists())

    def test_cli_parses_new_commands_and_flags(self):
        parser = cli.build_parser()
        self.assertEqual(
            parser.parse_args(["audit", "scan.json"]).command, "audit"
        )
        args = parser.parse_args(["diff", "old.json", "new.json"])
        self.assertEqual(args.command, "diff")
        args = parser.parse_args([
            "scan", "example.com", "--ai-audit", "ollama", "--no-takeover",
        ])
        self.assertEqual(args.ai_audit, "ollama")
        self.assertTrue(args.no_takeover)
        self.assertEqual(
            parser.parse_args(["scan", "example.com"]).ai_audit, "local"
        )
        self.assertEqual(
            parser.parse_args(["scan", "example.com"]).evidence_bytes,
            5 * 1024 * 1024,
        )
        self.assertEqual(cli.main(["audit", "/nonexistent/scan.json"]), 2)


class DecoyAndChainTests(unittest.TestCase):
    def _finding(self, title, severity, category, *, reproductions=2,
                 verified=True, stable=True, decoy=False, host="example.com"):
        return Finding(
            title=title,
            severity=severity,
            category=category,
            host=host,
            url=f"https://{host}/{category}",
            description="observed condition",
            verified=verified,
            verification="observed on independent requests",
            reproductions=reproductions,
            stable=stable,
            decoy_suspected=decoy,
            decoy_reason="response mentions a honeytoken" if decoy else "",
        )

    def test_decoy_markers_and_test_credentials(self):
        self.assertIn(
            "response mentions a honeypot",
            decoy_mod.markers("Welcome, this is a honeypot."),
        )
        self.assertEqual(decoy_mod.markers("ordinary product page"), [])
        severity, reason = decoy_mod.classify_credential("sk_test_123456")
        self.assertEqual(severity, "info")
        self.assertIn("Stripe test secret key", reason)
        severity, _ = decoy_mod.classify_credential("AKIAIOSFODNN7EXAMPLE")
        self.assertIsNone(severity)

    def test_chains_mark_observed_and_stamp_findings(self):
        token = self._finding(
            "Session token exposed in plaintext", "high", "tokens")
        cookie = self._finding(
            "Sensitive cookie sid missing security attributes", "medium",
            "cookies")
        chains = chain_mod.build_chains([token, cookie])
        session = [
            chain for chain in chains
            if chain.id == "session-plaintext-example.com"
        ]
        self.assertEqual(len(session), 1)
        chain = session[0]
        self.assertEqual(chain.status, "observed")
        self.assertEqual(
            [link.status for link in chain.links], ["observed", "observed"])
        self.assertEqual(chain.severity, "high")
        chain_mod.apply_chain_ids(chains, [token, cookie])
        self.assertIn(chain.id, token.chain_ids)
        self.assertIn(chain.id, cookie.chain_ids)
        payload = chain.to_dict()
        self.assertEqual(payload["links"][0]["reproductions"], 2)
        self.assertFalse(payload["links"][0]["decoy"])

    def test_partial_is_capped_and_decoy_blocks(self):
        token = self._finding(
            "Session token exposed in plaintext", "high", "tokens",
            reproductions=1, stable=None)
        cookie = self._finding(
            "Sensitive cookie sid missing security attributes", "high",
            "cookies", reproductions=1, stable=None)
        chain = [
            item for item in chain_mod.build_chains([token, cookie])
            if item.id == "session-plaintext-example.com"
        ][0]
        self.assertEqual(chain.status, "partial")
        self.assertEqual(chain.severity, "medium")
        decoy = self._finding(
            "Exposed test credential in bundle", "high", "secrets", decoy=True)
        blocked = [
            item for item in chain_mod.build_chains([decoy])
            if item.id == "decoy-artifacts"
        ][0]
        self.assertEqual(blocked.status, "blocked")
        self.assertEqual(blocked.severity, "info")
        self.assertEqual(blocked.links[0].status, "blocked")
        self.assertTrue(blocked.links[0].decoy)

    def test_stale_bundle_chain_uses_bundle_recon(self):
        drift = Finding(
            title="Build artifact drift: app.js hash differs between page and "
                  "build manifest",
            severity="info",
            category="bundle-drift",
            host="example.com",
            url="https://example.com/_next/static/x/_buildManifest.js",
            description="Hashes disagree.",
            verified=True,
            verification="both fetched directly",
            reproductions=1,
            stable=True,
        )
        recon = {"bundles": {"hosts": [{
            "host": "example.com",
            "drift": [{"type": "asset-hash-mismatch"}],
            "missing": [],
        }]}}
        chains = chain_mod.build_chains([drift], recon)
        stale = [
            chain for chain in chains
            if chain.id == "stale-bundle-example.com"
        ]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].links[0].title, drift.title)
        self.assertEqual(stale[0].status, "partial")

    def test_sqli_chain_links_storage_exposure(self):
        sqli = self._finding(
            "SQL error response triggered by parameter 'id'", "high", "sqli")
        dump = self._finding("Database dump downloadable", "high", "exposure")
        chain = [
            item for item in chain_mod.build_chains([sqli, dump])
            if item.id == "sqli-database-example.com"
        ][0]
        self.assertEqual(chain.status, "observed")
        self.assertEqual(chain.severity, "high")
        self.assertEqual(
            [link.role for link in chain.links], ["injection", "exposure"])
        self.assertIn("no rows were retrieved", chain.summary.lower()
                      + chain.impact.lower())
        single = [
            item for item in chain_mod.build_chains([sqli])
            if item.id == "sqli-database-example.com"
        ][0]
        self.assertEqual(len(single.links), 1)

    def test_webshell_chain_is_observed_execution(self):
        shell = self._finding(
            "Web shell or backdoor reachable at /shell.php", "critical",
            "backdoor")
        chain = [
            item for item in chain_mod.build_chains([shell])
            if item.id.startswith("webshell-exec-")
        ][0]
        self.assertEqual(chain.status, "observed")
        self.assertEqual(chain.severity, "critical")
        self.assertEqual(chain.links[0].role, "execution")

    def test_ssti_and_lfi_chains_use_build_context(self):
        ssti = self._finding(
            "Server-side template injection in parameter 'name' (Jinja2/Twig)",
            "high", "ssti")
        source_map = self._finding(
            "JavaScript source map published", "info", "exposure")
        chain = [
            item for item in chain_mod.build_chains([ssti, source_map])
            if item.id == "ssti-rce-example.com"
        ][0]
        self.assertEqual(chain.status, "observed")
        self.assertEqual(chain.severity, "high")
        self.assertEqual(
            [link.role for link in chain.links], ["injection", "exposure"])

        lfi = self._finding(
            "Local file inclusion in parameter 'file'", "high", "lfi")
        env = self._finding("Exposed .env file", "high", "exposure")
        chain = [
            item for item in chain_mod.build_chains([lfi, env])
            if item.id == "lfi-files-example.com"
        ][0]
        self.assertEqual(chain.severity, "high")
        self.assertEqual(chain.links[-1].title, env.title)

    def test_xss_chain_uses_cookie_gap(self):
        xss = self._finding(
            "Reflected HTML injection (possible XSS) in parameter 'q'",
            "medium", "xss")
        cookie = self._finding(
            "Sensitive cookie sid missing security attributes", "medium",
            "cookies")
        chain = [
            item for item in chain_mod.build_chains([xss, cookie])
            if item.id == "xss-session-example.com"
        ][0]
        self.assertEqual(chain.status, "observed")
        self.assertEqual(chain.severity, "medium")
        self.assertEqual(
            [link.role for link in chain.links], ["injection", "precondition"])
        self.assertIn("session cookie lacks security attributes",
                      chain.summary.lower())

    def test_capability_graph_builds_three_hop_chain(self):
        idor = self._finding(
            "Object accessible without authentication (possible IDOR/BOLA)",
            "high", "access-control")
        xss = self._finding(
            "Reflected HTML injection (possible XSS) in parameter 'q'",
            "medium", "xss")
        cookie = self._finding(
            "Sensitive cookie sid missing security attributes", "medium",
            "cookies")
        chains = [
            item for item in chain_mod.build_chains([idor, xss, cookie])
            if item.id.startswith("graph-")
        ]
        self.assertEqual(len(chains), 1)
        chain = chains[0]
        self.assertEqual(len(chain.links), 3)
        self.assertEqual(chain.status, "partial")
        self.assertEqual(chain.severity, "medium")
        self.assertEqual(chain.links[0].url, idor.url)
        self.assertEqual(chain.links[-1].url, cookie.url)
        self.assertIn("manual-verification", chain.limitations)

    def test_capability_graph_never_crosses_hosts(self):
        idor = self._finding(
            "Object accessible without authentication (possible IDOR/BOLA)",
            "high", "access-control", host="a.example.com")
        xss = self._finding(
            "Reflected HTML injection (possible XSS) in parameter 'q'",
            "medium", "xss", host="b.example.com")
        cookie = self._finding(
            "Sensitive cookie sid missing security attributes", "medium",
            "cookies", host="b.example.com")
        chains = [
            item for item in chain_mod.build_chains([idor, xss, cookie])
            if item.id.startswith("graph-")
        ]
        self.assertEqual(chains, [])

    def test_capability_graph_skips_decoys(self):
        idor = self._finding(
            "Object accessible without authentication (possible IDOR/BOLA)",
            "high", "access-control")
        xss = self._finding(
            "Reflected HTML injection (possible XSS) in parameter 'q'",
            "medium", "xss")
        cookie = self._finding(
            "Sensitive cookie sid missing security attributes", "medium",
            "cookies", decoy=True)
        chains = [
            item for item in chain_mod.build_chains([idor, xss, cookie])
            if item.id.startswith("graph-")
        ]
        self.assertEqual(chains, [])

    def test_log_poisoning_chain_stays_a_hypothesis(self):
        lfi = self._finding(
            "Local file inclusion in parameter 'file'", "high", "lfi")
        log = self._finding("Laravel log exposed", "medium", "exposure")
        chain = [
            item for item in chain_mod.build_chains([lfi, log])
            if item.id == "log-poisoning-example.com"
        ][0]
        self.assertEqual(chain.status, "partial")
        self.assertEqual(chain.severity, "medium")
        self.assertIn("hypothesis", chain.limitations.lower())
        self.assertIn("not an observed exploit", chain.limitations.lower())

    def test_git_exposure_chain_reports_source_disclosure(self):
        git = self._finding("Exposed git config", "high", "exposure")
        secret = self._finding("Client-side credential-shaped value", "medium",
                               "secrets")
        chain = [
            item for item in chain_mod.build_chains([git, secret])
            if item.id == "git-source-example.com"
        ][0]
        self.assertEqual(
            [link.role for link in chain.links], ["exposure", "impact"])
        self.assertIn("not performed", chain.impact.lower())

    def test_ssrf_chain_stays_a_hypothesis(self):
        ssrf = self._finding(
            "Server-side request fetch in parameter 'url' (possible SSRF)",
            "medium", "ssrf")
        actuator = self._finding(
            "Spring Boot actuator environment exposed", "high", "exposure")
        chain = [
            item for item in chain_mod.build_chains([ssrf, actuator])
            if item.id == "ssrf-internal-example.com"
        ][0]
        self.assertEqual(chain.status, "partial")
        self.assertEqual(chain.severity, "medium")
        self.assertEqual(
            [link.role for link in chain.links], ["precondition", "impact"])
        self.assertIn("never does", chain.limitations.lower())


class BundleReconTests(unittest.TestCase):
    def _result(self, url, status=200, body=b"", content_type="text/html"):
        return HttpResult(
            url=url,
            status=status,
            ok=status == 200,
            body=body,
            headers={"content-type": content_type},
        )

    def test_asset_hash_and_logical_name(self):
        self.assertEqual(
            bundle_mod.asset_hash(
                "https://x/static/js/main.4f3a2b1c.js"),
            "4f3a2b1c",
        )
        self.assertIsNone(bundle_mod.asset_hash("https://x/static/js/main.js"))
        self.assertEqual(
            bundle_mod.logical_name(
                "https://x/static/js/main.4f3a2b1c.js"),
            "main.js",
        )
        self.assertEqual(
            bundle_mod.logical_name(
                "https://x/static/js/app.chunk.4f3a2b1c.js"),
            "app.chunk.js",
        )

    def test_compare_deployments_detects_hash_drift(self):
        drift, listed = bundle_mod.compare_deployments(
            ["https://x/static/js/main.aaaa1111.js"],
            '{"main.js": "/static/js/main.bbbb2222.js"}',
        )
        self.assertTrue(listed)
        self.assertEqual(drift[0]["logical_name"], "main.js")
        self.assertEqual(drift[0]["page_hashes"], ["aaaa1111"])
        self.assertEqual(drift[0]["manifest_hashes"], ["bbbb2222"])

    def test_version_hints_map_only_known_libraries(self):
        report = bundle_mod.HostBundleReport(host="example.com")
        report.library_sources = {
            "jQuery": {"3.6.0": ["https://x/a.js"]},
            "React": {"18.2.0": ["https://x/b.js"]},
        }
        hints = bundle_mod.version_hints([report])
        self.assertIn("jquery", hints)
        self.assertEqual(hints["jquery"]["version"], "3.6.0")
        self.assertNotIn("react", hints)

    def test_analyze_reports_drift_and_missing_chunk(self):
        html = (
            '<html><head>'
            '<link rel="manifest" href="/asset-manifest.json">'
            '</head><body>'
            '<script src="/static/js/main.abc12345.js"></script>'
            '<script src="/static/js/old.def67890.js"></script>'
            '</body></html>'
        )
        page = self._result("https://example.com/", 200, html.encode())
        probe = Probe(
            host="example.com",
            url="https://example.com/",
            status=200,
            result=page,
        )

        def fetch(url):
            if url.endswith("/asset-manifest.json"):
                body = b'{"main.js": "/static/js/main.99999999.js"}'
                return self._result(url, 200, body, "application/json")
            if url.endswith("/main.abc12345.js"):
                return self._result(url, 200, b"var ok = true;", "text/javascript")
            return self._result(url, 404, b"not found")

        produced, reports, meta = bundle_mod.analyze(
            [probe], fetch, ["example.com"])
        titles = [finding.title for finding, _ in produced]
        self.assertTrue(any("Build artifact drift" in title for title in titles))
        self.assertTrue(any("missing" in title.lower() for title in titles))
        missing_finding = [
            finding for finding, _ in produced
            if "missing" in finding.title.lower()
        ][0]
        self.assertEqual(missing_finding.reproductions, 2)
        self.assertTrue(missing_finding.stable)
        self.assertEqual(meta["assets_fetched"], 2)
        self.assertGreaterEqual(meta["drift"], 1)
        self.assertEqual(meta["missing_chunks"], 1)
        self.assertEqual(reports[0].host, "example.com")

    def test_truncated_bundle_reads_are_flagged(self):
        html = (
            '<html><head></head><body>'
            '<script src="/static/js/main.abc12345.js"></script>'
            '</body></html>'
        )
        page = self._result("https://example.com/", 200, html.encode())
        probe = Probe(
            host="example.com",
            url="https://example.com/",
            status=200,
            result=page,
        )
        declared = 2 * 1024 * 1024
        body = b"Lodash 4.17.15 " + b"x" * 4096
        truncated_result = self._result(
            "https://example.com/static/js/main.abc12345.js",
            200, body, "text/javascript")
        truncated_result.truncated = True
        truncated_result.headers["content-length"] = str(declared)

        produced, reports, meta = bundle_mod.analyze(
            [probe], lambda url: truncated_result, ["example.com"])
        library_finding = [
            finding for finding, _ in produced
            if "library versions" in finding.title.lower()
        ][0]
        self.assertTrue(library_finding.poc)
        self.assertTrue(any("content-length" in step.lower()
                            for step in library_finding.poc))
        self.assertIn("captured prefix", library_finding.description)
        self.assertIn("Truncated reads", library_finding.evidence)
        self.assertIn(f"captured {len(body)} of {declared} bytes",
                      library_finding.evidence)
        self.assertEqual(meta["truncated_assets"], 1)
        self.assertTrue(reports[0].assets[0].truncated)
        self.assertEqual(reports[0].assets[0].content_length, declared)
        self.assertTrue(any("read" in warning and "bytes" in warning
                            for warning in meta["warnings"]))


class ValidationReportTests(unittest.TestCase):
    def _result(self):
        observed = Finding(
            title="Session token exposed in plaintext",
            severity="high",
            category="tokens",
            host="example.com",
            url="https://example.com/account?session=x",
            description="Token in URL.",
            verified=True,
            verification="observed twice",
            reproductions=2,
            stable=True,
        )
        cookie = Finding(
            title="Sensitive cookie sid missing security attributes",
            severity="medium",
            category="cookies",
            host="example.com",
            url="https://example.com/login",
            description="Cookie lacks Secure.",
            verified=True,
            verification="Set-Cookie observed twice",
            reproductions=2,
            stable=True,
        )
        decoy = Finding(
            title="Exposed test credential in bundle",
            severity="high",
            category="secrets",
            host="example.com",
            url="https://example.com/app.js",
            description="Pattern match.",
            verified=True,
            reproductions=1,
            stable=True,
            decoy_suspected=True,
            decoy_reason="response mentions a honeytoken",
        )
        chains = chain_mod.build_chains([observed, cookie, decoy])
        chain_mod.apply_chain_ids(chains, [observed, cookie, decoy])
        meta = chain_mod.chains_meta(chains)
        bundles = {
            "enabled": True,
            "hosts_checked": 1,
            "assets_fetched": 2,
            "manifests": 1,
            "drift": 1,
            "missing_chunks": 1,
            "truncated_assets": 1,
            "libraries": {"jQuery": ["3.6.0"]},
            "warnings": [],
            "hosts": [{
                "host": "example.com",
                "url": "https://example.com/",
                "frameworks": ["Next.js"],
                "build_ids": ["abc12345", "def67890"],
                "assets": [{
                    "url": "https://example.com/_next/static/chunks/app.js",
                    "role": "script",
                    "status": 200,
                    "bytes": 1048576,
                    "content_length": 2097152,
                    "truncated": True,
                    "sha256": "a" * 64,
                    "build_hash": "abc12345",
                    "libraries": {"Lodash": ["4.17.15"]},
                }],
                "manifests": [],
                "libraries": {},
                "drift": [{
                    "type": "asset-hash-mismatch",
                    "logical_name": "app.js",
                    "page_hashes": ["abc12345"],
                    "manifest_hashes": ["def67890"],
                }],
                "missing": [{
                    "url": "https://example.com/old.js",
                    "status": 404,
                    "control": "https://example.com/app.js",
                    "control_status": 200,
                }],
                "truncated": [{
                    "url": "https://example.com/_next/static/chunks/app.js",
                    "captured_bytes": 1048576,
                    "declared_bytes": 2097152,
                }],
                "skipped": 0,
            }],
        }
        return ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="0.7.0",
            started_at="2026-10-27T00:00:00Z",
            finished_at="2026-10-27T00:01:00Z",
            findings=[observed, cookie, decoy],
            stats={"live_hosts": 1, "requests": 12},
            recon={"chains": meta, "bundles": bundles},
        )

    def test_markdown_shows_chains_bundles_and_validation(self):
        result = self._result()
        markdown = render_markdown(result)
        self.assertIn("## Evidence-linked exploit chains", markdown)
        self.assertIn("session-plaintext-example.com", markdown)
        self.assertIn("[OBSERVED]", markdown)
        self.assertIn("**Validation:** reproduced 2x", markdown)
        self.assertIn("Decoy / canary suspected", markdown)
        self.assertIn("### Bundle / build drift", markdown)
        self.assertIn("asset-hash-mismatch", markdown)
        self.assertIn("Missing referenced chunks", markdown)
        self.assertIn("Client-side library versions", markdown)
        self.assertIn("Truncated asset reads", markdown)
        self.assertIn("truncated of 2097152", markdown)

    def test_html_shows_chain_flow_filters_and_decoy_banner(self):
        result = self._result()
        markup = render_html(result)
        self.assertIn("Evidence-linked exploit chains", markup)
        self.assertIn("chain-session-plaintext-example.com", markup)
        self.assertIn("node st-observed", markup)
        self.assertIn("Evidence-linked", markup)
        self.assertIn('id="valid-only"', markup)
        self.assertIn('id="hide-decoys"', markup)
        self.assertIn('data-verified="1"', markup)
        self.assertIn('data-decoy="1"', markup)
        self.assertIn("Decoy / canary suspected", markup)
        self.assertIn("Bundle / build drift", markup)
        self.assertIn("asset-hash-mismatch", markup)
        self.assertIn("Content-Length", markup)
        self.assertIn("Truncated asset", markup)
        self.assertIn("Open finding", markup)

    def test_decoys_are_excluded_from_risk_and_priorities(self):
        result = self._result()
        audit = heuristic_audit(result)
        self.assertLessEqual(audit.risk_score, 100)
        for priority in audit.priorities:
            self.assertNotIn("Exposed test credential", priority["title"])
        self.assertTrue(any(
            "decoy/canary marker" in item.get("reason", "").lower()
            for item in audit.manual_review
        ))
        payload = _audit_payload(result, audit)
        validation = payload["validation"]
        self.assertEqual(validation["decoys"], 1)
        self.assertGreaterEqual(validation["chains_total"], 1)
        self.assertEqual(validation["bundle_drift"], 1)
        self.assertEqual(validation["missing_chunks"], 1)


class InjectionProbeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body="", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        html_type = {"Content-Type": "text/html; charset=utf-8"}
        path = parsed.path
        if path == "/search":
            value = query.get("q", [""])[0]
            if value.endswith("'"):
                self._send(
                    500,
                    "You have an error in your SQL syntax; check the manual",
                    html_type,
                )
            else:
                self._send(
                    200,
                    "<html><body>Results for " + html.escape(value)
                    + "</body></html>",
                    html_type,
                )
        elif path == "/item":
            value = query.get("id", [""])[0].upper()
            if "AND 1=2" in value or "AND 2=3" in value:
                self._send(200, "<html><body>No item found</body></html>",
                           html_type)
            else:
                self._send(
                    200,
                    "<html><body>Item detail " + ("x" * 240)
                    + "</body></html>",
                    html_type,
                )
        elif path == "/render":
            value = query.get("name", [""])[0]
            match = re.search(r"\{\{(\d+)\*(\d+)\}\}", value)
            if match:
                product = str(int(match.group(1)) * int(match.group(2)))
                value = value.replace(match.group(0), product)
            self._send(200, "<html><body>" + value + "</body></html>",
                       html_type)
        elif path == "/greet":
            value = query.get("next", [""])[0]
            self._send(200, "<html><body><div>" + value + "</div></body></html>",
                       html_type)
        elif path == "/go":
            value = query.get("next", [""])[0]
            headers = dict(html_type)
            if "\r\n" in value:
                name = value.split("\r\n", 1)[1].split(":", 1)[0].strip()
                if name.lower().startswith("x-ww-"):
                    headers[name] = "1"
            self._send(302, "", headers)
        elif path == "/fetch":
            value = query.get("url", [""])[0]
            host = urlsplit(value).hostname or value
            if host.endswith(".invalid"):
                self._send(
                    200,
                    "<html><body>could not resolve host: "
                    + html.escape(host) + "</body></html>",
                    html_type,
                )
            else:
                self._send(200, "<html><body>Fetched OK</body></html>",
                           html_type)
        elif path == "/view":
            value = query.get("file", [""])[0]
            if "etc/passwd" in value:
                self._send(200, "root:x:0:0:root:/root:/bin/bash\n",
                           {"Content-Type": "text/plain"})
            else:
                self._send(200, "<html><body>Default page</body></html>",
                           html_type)
        elif path == "/shell.php":
            self._send(200, "<?php system($_GET['cmd']); ?>",
                       {"Content-Type": "text/plain"})
        elif path == "/b374k.php":
            self._send(200, "<html><title>b374k shell</title></html>",
                       html_type)
        else:
            self._send(404, "not found", {"Content-Type": "text/plain"})


class InjectionModuleTests(ServerHarness):
    handler = InjectionProbeHandler

    def setUp(self):
        self.client = HttpClient(
            scopes=["127.0.0.1"], rate=1000.0, timeout=5.0,
            budget=Budget(4000))

    def fetch(self, url: str) -> HttpResult:
        return self.client.get(url, follow=False, read_limit=131072)

    def analyze(self, query: str):
        return injection_mod.analyze(
            [self.base + query], self.fetch, ["127.0.0.1"], None,
            max_requests=80,
        )

    def test_error_based_sql_injection(self):
        produced, meta = self.analyze("search?q=phone")
        finding = next(
            (item for item in produced if "SQL error" in item[0].title), None)
        self.assertIsNotNone(finding, [f.title for f, _ in produced])
        finding, evidence = finding
        self.assertEqual(finding.category, "sqli")
        self.assertEqual(finding.severity, "high")
        self.assertTrue(finding.verified)
        self.assertIn("MySQL", finding.evidence)
        self.assertGreaterEqual(finding.reproductions, 2)
        self.assertEqual(meta["checks"]["sql_error"], 1)

    def test_boolean_sql_injection_differential(self):
        produced, _meta = self.analyze("item?id=1")
        finding = next(
            (item for item in produced if "Boolean" in item[0].title), None)
        self.assertIsNotNone(finding)
        finding, _evidence = finding
        self.assertEqual(finding.category, "sqli")
        self.assertEqual(finding.severity, "medium")
        self.assertTrue(finding.verified)

    def test_server_side_template_injection(self):
        produced, _meta = self.analyze("render?name=hello")
        finding = next(
            (item for item in produced if item[0].category == "ssti"), None)
        self.assertIsNotNone(finding, [f.title for f, _ in produced])
        self.assertEqual(finding[0].severity, "high")
        self.assertIn("Jinja2", finding[0].title)
        self.assertTrue(finding[0].verified)

    def test_reflected_html_injection(self):
        produced, _meta = self.analyze("greet?next=hi")
        finding = next(
            (item for item in produced if item[0].category == "xss"), None)
        self.assertIsNotNone(finding)
        self.assertEqual(finding[0].severity, "medium")
        self.assertIn("HTML body context", finding[0].evidence)

    def test_local_file_inclusion(self):
        produced, _meta = self.analyze("view?file=home")
        finding = next(
            (item for item in produced if item[0].category == "lfi"), None)
        self.assertIsNotNone(finding, [f.title for f, _ in produced])
        self.assertEqual(finding[0].severity, "high")
        self.assertIn("root:x:0:0:", finding[0].evidence)

    def test_clean_parameter_produces_no_finding(self):
        produced, _meta = self.analyze("item?id=abc")
        self.assertEqual(produced, [])

    def test_server_side_request_fetch(self):
        produced, meta = self.analyze("fetch?url=https://example.org/logo.png")
        finding = next(
            (item for item in produced if item[0].category == "ssrf"), None)
        self.assertIsNotNone(finding, [f.title for f, _ in produced])
        finding, _evidence = finding
        self.assertEqual(finding.severity, "medium")
        self.assertTrue(finding.verified)
        self.assertIn(".invalid", finding.evidence)
        self.assertIn("could not resolve host", finding.evidence)
        self.assertEqual(meta["checks"]["ssrf"], 1)

    def test_header_injection_via_crlf(self):
        produced, meta = self.analyze("go?next=/home")
        finding = next(
            (item for item in produced if item[0].category == "crlf"), None)
        self.assertIsNotNone(finding, [f.title for f, _ in produced])
        finding, _evidence = finding
        self.assertEqual(finding.severity, "low")
        self.assertTrue(finding.verified)
        self.assertIn("X-WW-", finding.evidence)
        self.assertEqual(meta["checks"]["crlf"], 1)

    def test_plain_page_has_no_ssrf_or_crlf_signal(self):
        produced, meta = self.analyze("greet?next=/home")
        self.assertEqual(
            [f.title for f, _ in produced if f.category in ("ssrf", "crlf")],
            [])
        self.assertEqual(meta["checks"]["ssrf"], 0)
        self.assertEqual(meta["checks"]["crlf"], 0)

    def test_credential_parameters_are_skipped(self):
        produced, meta = self.analyze("search?token=abc123secret")
        self.assertEqual(produced, [])
        self.assertEqual(meta["candidate_urls"], 0)


class BackdoorModuleTests(ServerHarness):
    handler = InjectionProbeHandler

    def setUp(self):
        self.client = HttpClient(
            scopes=["127.0.0.1"], rate=1000.0, timeout=5.0,
            budget=Budget(4000))

    def fetch(self, url: str) -> HttpResult:
        return self.client.get(url, follow=False, read_limit=131072)

    def test_reachable_web_shells(self):
        produced, meta = backdoor_mod.analyze(
            [("127.0.0.1", self.base.rstrip("/"))],
            self.fetch,
            ["127.0.0.1"],
            None,
            max_requests=80,
        )
        by_url = {finding.url.rsplit("/", 1)[-1]: finding
                  for finding, _ in produced}
        self.assertIn("shell.php", by_url)
        self.assertIn("b374k.php", by_url)
        self.assertEqual(by_url["shell.php"].severity, "high")
        self.assertEqual(by_url["b374k.php"].severity, "critical")
        self.assertTrue(by_url["b374k.php"].verified)
        self.assertEqual(meta["findings"], 2)

    def test_catch_all_suppresses_backdoor_claims(self):
        produced, _meta = backdoor_mod.analyze(
            [("127.0.0.1", self.base.rstrip("/"))],
            self.fetch,
            ["127.0.0.1"],
            lambda origin, path, result: True,
            max_requests=80,
        )
        self.assertEqual(produced, [])

    def test_checker_wires_injection_and_backdoors(self):
        client = HttpClient(
            scopes=["127.0.0.1"], rate=1000.0, timeout=5.0,
            budget=Budget(4000))
        probe = Probe(host="127.0.0.1", url=self.base + "render?name=hello",
                      status=200, result=client.get(self.base + "render?name=hello"))
        checker = Checker(
            client,
            [probe],
            [self.base + "render?name=hello"],
            secrets=False,
            bundles=False,
        )
        findings = checker.run()
        self.assertTrue(any(f.category == "ssti" for f in findings))
        self.assertTrue(any(f.category == "backdoor" for f in findings))
        self.assertTrue(checker.injection_meta["enabled"])
        self.assertEqual(checker.backdoor_meta["findings"], 2)
        self.assertGreater(checker.injection_meta["requests"], 0)


class SchemaFileCheckTests(unittest.TestCase):
    def _validator(self, path):
        for entry in FILE_CHECKS:
            if entry[0] == path:
                return entry[5]
        self.fail(f"{path} is not in FILE_CHECKS")

    def test_graphql_introspection_requires_json_body(self):
        validate = self._validator(
            "/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D")
        body = b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
        self.assertTrue(validate(body, {}, 200))
        self.assertFalse(validate(b"<html>queryType</html>", {}, 200))
        self.assertFalse(validate(body, {}, 500))

    def test_wordpress_users_requires_json_array(self):
        validate = self._validator("/wp-json/wp/v2/users")
        self.assertTrue(validate(b'[{"id":1,"slug":"admin"}]', {}, 200))
        self.assertFalse(validate(b'{"id":1,"slug":"admin"}', {}, 200))
        self.assertFalse(validate(b'[{"slug":"admin"}]', {}, 404))

    def test_actuator_mappings_and_configprops_markers(self):
        mappings = self._validator("/actuator/mappings")
        self.assertTrue(
            mappings(b'{"contexts":{"app":{"mappings":[]}}}', {}, 200))
        configprops = self._validator("/actuator/configprops")
        self.assertTrue(configprops(
            b'{"contexts":{"app":{"properties":{"db":"x"}}}}', {}, 200))
        self.assertFalse(configprops(b'{"status":"UP"}', {}, 200))

    def test_repo_metadata_and_debug_console_markers(self):
        svn = self._validator("/.svn/wc.db")
        self.assertTrue(svn(b"SQLite format 3\x00", {}, 200))
        self.assertFalse(svn(b"<html>not found</html>", {}, 200))
        hg = self._validator("/.hg/requires")
        self.assertTrue(hg(b"revlogv1\nstore\n", {}, 200))
        profiler = self._validator("/_profiler")
        self.assertTrue(
            profiler(b"<html><title>Symfony Profiler</title></html>", {}, 200))
        telescope = self._validator("/telescope")
        self.assertTrue(
            telescope(b"<html><h1>Laravel Telescope</h1></html>", {}, 200))

    def test_crossdomain_wildcard_requires_grant(self):
        validate = self._validator("/crossdomain.xml")
        policy = (b'<?xml version="1.0"?><cross-domain-policy>'
                  b'<allow-access-from domain="*"/></cross-domain-policy>')
        self.assertTrue(validate(policy, {}, 200))
        restricted = (b'<cross-domain-policy><allow-access-from '
                      b'domain="trusted.example"/></cross-domain-policy>')
        self.assertFalse(validate(restricted, {}, 200))
        self.assertFalse(validate(policy, {}, 404))


class WafFingerprintTests(unittest.TestCase):
    def _probe(self, host, headers, live=True):
        from types import SimpleNamespace
        result = HttpResult(
            url=f"https://{host}/", status=200, ok=True, headers=headers)
        return SimpleNamespace(live=live, host=host, result=result)

    def test_detects_cdn_headers_and_cookies(self):
        probes = [
            self._probe("a.example", {"cf-ray": "abc", "server": "cloudflare"}),
            self._probe("b.example", {
                "x-iinfo": "1", "set-cookie": "incap_ses_1=abc; path=/"}),
            self._probe("c.example", {"server": "nginx"}),
            self._probe("d.example", {}, live=False),
        ]
        meta = waf_fingerprint(probes)
        providers = {item["provider"]: item for item in meta["providers"]}
        self.assertEqual(meta["checked_hosts"], 3)
        self.assertEqual(providers["Cloudflare"]["evidence"], "cf-ray")
        self.assertEqual(providers["Cloudflare"]["hosts"], ["a.example"])
        self.assertIn("Imperva/Incapsula", providers)

    def test_no_fingerprint_without_signatures(self):
        meta = waf_fingerprint([self._probe("a.example", {"server": "nginx"})])
        self.assertEqual(meta["providers"], [])
        self.assertEqual(meta["checked_hosts"], 1)


if __name__ == "__main__":
    unittest.main()
