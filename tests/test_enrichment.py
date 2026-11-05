from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from webwarden import poc
from webwarden.cve import (
    candidate_finding,
    cpe_variants,
    extract_versions,
    parse_nvd,
)
from webwarden.httpclient import HttpResult
from webwarden.models import CveRef, Finding, ScanResult
from webwarden.nuclei import availability, parse_jsonl
from webwarden.recon import Probe
from webwarden.report import render_markdown


NUCLEI_EVENT = {
    "template-id": "CVE-2021-41773",
    "info": {
        "name": "Apache 2.4.49 Path Traversal",
        "severity": "high",
        "description": "Path traversal and file disclosure.",
        "remediation": "Upgrade Apache HTTP Server.",
        "tags": ["cve", "apache", "lfi"],
        "classification": {
            "cve-id": ["CVE-2021-41773"],
            "cvss-score": 7.5,
        },
    },
    "matched-at": "https://app.example.com/cgi-bin/.%2e/etc/passwd",
    "matcher-name": "regex",
    "type": "http",
}


class PocTests(unittest.TestCase):
    def test_nuclei_template_id_is_validated(self):
        self.assertIsNone(
            poc.nuclei_command("https://example.com/", "ok; rm -rf /")
        )
        command = poc.nuclei_command("https://example.com/", "CVE-2021-41773")
        self.assertIn("-id CVE-2021-41773", command or "")
        self.assertIn("-no-interactsh", command or "")

    def test_idor_poc_uses_placeholders(self):
        finding = Finding(
            title="possible IDOR",
            severity="medium",
            category="access-control",
            host="example.com",
            url="https://example.com/user/1",
            description="test",
        )
        commands = poc.for_finding(finding, has_auth_a=True, has_auth_b=True)
        joined = "\n".join(commands)
        self.assertIn("$SESSION_A", joined)
        self.assertIn("$SESSION_B", joined)
        self.assertNotIn("session=", joined)

    def test_script_never_embeds_secrets(self):
        finding = Finding(
            title="possible IDOR",
            severity="medium",
            category="access-control",
            host="example.com",
            url="https://example.com/user/1",
            description="test",
            poc=['curl -H "$SESSION_A" https://example.com/user/1'],
        )
        script = poc.render_script(
            [finding], "example.com", generated_at="2026-10-26T00:00:00Z",
            has_auth_a=True, has_auth_b=False,
        )
        self.assertIn('SESSION_A="${SESSION_A:-}"', script)
        self.assertIn("export SESSION_A=", script)
        self.assertNotIn("session=alice", script)
        self.assertNotIn(" --data", script)

    def test_write_script_sets_owner_only_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = poc.write_script(
                Path(tmp) / "poc.sh", [], "example.com"
            )
            self.assertTrue(path.exists())
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)


class NucleiTests(unittest.TestCase):
    def test_parse_match_with_cve(self):
        findings = parse_jsonl(json.dumps(NUCLEI_EVENT), ["*.example.com"])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.title, "Apache 2.4.49 Path Traversal")
        self.assertEqual(finding.severity, "high")
        self.assertTrue(finding.verified)
        self.assertEqual([cve.id for cve in finding.cves], ["CVE-2021-41773"])
        self.assertEqual(finding.cves[0].source, "nuclei")
        self.assertTrue(finding.cves[0].status.startswith("template match"))
        self.assertTrue(any("nuclei -u" in command for command in finding.poc))

    def test_template_id_cve_is_detected(self):
        event = {
            "template-id": "CVE-2023-12345",
            "info": {"name": "Example", "severity": "medium"},
            "matched-at": "https://app.example.com/x",
        }
        findings = parse_jsonl(json.dumps(event), ["*.example.com"])
        self.assertEqual(findings[0].cves[0].id, "CVE-2023-12345")

    def test_out_of_scope_and_invalid_lines_are_ignored(self):
        event = dict(NUCLEI_EVENT)
        event["matched-at"] = "https://outside.invalid/x"
        payload = json.dumps(event) + "\nnot json\n" + json.dumps(NUCLEI_EVENT)
        findings = parse_jsonl(payload, ["*.example.com"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].host, "app.example.com")

    def test_missing_binary_is_reported(self):
        status = availability(binary="/nonexistent/nuclei")
        self.assertFalse(status.installed)


class NvdTests(unittest.TestCase):
    def test_parse_nvd_metrics_and_sorting(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-1111",
                        "metrics": {"cvssMetricV31": [{
                            "cvssData": {"baseScore": 5.3,
                                         "baseSeverity": "MEDIUM"},
                        }]},
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2021-2222",
                        "metrics": {"cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8,
                                         "baseSeverity": "CRITICAL"},
                        }]},
                        "references": [{"url": "https://vendor.example/advisory"}],
                    }
                },
                {"cve": {"id": "NOT-A-CVE"}},
            ]
        }
        refs = parse_nvd(payload)
        self.assertEqual([ref.id for ref in refs],
                         ["CVE-2021-2222", "CVE-2021-1111"])
        self.assertEqual(refs[0].score, 9.8)
        self.assertEqual(refs[0].source, "nvd")
        self.assertTrue(refs[0].status.startswith("candidate"))
        self.assertEqual(refs[0].url, "https://vendor.example/advisory")

    def test_cpe_variants_include_nginx_vendor_change(self):
        cpes = cpe_variants("nginx", "1.18.0")
        self.assertIn("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", cpes)
        self.assertIn("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", cpes)

    def test_extract_versions_from_headers_and_body(self):
        result = HttpResult(
            url="https://example.com/",
            headers={
                "server": "nginx/1.18.0",
                "x-powered-by": "PHP/7.4.3",
            },
            body=(
                b"<meta name='generator' content='WordPress 5.8.1'>"
                b"<script src='/jquery.min.js?ver=3.5.1'></script>"
            ),
        )
        probe = Probe(
            host="example.com", url="https://example.com/",
            status=200, result=result,
        )
        versions = extract_versions([probe])
        self.assertEqual(versions["nginx"]["version"], "1.18.0")
        self.assertEqual(versions["php"]["version"], "7.4.3")
        self.assertEqual(versions["wordpress"]["version"], "5.8.1")
        self.assertEqual(versions["jquery"]["version"], "3.5.1")

    def test_candidate_finding_is_unverified(self):
        ref = CveRef(
            id="CVE-2021-23017", source="nvd",
            status="candidate (not verified)", score=7.7, severity="high",
        )
        finding = candidate_finding("nginx", {
            "version": "1.18.0",
            "hosts": ["example.com"],
            "url": "https://example.com/",
            "evidence": "Server: nginx/1.18.0",
        }, [ref])
        self.assertFalse(finding.verified)
        self.assertEqual(finding.severity, "info")
        self.assertEqual(finding.cves[0].id, "CVE-2021-23017")
        self.assertIn("not tested on the target", finding.verification)


class ReportEnrichmentTests(unittest.TestCase):
    def test_report_shows_verification_cves_and_poc(self):
        finding = Finding(
            title="Exposed .env file",
            severity="high",
            category="exposure",
            host="example.com",
            url="https://example.com/.env",
            description="Environment file is readable.",
            remediation="Remove the file.",
            evidence="HTTP 200; signature matched",
            confidence="confirmed",
            verified=True,
            verification="signature matched on two independent requests",
            poc=["curl -sS --max-time 15 -D - 'https://example.com/.env'"],
            cves=[CveRef(
                id="CVE-2021-23017", source="nvd",
                status="candidate (not verified)", score=7.7,
            )],
        )
        result = ScanResult(
            target="example.com",
            scopes=["example.com"],
            version="0.2.0",
            started_at="2026-10-26T00:00:00Z",
            finished_at="2026-10-26T00:10:00Z",
            stats={"findings": 1, "verified": 1, "cves": 1},
            recon={
                "components": {
                    "nginx": {
                        "version": "1.18.0",
                        "evidence": "Server: nginx/1.18.0",
                        "hosts": ["example.com"],
                    }
                },
                "nuclei": {
                    "enabled": False,
                    "engine": None,
                    "templates": None,
                    "targets": 0,
                    "matches": 0,
                    "note": "not requested",
                },
            },
            findings=[finding],
        )
        markdown = render_markdown(result)
        self.assertIn("Verified by reproduction:** yes", markdown)
        self.assertIn("CVE references", markdown)
        self.assertIn("CVE-2021-23017", markdown)
        self.assertIn("candidate (not verified)", markdown)
        self.assertIn("PoC (authorized scope only)", markdown)
        self.assertIn("Component versions", markdown)
        self.assertIn("Nuclei template matching", markdown)
        self.assertIn("Findings verified by reproduction: **1 / 1**", markdown)


if __name__ == "__main__":
    unittest.main()
