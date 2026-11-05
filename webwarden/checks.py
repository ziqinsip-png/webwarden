"""Non-destructive, read-only checks and finding generation."""

from __future__ import annotations

import re
import secrets
import shlex
import ssl
import time
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from . import backdoors as backdoor_scan
from . import bundles as bundle_recon
from . import decoy
from . import injection as injection_scan
from .evidence import (
    DEFAULT_EVIDENCE_BYTES,
    EvidenceStore,
    evidence_limit as normalize_evidence_limit,
)
from .httpclient import HttpClient, HttpResult
from .models import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_FIRM,
    CONFIDENCE_MANUAL,
    Finding,
)
from .poc import (
    evidence_slug,
    for_finding as poc_for_finding,
    full_capture,
)
from .recon import Probe
from .secrets import scan_text
from .tokens import CookieView, cookie_summary, decode_jwt, parse_cookies
from .util import (
    content_looks_like_login,
    in_scope,
    sha_prefix,
    similar_length,
)

REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "next", "return",
    "returnurl", "return_url", "dest", "destination", "continue", "target",
    "r", "u", "goto", "callback", "forward",
}
BLOCKED_STATUSES = {401, 403, 404, 410, 429, 451}
ID_RE = re.compile(
    r"(?:^|[/=])(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12})(?:[/?&#]|$)",
    re.IGNORECASE,
)
PROBE_ORIGIN_RE = re.compile(r"^https?://[^/]+", re.IGNORECASE)
HEADER_LABELS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}
HEADER_ORDER = list(HEADER_LABELS.values())
SECURITY_TXT_PATH = "/.well-known/security.txt"
SECURITY_TXT_FIELDS = (
    "contact", "expires", "encryption", "acknowledgments",
    "preferred-languages", "canonical", "policy", "hiring",
)
HIGH_RISK_PARAMS = {
    "password", "passwd", "pwd", "client_secret", "secret", "access_token",
    "refresh_token", "id_token", "token", "jwt", "session", "sessionid",
    "sid", "auth", "authorization", "api_key", "apikey", "private_key",
}
LOW_RISK_PARAMS = {
    "key", "signature", "sig", "code", "ticket", "nonce", "invite",
}
SCRIPT_RE = re.compile(
    r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE
)
SOURCE_MAP_RE = re.compile(
    r"sourceMappingURL=([^\s*\"']+)", re.IGNORECASE
)


def _marker(*markers: bytes):
    def validate(body: bytes, headers: dict[str, str], status: int) -> bool:
        if status not in (200, 206):
            return False
        lowered = body.lower()
        return any(marker in body or marker.lower() in lowered for marker in markers)

    return validate


def _any_status_ok(body: bytes, headers: dict[str, str], status: int) -> bool:
    return status in (200, 206) and len(body) >= 32


def _regex_marker(*patterns: str):
    compiled = [re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in patterns]

    def validate(body: bytes, headers: dict[str, str], status: int) -> bool:
        if status not in (200, 206):
            return False
        text = body[:400000].decode("utf-8", "replace")
        return any(pattern.search(text) for pattern in compiled)

    return validate


def _xmlrpc_marker(body: bytes, headers: dict[str, str], status: int) -> bool:
    if status not in (200, 405):
        return False
    return b"xml-rpc" in body[:4096].lower()


def _all_marker(*markers: bytes):
    def validate(body: bytes, headers: dict[str, str], status: int) -> bool:
        if status not in (200, 206):
            return False
        lowered = body.lower()
        return all(marker.lower() in lowered for marker in markers)

    return validate


def _json_marker(*markers: bytes):
    """Require a JSON body that carries every marker (case-insensitive)."""
    def validate(body: bytes, headers: dict[str, str], status: int) -> bool:
        if status not in (200, 206):
            return False
        head = body[:2048].lstrip()
        if not head.startswith((b"{", b"[")):
            return False
        lowered = body[:200000].lower()
        return all(marker.lower() in lowered for marker in markers)

    return validate


def _json_array_marker(*markers: bytes):
    """Same as ``_json_marker`` but the body must be a JSON array."""
    def validate(body: bytes, headers: dict[str, str], status: int) -> bool:
        if status not in (200, 206):
            return False
        if not body[:512].lstrip().startswith(b"["):
            return False
        lowered = body[:200000].lower()
        return all(marker.lower() in lowered for marker in markers)

    return validate


def _wildcard_xml_marker(root: bytes):
    """Require the XML policy root and a wildcard grant in the same body."""
    def validate(body: bytes, headers: dict[str, str], status: int) -> bool:
        if status not in (200, 206):
            return False
        head = body[:65536]
        if root.lower() not in head.lower():
            return False
        return b'domain="*"' in head or b"domain='*'" in head \
            or b'"*"' in head

    return validate


FILE_CHECKS = [
    ("/.git/HEAD", "high", "Exposed .git directory",
     "Version-control metadata is readable, which can leak source code, history, "
     "credentials, and deployment details.",
     "Block access to .git/ at the web server or remove the directory from the docroot.",
     _marker(b"ref: refs/"), CONFIDENCE_CONFIRMED),
    ("/.git/config", "high", "Exposed git config",
     "Git configuration is readable and may disclose remote URLs and credentials.",
     "Deny /.git/* in the web server configuration.",
     _marker(b"[core]"), CONFIDENCE_CONFIRMED),
    ("/.env", "high", "Exposed .env file",
     "Environment files often contain database passwords, API keys, and app secrets.",
     "Never serve dotfiles; move secrets out of the docroot and rotate exposed keys.",
     _marker(b"APP_KEY=", b"DB_PASSWORD=", b"SECRET_KEY=", b"AWS_SECRET_ACCESS_KEY=",
             b"DB_PASS=", b"MAIL_PASSWORD="),
     CONFIDENCE_CONFIRMED),
    ("/.aws/credentials", "critical", "Exposed AWS credentials file",
     "Cloud credentials were returned by the web server.",
     "Remove the file, rotate the keys immediately, and review cloud audit logs.",
     _marker(b"aws_access_key_id"), CONFIDENCE_CONFIRMED),
    ("/id_rsa", "critical", "Private SSH key exposed",
     "A private key was served over HTTP.",
     "Delete the file from the docroot, rotate the key, and audit for misuse.",
     _marker(b"BEGIN OPENSSH PRIVATE KEY", b"BEGIN RSA PRIVATE KEY"),
     CONFIDENCE_CONFIRMED),
    ("/wp-config.php.bak", "high", "WordPress config backup exposed",
     "A backup of wp-config.php can leak database credentials and salts.",
     "Remove backups from the docroot and rotate credentials.",
     _marker(b"DB_NAME", b"DB_PASSWORD"), CONFIDENCE_CONFIRMED),
    ("/config.php.bak", "high", "PHP config backup exposed",
     "A backup configuration file can leak credentials.",
     "Remove backups from the docroot and rotate credentials.",
     _marker(b"DB_NAME", b"DB_PASSWORD", b"$db_pass", b"'password' =>",
             b'"password" =>'),
     CONFIDENCE_CONFIRMED),
    ("/backup.zip", "medium", "Public backup archive",
     "A backup archive is downloadable and may contain source or database dumps.",
     "Remove the archive from the docroot and store backups outside the web root.",
     _marker(b"PK\x03\x04"), CONFIDENCE_FIRM),
    ("/backup.tar.gz", "medium", "Public backup archive",
     "A compressed backup is downloadable and may contain source or database dumps.",
     "Remove the archive from the docroot and store backups outside the web root.",
     _marker(b"\x1f\x8b"), CONFIDENCE_FIRM),
    ("/server-status", "medium", "Apache server-status exposed",
     "Apache status pages disclose internal URLs, clients, and request details.",
     "Restrict /server-status to localhost.",
     _marker(b"Apache Server Status"), CONFIDENCE_CONFIRMED),
    ("/actuator/env", "high", "Spring Boot actuator environment exposed",
     "Actuator endpoints can leak configuration, secrets, and environment variables.",
     "Disable or authenticate actuator endpoints.",
     _marker(b'"propertySources"', b'"activeProfiles"'), CONFIDENCE_FIRM),
    ("/phpinfo.php", "low", "phpinfo() exposed",
     "phpinfo discloses PHP configuration, paths, and loaded modules.",
     "Remove phpinfo scripts from production.",
     _marker(b"PHP Version"), CONFIDENCE_CONFIRMED),
    ("/.svn/entries", "medium", "Exposed SVN metadata",
     "Subversion metadata may leak source code and history.",
     "Deny access to .svn/ directories.",
     _marker(b"dir\n", b"svn://"), CONFIDENCE_FIRM),
    ("/.DS_Store", "low", "macOS .DS_Store exposed",
     ".DS_Store reveals directory and file names to unauthenticated visitors.",
     "Deny dotfiles at the web server.",
     _marker(b"Bud1"), CONFIDENCE_CONFIRMED),
    ("/admin/", "info", "Admin interface reachable",
     "An administrative interface responds without an authentication challenge. "
     "Verify manually whether it is intended to be public.",
     "Restrict administrative interfaces by network or SSO.",
     _any_status_ok, CONFIDENCE_MANUAL),
    ("/wp-admin/", "info", "WordPress admin reachable",
     "The WordPress admin login page is reachable. This is normal for WordPress; "
     "verify hardening (2FA, rate limiting, XML-RPC).",
     "Enforce 2FA, restrict /wp-login.php, and disable XML-RPC if unused.",
     _marker(b"wp-login", b"user_login", b"wordpress"), CONFIDENCE_MANUAL),
    ("/phpmyadmin/", "low", "phpMyAdmin reachable",
     "A database administration panel responds publicly.",
     "Restrict phpMyAdmin behind VPN/SSO and strong authentication.",
     _marker(b"phpmyadmin", b"pma_"), CONFIDENCE_MANUAL),
    ("/manager/html", "low", "Tomcat manager reachable",
     "The Tomcat manager application responds publicly.",
     "Restrict /manager to trusted networks and remove default accounts.",
     _all_marker(b"tomcat", b"manager"), CONFIDENCE_FIRM),
    ("/swagger-ui/", "info", "API documentation exposed",
     "Swagger UI is public and may reveal internal endpoints and parameters.",
     "Require authentication or disable API docs in production.",
     _marker(b"Swagger UI", b"swagger-ui"), CONFIDENCE_FIRM),
    ("/graphql", "info", "GraphQL endpoint exposed",
     "A GraphQL endpoint responds. Introspection and authorization should be reviewed.",
     "Disable introspection in production and enforce per-field authorization.",
     _marker(b'"data"', b'"errors"'), CONFIDENCE_MANUAL),
    ("/.htpasswd", "medium", "Apache .htpasswd exposed",
     "Password hashes for HTTP authentication are downloadable. Offline "
     "cracking may recover credentials.",
     "Deny .htpasswd at the web server and rotate any exposed passwords.",
     _regex_marker(r"^[^:\r\n]{1,64}:\$(?:apr1|2[aby]|1|5|6)\$"),
     CONFIDENCE_CONFIRMED),
    ("/.htaccess", "low", "Apache .htaccess exposed",
     "Server rewrite and access rules are readable, which reveals internal "
     "paths and can help bypass naive filtering.",
     "Deny dotfiles at the web server.",
     _regex_marker(r"^\s*(?:RewriteEngine|AuthType|Order\s+allow|<IfModule)",
                   r"deny from all"),
     CONFIDENCE_FIRM),
    ("/web.config", "medium", "IIS web.config exposed",
     "IIS configuration is readable and may contain connection strings or "
     "authentication settings.",
     "Deny web.config and move secrets to protected configuration.",
     _regex_marker(r"<configuration[\s>]", r"<system\.web>"),
     CONFIDENCE_FIRM),
    ("/.npmrc", "high", "npm authentication token exposed",
     "An .npmrc file with an _authToken was served; the token may allow "
     "publishing or reading private packages.",
     "Remove .npmrc from the docroot and revoke the token.",
     _regex_marker(r"(?m)^\s*(?://[^=\s]+/)?_authToken\s*="),
     CONFIDENCE_CONFIRMED),
    ("/.gitlab-ci.yml", "medium", "GitLab CI configuration exposed",
     "CI configuration can reveal internal services, variables, and deployment "
     "commands.",
     "Remove CI files from the web root.",
     _regex_marker(r"(?m)^\s*(?:stages|script|variables)\s*:"),
     CONFIDENCE_FIRM),
    ("/docker-compose.yml", "medium", "Docker Compose file exposed",
     "Compose files disclose service names, images, ports, and sometimes "
     "credentials via environment values.",
     "Remove compose files from the web root and use secrets management.",
     _regex_marker(r"(?m)^\s*services\s*:"),
     CONFIDENCE_FIRM),
    ("/Dockerfile", "low", "Dockerfile exposed",
     "The build recipe reveals base images, installed packages, and internal "
     "paths.",
     "Remove build files from the web root.",
     _regex_marker(r"(?m)^\s*FROM\s+\S+",
                   r"(?m)^\s*(?:RUN|COPY|WORKDIR|CMD|ENTRYPOINT)\s+"),
     CONFIDENCE_FIRM),
    ("/composer.lock", "low", "Composer lockfile exposed",
     "The lockfile enumerates exact PHP dependency versions, which helps map "
     "known CVEs.",
     "Remove lockfiles from the docroot.",
     _regex_marker(r'"packages"\s*:'), CONFIDENCE_FIRM),
    ("/.idea/workspace.xml", "low", "JetBrains workspace file exposed",
     "IDE workspace metadata may reveal project paths, run configurations, and "
     "internal hostnames.",
     "Deny .idea/ at the web server.",
     _regex_marker(r"<project version="), CONFIDENCE_FIRM),
    ("/dump.sql", "high", "Database dump downloadable",
     "A SQL dump is public. It may contain user data, password hashes, and "
     "application secrets.",
     "Remove the dump, rotate exposed credentials, and review data exposure.",
     _regex_marker(r"(?is)CREATE TABLE[\s\S]{0,2000}INSERT INTO"),
     CONFIDENCE_CONFIRMED),
    ("/database.sql", "high", "Database dump downloadable",
     "A SQL dump is public. It may contain user data, password hashes, and "
     "application secrets.",
     "Remove the dump, rotate exposed credentials, and review data exposure.",
     _regex_marker(r"(?is)CREATE TABLE[\s\S]{0,2000}INSERT INTO"),
     CONFIDENCE_CONFIRMED),
    ("/backup.sql", "high", "Database dump downloadable",
     "A SQL backup is public. It may contain user data, password hashes, and "
     "application secrets.",
     "Remove the backup, rotate exposed credentials, and review data exposure.",
     _regex_marker(r"(?is)CREATE TABLE[\s\S]{0,2000}INSERT INTO"),
     CONFIDENCE_CONFIRMED),
    ("/.env.local", "high", "Exposed .env backup",
     "An environment file with application secrets is downloadable.",
     "Remove the file, rotate every exposed secret, and review access logs.",
     _marker(b"APP_KEY=", b"DB_PASSWORD=", b"SECRET_KEY=",
             b"AWS_SECRET_ACCESS_KEY=", b"API_KEY="),
     CONFIDENCE_CONFIRMED),
    ("/.env.production", "high", "Exposed production .env",
     "A production environment file with application secrets is downloadable.",
     "Remove the file, rotate every exposed secret, and review access logs.",
     _marker(b"APP_KEY=", b"DB_PASSWORD=", b"SECRET_KEY=",
             b"AWS_SECRET_ACCESS_KEY=", b"API_KEY="),
     CONFIDENCE_CONFIRMED),
    ("/sftp-config.json", "high", "SFTP client configuration exposed",
     "Editor SFTP configuration commonly stores host, username, password, and "
     "the remote root path.",
     "Remove the file and rotate the SFTP credential.",
     _regex_marker(r'"type"\s*:\s*"s?ftp"'), CONFIDENCE_CONFIRMED),
    ("/wp-config.php~", "high", "WordPress config backup exposed",
     "A backup of wp-config.php can leak database credentials and salts.",
     "Remove backups from the docroot and rotate credentials.",
     _marker(b"DB_NAME", b"DB_PASSWORD"), CONFIDENCE_CONFIRMED),
    ("/config.bak", "high", "PHP config backup exposed",
     "A backup configuration file can leak database credentials.",
     "Remove backups from the docroot and rotate credentials.",
     _marker(b"DB_NAME", b"DB_PASSWORD", b"$db_pass", b"'password' =>",
             b'"password" =>'),
     CONFIDENCE_CONFIRMED),
    ("/storage/logs/laravel.log", "medium", "Laravel log exposed",
     "Application logs can contain stack traces, SQL, session identifiers, and "
     "sometimes credentials.",
     "Deny log paths and store logs outside the docroot.",
     _regex_marker(r"production\.ERROR", r"local\.ERROR"),
     CONFIDENCE_CONFIRMED),
    ("/debug.log", "low", "Debug log exposed",
     "A debug log may disclose stack traces and internal paths.",
     "Deny log files at the web server.",
     _regex_marker(r"(?m)^\[[^\]]+\] .*(?:Fatal error|Stack trace|PHP Warning)"),
     CONFIDENCE_FIRM),
    ("/.git/logs/HEAD", "low", "Git reflog exposed",
     "Git reflog reveals commits, author identities, and branch operations.",
     "Deny .git/ at the web server.",
     _regex_marker(r"(?m)^[0-9a-f]{40} "), CONFIDENCE_CONFIRMED),
    ("/actuator/heapdump", "high", "Spring Boot heap dump downloadable",
     "A heap dump can contain live sessions, credentials, and personal data "
     "from application memory.",
     "Disable or authenticate actuator heap dumps and treat the data as "
     "compromised.",
     _marker(b"JAVA PROFILE", b"HPROF"), CONFIDENCE_CONFIRMED),
    ("/openapi.json", "info", "OpenAPI specification exposed",
     "The API schema is public, which reveals endpoints and parameter names. "
     "This is informational unless it enables unauthorized data access.",
     "Require authentication or remove schema files from production.",
     _regex_marker(r'"(?:openapi|swagger)"\s*:'), CONFIDENCE_CONFIRMED),
    ("/swagger.json", "info", "Swagger specification exposed",
     "The API schema is public, which reveals endpoints and parameter names.",
     "Require authentication or remove schema files from production.",
     _regex_marker(r'"(?:openapi|swagger)"\s*:'), CONFIDENCE_CONFIRMED),
    ("/api-docs", "info", "API documentation reachable",
     "API documentation responds publicly and may reveal internal endpoints.",
     "Require authentication or disable docs in production.",
     _regex_marker(r'"(?:openapi|swagger)"\s*:', r"Swagger UI"),
     CONFIDENCE_FIRM),
    ("/xmlrpc.php", "low", "WordPress XML-RPC enabled",
     "The XML-RPC endpoint accepts requests. It can amplify credential "
     "brute force and enable pingback-based SSRF if not restricted.",
     "Disable XML-RPC if unused, or restrict it by IP and enforce rate limits.",
     _xmlrpc_marker, CONFIDENCE_FIRM),
    ("/system/console/bundles", "medium", "AEM/Felix system console exposed",
     "The Apache Felix web console can expose OSGi bundles, configuration, "
     "and sometimes credentials or installer access.",
     "Require authentication for /system/console and restrict it to trusted "
     "networks.",
     _all_marker(b"Apache Felix", b"bundles"), CONFIDENCE_FIRM),
    ("/crx/de/index.jsp", "medium", "AEM CRXDE Lite exposed",
     "CRXDE Lite provides repository read/write access and is not meant to be "
     "public in production.",
     "Disable CRXDE Lite or require authentication and network restriction.",
     _marker(b"CRXDE Lite"), CONFIDENCE_FIRM),
    ("/actuator/mappings", "medium", "Spring Boot actuator mappings exposed",
     "The mappings endpoint lists every route with its handler, which maps the "
     "application for an attacker and can reveal internal admin paths.",
     "Require authentication for actuator endpoints and expose only health/info.",
     _json_marker(b'"mappings"'), CONFIDENCE_CONFIRMED),
    ("/actuator/configprops", "medium",
     "Spring Boot actuator configuration properties exposed",
     "Configuration properties can include datasource URLs, credentials, and "
     "internal service addresses.",
     "Require authentication for actuator endpoints and remove secrets from "
     "configuration.",
     _json_marker(b'"contexts"', b'"properties"'), CONFIDENCE_CONFIRMED),
    ("/actuator/jolokia", "low", "Spring Boot Jolokia endpoint exposed",
     "The Jolokia bridge exposes JMX over HTTP, including MBean reads and "
     "sometimes operations.",
     "Disable Jolokia or require authentication and network restriction.",
     _marker(b'"jolokia"'), CONFIDENCE_FIRM),
    ("/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D", "low",
     "GraphQL introspection enabled",
     "The endpoint answers an introspection query, so the full schema "
     "(types, fields, and arguments) can be downloaded to target the API.",
     "Disable introspection in production and require authorization on the "
     "GraphQL endpoint.",
     _json_marker(b'"queryType"'), CONFIDENCE_FIRM),
    ("/wp-json/wp/v2/users", "low",
     "WordPress user enumeration via REST API",
     "The REST users endpoint lists account slugs, which feeds credential "
     "stuffing and social engineering.",
     "Restrict the users endpoint to authenticated users or disable anonymous "
     "REST user listing.",
     _json_array_marker(b'"slug"', b'"id"'), CONFIDENCE_FIRM),
    ("/?rest_route=/wp/v2/users", "low",
     "WordPress user enumeration via REST API",
     "The REST users endpoint lists account slugs, which feeds credential "
     "stuffing and social engineering.",
     "Restrict the users endpoint to authenticated users or disable anonymous "
     "REST user listing.",
     _json_array_marker(b'"slug"', b'"id"'), CONFIDENCE_FIRM),
    ("/.svn/wc.db", "medium", "Exposed SVN working copy",
     "A Subversion working-copy database is served, which can reconstruct "
     "source and credentials from repository history.",
     "Deny /.svn/ and remove working copies from the docroot.",
     _marker(b"SQLite format 3"), CONFIDENCE_CONFIRMED),
    ("/.hg/requires", "medium", "Exposed Mercurial metadata",
     "Mercurial repository metadata is readable, which can leak source and "
     "history.",
     "Deny /.hg/ and remove repositories from the docroot.",
     _marker(b"revlogv1"), CONFIDENCE_CONFIRMED),
    ("/_profiler", "medium", "Symfony profiler exposed",
     "The Symfony profiler records full requests and responses, including "
     "headers, cookies, SQL, and configuration values.",
     "Disable the profiler in production (web_profiler settings) and require "
     "authentication for /_profiler.",
     _all_marker(b"Symfony", b"Profiler"), CONFIDENCE_FIRM),
    ("/telescope", "medium", "Laravel Telescope exposed",
     "Telescope stores requests, queries, exceptions, and mail, which exposes "
     "session data and credentials.",
     "Restrict Telescope to local environments or gate it behind authorization.",
     _all_marker(b"Laravel", b"Telescope"), CONFIDENCE_FIRM),
    ("/elmah.axd", "medium", "ELMAH error log exposed",
     "The ELMAH error log lists exceptions with stack traces, request data, "
     "and sometimes server paths.",
     "Deny remote access to elmah.axd or require authentication.",
     _marker(b"Error Log for", b"elmah"), CONFIDENCE_FIRM),
    ("/trace.axd", "low", "ASP.NET trace log exposed",
     "The ASP.NET trace viewer lists recent requests with headers and session "
     "identifiers.",
     "Disable tracing in production and deny remote access to trace.axd.",
     _marker(b"Application Trace"), CONFIDENCE_FIRM),
    ("/server-info", "low", "Apache server-info exposed",
     "mod_info publishes the loaded modules and configuration directives.",
     "Restrict /server-info to localhost or remove mod_info.",
     _marker(b"Apache Server Information"), CONFIDENCE_FIRM),
    ("/crossdomain.xml", "low", "Permissive crossdomain.xml",
     "The Flash policy grants wildcard access, which lets any origin read "
     "authenticated responses from this host.",
     "Restrict allow-access-from to the origins that need it, or remove the "
     "policy.",
     _wildcard_xml_marker(b"<cross-domain-policy"), CONFIDENCE_FIRM),
    ("/clientaccesspolicy.xml", "low", "Permissive clientaccesspolicy.xml",
     "The Silverlight policy grants wildcard access to this host.",
     "Restrict the policy to trusted origins or remove it.",
     _wildcard_xml_marker(b"<access-policy"), CONFIDENCE_FIRM),
    ("/id_dsa", "critical", "Private DSA key exposed",
     "A private key was served over HTTP.",
     "Delete the file from the docroot, rotate the key, and audit for misuse.",
     _marker(b"BEGIN DSA PRIVATE KEY"), CONFIDENCE_CONFIRMED),
    ("/wp-content/debug.log", "low", "Debug log exposed",
     "A WordPress debug log is readable and can contain paths, plugin errors, "
     "and personal data.",
     "Disable WP_DEBUG_LOG in production or deny access to the log file.",
     _marker(b"PHP Fatal error", b"PHP Warning", b"PHP Notice"),
     CONFIDENCE_CONFIRMED),
]


# Passive fingerprint only: names that a CDN/WAF puts on ordinary responses.
# Nothing is sent to provoke a block page.
WAF_SIGNATURES = (
    ("Cloudflare", ("cf-ray", "cf-cache-status"), ()),
    ("Akamai", ("akamai-grn", "x-akamai-transformed",
                "x-akamai-request-id"), ()),
    ("Imperva/Incapsula", ("x-iinfo",), ("incap_ses", "visid_incap")),
    ("Sucuri", ("x-sucuri-id", "x-sucuri-cache"), ()),
    ("AWS CloudFront", ("x-amz-cf-id", "x-amz-cf-pop"), ()),
    ("Fastly", ("x-fastly-request-id", "x-served-by"), ()),
    ("Azure Front Door", ("x-azure-ref",), ()),
    ("F5 BIG-IP", ("x-wa-info",), ("bigipserver",)),
    ("Barracuda", (), ("barra_counter_session",)),
    ("ModSecurity", ("x-mod-security",), ()),
)


def _cookie_names(headers: dict[str, str]) -> set[str]:
    names: set[str] = set()
    raw = headers.get("set-cookie") or ""
    for chunk in raw.split(","):
        name = chunk.split("=", 1)[0].strip().lower()
        if name and " " not in name:
            names.add(name)
    return names


def waf_fingerprint(probes) -> dict:
    hits: dict[str, dict] = {}
    checked = 0
    for probe in probes:
        result = getattr(probe, "result", None)
        if not result or not getattr(probe, "live", False):
            continue
        checked += 1
        headers = {str(key).lower(): str(value)
                   for key, value in (result.headers or {}).items()}
        cookies = _cookie_names(headers)
        server = headers.get("server", "").lower()
        for provider, header_names, cookie_names in WAF_SIGNATURES:
            evidence = next(
                (name for name in header_names if name in headers), None)
            if evidence is None:
                evidence = next(
                    (name for name in cookie_names if name in cookies), None)
            if evidence is None and provider == "Cloudflare" \
                    and "cloudflare" in server:
                evidence = "server: cloudflare"
            if evidence is None and provider == "Sucuri" \
                    and "sucuri" in server:
                evidence = "server: sucuri"
            if evidence is None:
                continue
            entry = hits.setdefault(
                provider, {"provider": provider, "evidence": evidence,
                           "hosts": []})
            if probe.host not in entry["hosts"]:
                entry["hosts"].append(probe.host)
    providers = sorted(hits.values(),
                       key=lambda item: (-len(item["hosts"]), item["provider"]))
    return {
        "checked_hosts": checked,
        "providers": providers,
        "note": (
            "Passive header/CDN fingerprint from ordinary responses; it "
            "identifies infrastructure around the target, not a vulnerability."
        ),
    }


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def _join(origin: str, path: str) -> str:
    return origin.rstrip("/") + "/" + path.lstrip("/")


def _parse_expiry(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def _redacted_cookie(raw: str) -> str:
    segments = [part.strip() for part in raw.split(";") if part.strip()]
    if not segments:
        return "cookie=<redacted>"
    name = segments[0].split("=", 1)[0].strip() or "cookie"
    return "; ".join([f"{name}=<redacted>"] + segments[1:])


def _cookie_fingerprint(raw: str) -> str:
    segments = [part.strip() for part in raw.split(";") if part.strip()]
    if not segments or "=" not in segments[0]:
        return "value not captured"
    value = segments[0].split("=", 1)[1].strip()
    if not value:
        return "empty value"
    digest = sha_prefix(value.encode("utf-8", "replace"))
    return f"value length {len(value)}, sha256:{digest}"


def _csp_weak(csp: str) -> str:
    lowered = csp.lower()
    if not lowered.strip():
        return ""
    reasons = []
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        reasons.append("allows 'unsafe-inline'/'unsafe-eval'")
    if re.search(r"(?:^|[;\s])script-src[^;]*\*", lowered) or \
            re.search(r"default-src[^;]*\*", lowered):
        reasons.append("allows wildcard script sources")
    return "; ".join(reasons)


def _header_gaps(result: HttpResult, csp: str = "") -> list[str]:
    headers = result.headers
    secure = result.final_url.startswith("https://")
    gaps: list[str] = []
    if secure and "strict-transport-security" not in headers:
        gaps.append("Strict-Transport-Security")
    if not (headers.get("content-security-policy") or
            headers.get("content-security-policy-report-only")):
        gaps.append("Content-Security-Policy")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        gaps.append("X-Content-Type-Options")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        gaps.append("X-Frame-Options")
    if "referrer-policy" not in headers:
        gaps.append("Referrer-Policy")
    if "permissions-policy" not in headers:
        gaps.append("Permissions-Policy")
    return gaps


def _verbatim_headers(result: HttpResult, redact_cookies: bool = False) -> list[str]:
    lines = [f"HTTP {result.status if result.status is not None else 'no response'}"]
    for name in sorted(result.headers):
        if name == "set-cookie":
            continue
        lines.append(f"{name}: {result.headers[name]}")
    for cookie in result.set_cookies:
        lines.append(
            "set-cookie: " + (_redacted_cookie(cookie) if redact_cookies else cookie)
        )
    return lines


class Checker:
    def __init__(
        self,
        client: HttpClient,
        probes: list[Probe],
        urls: list[str],
        auth_a: dict[str, str] | None = None,
        auth_b: dict[str, str] | None = None,
        auth_host: str | None = None,
        max_file_hosts: int = 8,
        bypass: bool = False,
        bypass_max_paths: int = 4,
        bypass_max_variants: int = 10,
        bypass_max_requests: int = 200,
        evidence_dir: Path | None = None,
        evidence_bytes: int = DEFAULT_EVIDENCE_BYTES,
        robots: dict[str, list[str]] | None = None,
        robots_paths: bool = False,
        secrets: bool = True,
        bundles: bool = True,
        injection: bool = True,
        backdoors: bool = True,
        injection_requests: int = 180,
        backdoor_requests: int = 80,
    ) -> None:
        self.client = client
        self.probes = probes
        self.urls = list(dict.fromkeys(urls))
        self.auth_a = auth_a or {}
        self.auth_b = auth_b or {}
        self.auth_host = (auth_host or "").lower()
        self.max_file_hosts = max_file_hosts
        self.bypass = bypass
        self.bypass_max_paths = max(0, bypass_max_paths)
        self.bypass_max_variants = max(1, min(16, bypass_max_variants))
        self.bypass_max_requests = max(0, bypass_max_requests)
        self.evidence_limit = normalize_evidence_limit(evidence_bytes)
        self.evidence = EvidenceStore(evidence_dir, limit=self.evidence_limit)
        self.bypass_attempts: list[dict] = []
        self._bypass_paths: dict[str, int] = {}
        self._bypass_requests = 0
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str, str]] = set()
        self._baselines: dict[
            tuple[str, int], tuple[int, bytes, int] | None] = {}
        self.header_matrix: list[dict] = []
        self.security_txt: dict[str, dict] = {}
        self._header_obs: list[dict] = []
        self._cookie_obs: dict[str, dict[str, dict]] = {}
        self.robots = robots or {}
        self.robots_paths = robots_paths
        self.scan_secrets = secrets
        self.scan_bundles = bundles
        self.scan_injection = injection
        self.scan_backdoors = backdoors
        self.injection_requests = max(0, injection_requests)
        self.backdoor_requests = max(0, backdoor_requests)
        self.injection_meta: dict = {}
        self.backdoor_meta: dict = {}
        self.injection_count = 0
        self.backdoor_count = 0
        self.bundle_reports: list = []
        self.bundle_meta: dict = {}
        self.waf_meta: dict = {}
        self._crawled: dict[str, HttpResult] = {}
        self._client_sources: dict[str, HttpResult] = {}
        self.secret_files = 0
        self.secret_hits: list[dict] = []
        self.source_maps: list[dict] = []
        self.url_token_count = 0

    def run(self) -> list[Finding]:
        for probe in self.probes:
            if not probe.live or not probe.result or not probe.url:
                continue
            self._record_headers(probe.result)
            self._record_cookies(probe.result)
            if probe.url.startswith("http://"):
                self._check_plaintext_tokens(
                    probe.host, probe.result.final_url, probe.result)
            self._check_tls(probe)
            self._check_listing(probe)
            self._check_cors(probe)
            self._check_https_enforced(probe)

        for index, probe in enumerate(
            [item for item in self.probes if item.live and item.url]
        ):
            if index >= self.max_file_hosts:
                break
            self._check_files(probe)
            self._check_security_txt(probe)

        self._finalize_headers()
        self._finalize_cookies()
        self._check_crawled_listings()
        if self.scan_secrets:
            self._check_client_secrets()
        if self.scan_bundles:
            self._check_bundles()
        self._check_url_tokens()
        if self.robots_paths:
            self._check_robots_paths()
        self._check_redirects()
        self._check_idor()
        if self.scan_backdoors:
            self._check_backdoors()
        if self.scan_injection:
            self._check_injection()
        self.waf_meta = waf_fingerprint(self.probes)
        return self.findings

    def _add(self, finding: Finding) -> None:
        key = finding.key()
        if key in self._seen:
            return
        self._seen.add(key)
        if not finding.poc:
            finding.poc = poc_for_finding(
                finding,
                has_auth_a=bool(self.auth_a),
                has_auth_b=bool(self.auth_b),
            )
        self.findings.append(finding)

    def _stamp(
        self,
        finding: Finding,
        *,
        reproductions: int = 1,
        stable: bool | None = None,
        result: HttpResult | None = None,
        text: str | None = None,
    ) -> Finding:
        """Record how often a result reproduced and whether a decoy was seen."""
        finding.reproductions = max(0, int(reproductions))
        finding.stable = stable
        self._note_decoy(finding, result, text=text)
        return finding

    def _note_decoy(
        self,
        finding: Finding,
        result: HttpResult | None,
        *,
        text: str | None = None,
    ) -> None:
        if result is not None and text is None:
            text = result.text
        found = decoy.markers(text or "")
        if not found:
            return
        finding.decoy_suspected = True
        finding.decoy_reason = "; ".join(found)
        if finding.confidence == CONFIDENCE_CONFIRMED:
            finding.confidence = CONFIDENCE_FIRM
        note = (
            "Decoy/canary marker in the response ("
            + "; ".join(found)
            + "); treat this as a planted or test artifact until proven "
              "otherwise."
        )
        finding.verification = (
            f"{finding.verification} | {note}"
            if finding.verification else note
        )

    def _record_headers(self, result: HttpResult | None) -> None:
        if not result or result.status is None or result.status >= 400:
            return
        url = result.final_url
        if not url:
            return
        if any(entry["url"] == url for entry in self.header_matrix):
            return
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return
        headers = result.headers
        policy = headers.get("content-security-policy", "")
        report_only = headers.get("content-security-policy-report-only", "")
        csp = policy or report_only
        gaps = _header_gaps(result, csp)
        weak = _csp_weak(csp)
        if report_only and not policy:
            weak = (weak + "; " if weak else "") + "report-only (not enforced)"
        content_type = headers.get("content-type", "").lower()
        body_head = result.text[:512].lstrip().lower() if result.text else ""
        html = "html" in content_type or "<!doctype html" in body_head or \
            "<html" in body_head
        powered_by = headers.get("x-powered-by", "")
        present = {
            "Strict-Transport-Security": "strict-transport-security" in headers,
            "Content-Security-Policy": bool(csp),
            "X-Content-Type-Options":
                headers.get("x-content-type-options", "").lower() == "nosniff",
            "X-Frame-Options":
                "x-frame-options" in headers or "frame-ancestors" in csp,
            "Referrer-Policy": "referrer-policy" in headers,
            "Permissions-Policy": "permissions-policy" in headers,
        }
        self.header_matrix.append({
            "url": url,
            "scheme": parsed.scheme,
            "host": host,
            "status": result.status,
            "html": html,
            "present": present,
            "missing": gaps,
            "csp": csp[:240],
            "csp_weak": weak,
            "powered_by": powered_by[:120],
        })
        self._header_obs.append({
            "url": url,
            "scheme": parsed.scheme,
            "host": host,
            "status": result.status,
            "html": html,
            "gaps": gaps,
            "csp_weak": weak,
            "result": result,
        })

    def _header_matrix_lines(self, host: str) -> list[str]:
        lines = ["Header coverage (" + ", ".join(HEADER_ORDER) + "):"]
        for entry in self.header_matrix:
            if entry["host"] != host:
                continue
            marks = ", ".join(
                f"{label}={'present' if entry['present'].get(label) else 'absent'}"
                for label in HEADER_ORDER
            )
            lines.append(f"- {entry['url']} (HTTP {entry['status']}): {marks}")
        return lines

    def _finalize_headers(self) -> None:
        by_host: dict[str, list[dict]] = {}
        for observation in self._header_obs:
            if observation["html"] and observation["status"] < 400:
                by_host.setdefault(observation["host"], []).append(observation)
        for host, observations in by_host.items():
            sitewide: dict[str, list[str]] = {}
            partial: dict[str, list[str]] = {}
            for label in HEADER_ORDER:
                applicable = [
                    item for item in observations
                    if label != "Strict-Transport-Security"
                    or item["scheme"] == "https"
                ]
                if not applicable:
                    continue
                missing = [item for item in applicable if label in item["gaps"]]
                if not missing:
                    continue
                if len(missing) == len(applicable):
                    sitewide[label] = [item["url"] for item in applicable]
                else:
                    partial[label] = [item["url"] for item in missing]
            representative = next(
                (item for item in observations if item["scheme"] == "https"),
                observations[0],
            )
            matrix = self._header_matrix_lines(host)
            if sitewide:
                labels = list(sitewide)
                analysis = "\n".join(
                    ["Missing on every evaluated endpoint: " + ", ".join(labels)]
                    + matrix + ["", "Response headers (verbatim):"]
                    + _verbatim_headers(representative["result"])
                )
                finding = Finding(
                    title="Security headers not fully configured",
                    severity="low",
                    category="headers",
                    host=host,
                    url=representative["url"],
                    description=(
                        f"{', '.join(labels)} were absent on all "
                        f"{len(observations)} HTML endpoint(s) evaluated for this host, "
                        "so the gap is site-wide rather than endpoint-specific."
                    ),
                    remediation="Add HSTS on HTTPS, a CSP, X-Content-Type-Options: "
                                "nosniff, a frame policy, Referrer-Policy, and "
                                "Permissions-Policy at the edge/server.",
                    confidence=CONFIDENCE_CONFIRMED,
                    verified=True,
                    verification=(
                        f"response headers observed directly on "
                        f"{len(observations)} endpoint(s) for {host}"
                    ),
                )
                self._stamp(
                    finding,
                    reproductions=len(observations),
                    stable=True,
                    result=representative["result"],
                )
                self.evidence.attach(
                    finding, representative["result"],
                    f"site-wide header gaps {host}", intro=analysis,
                )
                self._add(finding)
            if partial and not sitewide:
                lines = [
                    f"{url}: missing {label}"
                    for label, urls in partial.items() for url in urls
                ]
                finding = Finding(
                    title="Security headers applied inconsistently across endpoints",
                    severity="info",
                    category="headers",
                    host=host,
                    url=representative["url"],
                    description=(
                        "Some endpoints set defensive headers that others on the same "
                        "host do not. Coverage differences are not vulnerabilities by "
                        "themselves; verify which responses serve sensitive content."
                    ),
                    remediation="Apply the same security header policy to every HTML "
                                "response, including alternate schemes and error pages.",
                    evidence="\n".join(
                        ["Headers present on some endpoints but absent on others:"]
                        + lines + [""] + matrix
                    ),
                    confidence=CONFIDENCE_CONFIRMED,
                    verified=True,
                    verification=(
                        f"headers compared across {len(observations)} endpoint(s)"
                    ),
                )
                self._stamp(
                    finding,
                    reproductions=len(observations),
                    stable=True,
                )
                self._add(finding)
            weak = sorted({
                item["csp_weak"] for item in observations if item["csp_weak"]
            })
            if weak:
                urls = [
                    item["url"] for item in observations if item["csp_weak"]
                ]
                self._add(self._stamp(Finding(
                    title="Content-Security-Policy present but weak",
                    severity="info",
                    category="headers",
                    host=host,
                    url=urls[0],
                    description="A CSP is published but its directives weaken the "
                                "protection it is meant to provide.",
                    remediation="Remove 'unsafe-inline'/'unsafe-eval' and wildcard "
                                "script sources, or enforce a nonce/hash-based policy.",
                    evidence="\n".join(
                        [f"{item['url']}: {item['csp_weak']}"
                         for item in observations if item["csp_weak"]]
                        + [""] + matrix
                    ),
                    confidence=CONFIDENCE_CONFIRMED,
                    verified=True,
                    verification="CSP directive values observed directly",
                ), reproductions=len(observations), stable=True))

    def _record_cookies(self, result: HttpResult | None) -> None:
        if not result or not result.set_cookies:
            return
        host = (urlsplit(result.final_url).hostname or "").lower()
        if not host:
            return
        https = result.final_url.startswith("https://")
        for raw, view in zip(result.set_cookies, parse_cookies(result.set_cookies)):
            bucket = self._cookie_obs.setdefault(host, {})
            record = bucket.get(view.name)
            if record is None:
                record = {
                    "view": view, "urls": [], "https_missing": set(),
                    "http_missing": set(), "result": result, "raw": raw,
                    "http_urls": [],
                }
                bucket[view.name] = record
            if result.final_url not in record["urls"]:
                record["urls"].append(result.final_url)
            if https:
                record["https_missing"] |= set(
                    view.missing(secure_required=True))
                if record["result"] is None or \
                        record["result"].final_url.startswith("http://"):
                    record["result"] = result
                    record["raw"] = raw
            else:
                record["http_missing"] |= set(
                    view.missing(secure_required=False))
                record["http_urls"].append(result.final_url)

    def _cookie_evidence(self, record: dict) -> list[str]:
        view: CookieView = record["view"]
        return [
            cookie_summary(view),
            "Observed at: " + ", ".join(sorted(set(record["urls"]))),
            "Set-Cookie (value redacted in text; raw capture stored as evidence): "
            + _redacted_cookie(record["raw"]),
            "Value fingerprint: " + _cookie_fingerprint(record["raw"]),
            "Policy: token values are never decoded for authorization, verified, "
            "or replayed; JWT claims, when present, are decoded offline only to "
            "classify the token.",
        ]

    def _finalize_cookies(self) -> None:
        for host, bucket in self._cookie_obs.items():
            anonymous: list[str] = []
            anonymous_result: HttpResult | None = None
            for name in sorted(bucket):
                record = bucket[name]
                view: CookieView = record["view"]
                missing = sorted(record["https_missing"] | record["http_missing"])
                if not missing:
                    continue
                if not view.sensitive:
                    anonymous.append(f"{name}: missing {', '.join(missing)}")
                    anonymous_result = anonymous_result or record["result"]
                    continue
                severity = "medium" if "HttpOnly" in missing else "low"
                analysis = "\n".join(
                    self._cookie_evidence(record)
                    + ["", "Response headers (verbatim):",
                       "\n".join(_verbatim_headers(record["result"]))]
                )
                finding = Finding(
                    title=f"Sensitive cookie {name} missing security attributes",
                    severity=severity,
                    category="cookies",
                    host=host,
                    url=record["urls"][0],
                    description=(
                        f"The cookie '{name}' is classified as sensitive "
                        f"({view.reason}) but omits {', '.join(missing)}. "
                        "Missing HttpOnly keeps it readable by scripts; missing "
                        "SameSite widens CSRF exposure; missing Secure allows "
                        "cleartext transmission."
                    ),
                    remediation="Set Secure, HttpOnly, and SameSite=Lax/Strict on "
                                "session and authentication cookies.",
                    confidence=CONFIDENCE_FIRM,
                    verified=True,
                    verification="Set-Cookie attributes observed directly",
                )
                self._stamp(
                    finding,
                    reproductions=1,
                    stable=True,
                    result=record["result"],
                )
                if record["result"] is not None:
                    self.evidence.attach(
                        finding, record["result"],
                        f"cookie attributes {name}", intro=analysis)
                self._add(finding)
            if anonymous:
                analysis = "\n".join(
                    anonymous
                    + [""]
                    + ([
                        "Set-Cookie (values redacted):",
                        "\n".join(
                            _redacted_cookie(bucket[name]["raw"])
                            for name in sorted(bucket)
                            if not bucket[name]["view"].sensitive
                        ),
                    ] if anonymous_result else [])
                )
                finding = Finding(
                    title="Anonymous cookie missing security attributes",
                    severity="info",
                    category="cookies",
                    host=host,
                    url=anonymous_result.final_url if anonymous_result else host,
                    description=(
                        "Cookies classified as anonymous, public, or preference data "
                        "omit Secure/HttpOnly/SameSite. This is usually informational"
                        "; verify they never carry authenticated state."
                    ),
                    remediation="Mark anonymous/preference cookies HttpOnly and "
                                "SameSite=Lax where the application permits it.",
                    confidence=CONFIDENCE_FIRM,
                    verified=True,
                    verification="Set-Cookie attributes observed directly",
                )
                self._stamp(
                    finding,
                    reproductions=1,
                    stable=True,
                    result=anonymous_result,
                )
                if anonymous_result is not None:
                    self.evidence.attach(
                        finding, anonymous_result, f"anonymous cookies {host}",
                        intro=analysis)
                self._add(finding)

        for host, bucket in self._cookie_obs.items():
            for name in sorted(bucket):
                record = bucket[name]
                view: CookieView = record["view"]
                if not view.sensitive or not view.domain.startswith("."):
                    continue
                parent = view.domain.lstrip(".").lower()
                if not parent or host == parent or \
                        not host.endswith("." + parent):
                    continue
                analysis = "\n".join(
                    self._cookie_evidence(record)
                    + ["", "Impact: the cookie is sent to every host under "
                       f"{parent}, so a weaker sibling host can read it."]
                )
                finding = Finding(
                    title=f"Sensitive cookie {name} scoped to parent domain",
                    severity="info",
                    category="cookies",
                    host=host,
                    url=record["urls"][0],
                    description=(
                        f"The sensitive cookie '{name}' sets Domain={view.domain}, "
                        f"so it is sent to all subdomains of {parent}. A single "
                        "compromised sibling host can then collect it. Informational "
                        "unless a weaker sibling exists."
                    ),
                    remediation=f"Narrow the cookie Domain to {host} or use the "
                                "__Host- prefix where the framework permits it.",
                    confidence=CONFIDENCE_FIRM,
                    verified=True,
                    verification="Set-Cookie Domain attribute observed directly",
                )
                self._stamp(
                    finding,
                    reproductions=1,
                    stable=True,
                    result=record["result"],
                )
                if record["result"] is not None:
                    self.evidence.attach(
                        finding, record["result"],
                        f"cookie domain {name}", intro=analysis)
                self._add(finding)

    def _check_tls(self, probe: Probe) -> None:
        result = probe.result
        if not result or not result.tls:
            return
        tls = result.tls
        url = result.final_url
        issues: list[str] = []
        severity = None

        if tls.verify_error:
            issues.append(f"Certificate validation: {tls.verify_error}")
            severity = "medium"
        if tls.protocol in ("TLSv1", "TLSv1.1"):
            issues.append(f"Negotiated legacy protocol {tls.protocol}")
            severity = severity or "medium"
        if tls.not_after:
            try:
                expires = ssl.cert_time_to_seconds(tls.not_after)
                days = (expires - time.time()) / 86400.0
                if days < 0:
                    issues.append(f"Certificate expired {abs(days):.0f} days ago")
                    severity = "medium"
                elif days < 14:
                    issues.append(f"Certificate expires in {days:.0f} days")
                    severity = severity or "low"
            except (ValueError, OverflowError):
                pass
        if not issues:
            return
        self._add(self._stamp(Finding(
            title="TLS configuration issue",
            severity=severity or "low",
            category="tls",
            host=probe.host,
            url=url,
            description="The TLS endpoint has certificate or protocol weaknesses.",
            remediation="Use a valid certificate, renew before expiry, and require "
                        "TLS 1.2 or newer.",
            evidence="\n".join(issues + [
                "",
                "TLS metadata (verbatim):",
                f"Protocol: {tls.protocol or '(none)'}",
                f"Cipher: {tls.cipher or '(none)'}",
                f"Subject: {tls.subject or '(none)'}",
                f"Issuer: {tls.issuer or '(none)'}",
                f"Not after: {tls.not_after or '(unknown)'}",
                f"SAN: {', '.join(tls.san) or '(none)'}",
                f"Verify error: {tls.verify_error or '(none)'}",
            ]),
            confidence=CONFIDENCE_FIRM,
            verified=True,
            verification="TLS handshake performed and certificate decoded directly",
        ), reproductions=1))

    def _check_listing(self, probe: Probe) -> None:
        result = probe.result
        if not result or not result.text:
            return
        self._listing_finding(
            probe.host, result.final_url, result.text, result)

    def _check_crawled_listings(self) -> None:
        checked = 0
        for url in self.urls:
            if checked >= 6:
                break
            parsed = urlsplit(url)
            if not parsed.path.endswith("/") or not self._in_client_scope(url):
                continue
            if parsed.path == "/":
                continue
            checked += 1
            result = self.client.get(url, follow=False, read_limit=65536)
            if not result.ok or result.status != 200 or not result.text:
                continue
            self._crawled[url] = result
            self._record_headers(result)
            self._listing_finding(
                (parsed.hostname or ""), url, result.text, result)

    def _listing_finding(self, host: str, url: str, text: str,
                         result: HttpResult | None = None) -> None:
        lowered = text[:200000].lower()
        if "index of /" not in lowered and "directory listing for" not in lowered:
            return
        if result is not None and self._is_catch_all(
                _origin(url), urlsplit(url).path or "/", result):
            return
        finding = Finding(
            title="Directory listing enabled",
            severity="low",
            category="exposure",
            host=host,
            url=url,
            description="The server renders a directory index, exposing file names.",
            remediation="Disable autoindex/directory listing.",
            evidence="Response contains a directory index page.",
            confidence=CONFIDENCE_CONFIRMED,
            verified=True,
            verification="directory index signature matched in the response body",
        )
        self._stamp(finding, reproductions=1, stable=True, text=text)
        if result is not None:
            if self.evidence.enabled:
                full = self.client.get(
                    url, follow=False, read_limit=self.evidence_limit,
                    max_bytes=self.evidence_limit,
                )
                if full.ok and full.status == result.status:
                    result = full
            self.evidence.attach(finding, result, f"directory listing {url}")
        self._add(finding)

    def _check_cors(self, probe: Probe) -> None:
        if not probe.url:
            return
        origin = _origin(probe.url)
        marker = "https://webwarden.invalid"
        second_marker = "https://webwarden-verify.invalid"
        result = self.client.get(origin + "/", headers={"Origin": marker}, follow=False)
        reflected = False
        if result.ok:
            reflected = self._cors_reflection(
                probe, origin, marker, second_marker, result)
        if reflected:
            return
        null_result = self.client.get(
            origin + "/", headers={"Origin": "null"}, follow=False)
        if null_result.ok:
            null_allowed = null_result.headers.get(
                "access-control-allow-origin", "").strip()
            null_credentials = null_result.headers.get(
                "access-control-allow-credentials", "").lower() == "true"
            if null_allowed == "null":
                second_null = self.client.get(
                    origin + "/", headers={"Origin": "null"}, follow=False)
                reproduced = bool(
                    second_null.ok
                    and second_null.headers.get(
                        "access-control-allow-origin", "").strip() == "null"
                )
                finding = Finding(
                    title="CORS allows the null origin",
                    severity="high" if null_credentials else "medium",
                    category="cors",
                    host=probe.host,
                    url=origin + "/",
                    description=(
                        "The server trusts the 'null' Origin, which sandboxed "
                        "iframes, data: URLs, and some redirect chains can send. "
                        + ("Combined with credentials, this can expose "
                           "authenticated responses. " if null_credentials else "")
                        + "Verify with a non-credentialed cross-origin read."
                    ),
                    remediation="Never whitelist the 'null' origin; match exact "
                                "trusted HTTPS origins instead.",
                    evidence=(
                        "Origin: null\n"
                        f"Access-Control-Allow-Origin: {null_allowed}\n"
                        "Access-Control-Allow-Credentials: "
                        f"{'true' if null_credentials else '(absent)'}"
                        "\n\nResponse headers (verbatim):\n"
                        + "\n".join(_verbatim_headers(null_result))
                    ),
                    confidence=CONFIDENCE_CONFIRMED if reproduced else CONFIDENCE_FIRM,
                    verified=reproduced,
                    verification=(
                        "null Origin reflection reproduced on two requests"
                        if reproduced else
                        "null Origin reflected once; a second request did not "
                        "repeat it"
                    ),
                )
                self._stamp(
                    finding,
                    reproductions=2 if reproduced else 1,
                    stable=reproduced,
                    result=null_result,
                )
                self._add(finding)

    def _cors_reflection(
        self,
        probe: Probe,
        origin: str,
        marker: str,
        second_marker: str,
        result: HttpResult,
    ) -> bool:
        allowed = result.headers.get("access-control-allow-origin", "")
        credentials = result.headers.get("access-control-allow-credentials", "").lower()
        verified = False
        verification = ""
        reproductions = 1
        stable: bool | None = True
        if allowed == marker:
            if credentials == "true":
                severity, title = "high", "CORS allows credentialed requests from any origin"
            else:
                severity, title = "low", "CORS reflects arbitrary origins"
            second = self.client.get(
                origin + "/", headers={"Origin": second_marker}, follow=False
            )
            reproduced = second.ok and \
                second.headers.get("access-control-allow-origin", "") == second_marker
            verified = bool(reproduced)
            reproductions = 2 if reproduced else 1
            stable = reproduced
            verification = (
                "arbitrary Origin reflection reproduced with two distinct origins"
                if reproduced else
                "reflected once; a second, different Origin was not reflected"
            )
        elif allowed == "*" and credentials == "true":
            severity, title = "medium", "CORS wildcard combined with credentials"
            verified = True
            verification = "wildcard and credentials flags observed directly"
        else:
            return False
        finding = Finding(
            title=title,
            severity=severity,
            category="cors",
            host=probe.host,
            url=origin + "/",
            description="The server reflects an attacker-controlled Origin header. "
                        "If credentials are allowed, cross-origin reads become possible.",
            remediation="Allow only trusted origins and avoid reflecting arbitrary values.",
            evidence=f"Origin: {marker}\n"
                     f"Access-Control-Allow-Origin: {allowed}\n"
                     f"Access-Control-Allow-Credentials: {credentials or '(absent)'}"
                     "\n\nResponse headers (verbatim):\n"
                     + "\n".join(_verbatim_headers(result)),
            confidence=CONFIDENCE_CONFIRMED if severity == "high" else CONFIDENCE_FIRM,
            verified=verified,
            verification=verification,
        )
        self._stamp(
            finding,
            reproductions=reproductions,
            stable=stable,
            result=result,
        )
        self._add(finding)
        return True

    def _check_https_enforced(self, probe: Probe) -> None:
        if not probe.url or not probe.url.startswith("https://"):
            return
        parsed = urlsplit(probe.url)
        plain = f"http://{parsed.netloc}/"
        result = self.client.get(plain, follow=False)
        if not result.ok or result.status is None:
            return
        if 200 <= result.status < 300:
            self._record_headers(result)
            confirmation = self.client.get(plain, follow=False)
            reproduced = bool(
                confirmation.ok and confirmation.status is not None
                and 200 <= confirmation.status < 300
            )
            finding = Finding(
                title="HTTPS not enforced",
                severity="low",
                category="tls",
                host=probe.host,
                url=plain,
                description="The same content is served over plain HTTP without a "
                            "redirect, allowing downgrade and on-path interception. "
                            "Severity depends on what the cleartext response exposes.",
                remediation="Redirect all HTTP requests to HTTPS and enable HSTS.",
                evidence=(
                    f"HTTP status {result.status} without a redirect\n\n"
                    + "\n".join(_verbatim_headers(result))
                ),
                confidence=CONFIDENCE_CONFIRMED,
                verified=True,
                verification=(
                    f"HTTP {result.status} observed directly without a redirect"
                    + ("; reproduced on a second request" if reproduced else
                       "; second request did not reproduce the cleartext response")
                ),
            )
            self._stamp(
                finding,
                reproductions=2 if reproduced else 1,
                stable=reproduced,
                result=result,
            )
            self.evidence.attach(finding, result, f"plaintext HTTP root {probe.host}")
            self._add(finding)
            self._check_plaintext_tokens(probe.host, plain, result)
            for sample in self._plaintext_samples(probe, limit=2):
                sample_result = self.client.get(
                    sample, follow=False, read_limit=65536)
                if not sample_result.ok or sample_result.status is None:
                    continue
                if not 200 <= sample_result.status < 300:
                    continue
                self._record_headers(sample_result)
                self._check_plaintext_tokens(probe.host, sample, sample_result)

    def _plaintext_samples(self, probe: Probe, limit: int = 2) -> list[str]:
        host = (urlsplit(probe.url or "").hostname or "").lower()
        samples: list[str] = []
        for url in self.urls:
            parsed = urlsplit(url)
            if parsed.scheme != "https" or \
                    (parsed.hostname or "").lower() != host:
                continue
            if parsed.path in ("", "/"):
                continue
            sample = urlunsplit(("http", parsed.netloc, parsed.path,
                                 parsed.query, ""))
            if sample not in samples:
                samples.append(sample)
            if len(samples) >= limit:
                break
        return samples

    def _check_plaintext_tokens(
        self,
        host: str,
        url: str,
        result: HttpResult,
    ) -> None:
        if not result.set_cookies:
            return
        groups: dict[str, list[tuple[CookieView, str]]] = {
            "high": [], "medium": [], "info": [],
        }
        for raw, view in zip(result.set_cookies,
                             parse_cookies(result.set_cookies)):
            if view.jwt is not None:
                if view.jwt.is_public:
                    groups["info"].append((view, raw))
                elif view.sensitive or view.jwt.subject or view.jwt.scope:
                    groups["high"].append((view, raw))
                else:
                    groups["info"].append((view, raw))
            elif view.sensitive:
                groups["medium"].append((view, raw))
            else:
                groups["info"].append((view, raw))
        titles = {
            "high": "Authenticated session token transmitted over plaintext HTTP",
            "medium": "Session-like cookie transmitted over plaintext HTTP",
            "info": "Anonymous/public token transmitted over plaintext HTTP",
        }
        descriptions = {
            "high": "A token whose claims indicate an authenticated/privileged "
                    "session is issued over unencrypted HTTP. Anyone on the network "
                    "path can read and replay it until it expires.",
            "medium": "An opaque session-like cookie is issued over unencrypted "
                      "HTTP. Its value is not decodable offline, so treat it as a "
                      "live session credential and verify impact manually.",
            "info": "A cookie whose claims/name indicate public or anonymous data "
                    "is issued over unencrypted HTTP. Impact is limited unless the "
                    "cookie later gains authenticated state.",
        }
        for severity, items in groups.items():
            if not items:
                continue
            lines: list[str] = []
            for view, raw in items:
                lines.extend([
                    cookie_summary(view, secure_required=False),
                    "Set-Cookie (value redacted in text): "
                    + _redacted_cookie(raw),
                    "Value fingerprint: " + _cookie_fingerprint(raw),
                ])
                if view.jwt is not None:
                    lines.append(
                        "JWT claims (offline decode, not verified): "
                        + (view.jwt.summary() or "(unreadable)"))
            analysis = "\n".join(
                [f"Cleartext response: {url}",
                 f"HTTP status: {result.status}"] + lines
                + ["", "Policy: token values were not decoded for "
                      "authorization, verified, or replayed; JWT claims were "
                      "decoded offline only to classify the token."]
                + ["", "Response headers (verbatim except cookie values; "
                      "the raw response is stored in the evidence file):"]
                + _verbatim_headers(result, redact_cookies=True)
            )
            finding = Finding(
                title=titles[severity],
                severity=severity,
                category="tokens",
                host=host,
                url=url,
                description=descriptions[severity],
                remediation="Serve the site over HTTPS only, redirect HTTP, enable "
                            "HSTS, and mark session cookies Secure; rotate any "
                            "token that may have crossed a network the operator "
                            "does not control.",
                confidence=CONFIDENCE_CONFIRMED,
                verified=True,
                verification=(
                    "Set-Cookie issued over an HTTP response observed directly; "
                    "claims decoded offline without signature verification"
                ),
            )
            self._stamp(finding, reproductions=1, stable=True, result=result)
            self.evidence.attach(
                finding, result, f"plaintext token {host}", intro=analysis)
            self._add(finding)

    def _check_security_txt(self, probe: Probe) -> None:
        if not probe.url:
            return
        origin = _origin(probe.url)
        host = (urlsplit(origin).hostname or "").lower()
        if host in self.security_txt or not in_scope(host, self.client.scopes):
            return
        url = _join(origin, SECURITY_TXT_PATH)
        result = self.client.get(url, follow=False, read_limit=65536)
        entry: dict = {
            "url": url, "status": result.status, "valid": False,
            "reason": "", "contacts": [], "expires": "", "expired": False,
            "fields": {},
        }
        self.security_txt[host] = entry
        if not result.ok or result.status is None:
            entry["reason"] = "no response"
            return
        if result.status != 200:
            entry["reason"] = f"HTTP {result.status}"
            return
        content_type = result.headers.get("content-type", "").lower()
        text = result.text or ""
        head = text.lstrip()[:512].lower()
        if "html" in content_type or head.startswith("<!doctype") or \
                head.startswith("<html"):
            entry["reason"] = "response is an HTML page, not a security.txt file"
            return
        if self._is_catch_all(origin, SECURITY_TXT_PATH, result):
            entry["reason"] = "response matches the host's catch-all page"
            return
        fields: dict[str, list[str]] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key in SECURITY_TXT_FIELDS and value:
                fields.setdefault(key, []).append(value)
        entry["fields"] = fields
        contacts = fields.get("contact", [])
        entry["contacts"] = contacts
        expires = (fields.get("expires") or [""])[0]
        entry["expires"] = expires
        if not contacts:
            entry["reason"] = "no Contact field (required by RFC 9116)"
            return
        entry["valid"] = True
        moment = _parse_expiry(expires) if expires else None
        expired = moment is not None and moment <= datetime.now(timezone.utc)
        entry["expired"] = expired
        missing_expires = not expires
        title = ("security.txt has expired" if expired
                 else "security.txt published")
        severity = "low" if expired else "info"
        detail = [f"URL: {url}"]
        for key in SECURITY_TXT_FIELDS:
            for value in fields.get(key, []):
                detail.append(f"{key.title()}: {value}")
        if missing_expires:
            detail.append("Expires: (missing; RFC 9116 requires this field)")
        finding = Finding(
            title=title,
            severity=severity,
            category="exposure",
            host=host,
            url=url,
            description=(
                "A security contact file was parsed successfully. This is "
                "informational unless the Expires date has passed or required "
                "fields are missing."
            ),
            remediation="Keep Contact and Expires current (RFC 9116); refresh "
                        "Expires before it lapses.",
            confidence=CONFIDENCE_CONFIRMED,
            verified=True,
            verification="security.txt parsed from the response body",
        )
        self._stamp(finding, reproductions=1, stable=True, result=result)
        self.evidence.attach(
            finding, result, f"security.txt {host}",
            intro="\n".join(detail))
        self._add(finding)

    @staticmethod
    def _normalize_body(body: bytes, path: str) -> bytes:
        normalized = body
        if len(path) > 1:
            normalized = normalized.replace(path.encode("utf-8", "ignore"), b"<path>")
            # Catch-all routes often echo each path segment separately (for
            # example {"code":"<seg1>","location":"<seg2>"}), so normalize the
            # segments too instead of only the joined path.
            for segment in path.strip("/").split("/"):
                if len(segment) >= 4:
                    normalized = normalized.replace(
                        segment.encode("utf-8", "ignore"), b"<seg>")
        return re.sub(rb"\s+", b" ", normalized).strip().lower()

    @staticmethod
    def _path_segments(path: str) -> int:
        return max(1, len([part for part in path.split("/") if part]))

    def _soft404_baseline(
        self, origin: str, segments: int = 1
    ) -> tuple[int, bytes, int] | None:
        """Fetch a random missing path with the same shape as the tested one."""
        segments = max(1, segments)
        key = (origin, segments)
        if key in self._baselines:
            return self._baselines[key]
        parts = [f"webwarden-missing-{secrets.token_hex(6)}"
                 for _ in range(segments)]
        path = "/" + "/".join(parts)
        result = self.client.get(origin + path, follow=False, read_limit=16384)
        baseline = None
        if result.ok and result.status is not None:
            baseline = (
                result.status,
                self._normalize_body(result.body, path),
                len(result.body),
            )
        self._baselines[key] = baseline
        return baseline

    def _is_catch_all(self, origin: str, path: str, result: HttpResult) -> bool:
        """True when a URL only returned the host's generic 200/403 page."""
        if result.status in BLOCKED_STATUSES:
            return True
        if result.status not in (200, 206):
            return False
        baseline = self._soft404_baseline(origin, self._path_segments(path))
        if not baseline:
            return False
        base_status, base_body, base_size = baseline
        if result.status != base_status or base_status not in (200, 206):
            return False
        body = self._normalize_body(result.body, path)
        if body == base_body:
            return True
        if not similar_length(len(body), len(base_body), 0.05):
            return False
        return SequenceMatcher(None, body[:8192], base_body[:8192]).ratio() > 0.95

    def _bypass_variants(
        self, url: str, path: str
    ) -> list[tuple[str, str, dict[str, str]]]:
        parsed = urlsplit(url)
        scheme, netloc, query = parsed.scheme, parsed.netloc, parsed.query
        origin = f"{scheme}://{netloc}"
        base = path if path.startswith("/") else "/" + path
        stripped = base.strip("/")
        path_variants: list[tuple[str, str, dict[str, str]]] = []
        if stripped:
            path_tests = [
                ("path double slash", f"//{stripped}"),
                ("path trailing slash", f"/{stripped}/"),
                ("path dot segment", f"/./{stripped}"),
                ("path trailing dot", f"/{stripped}/."),
                ("path encoded dot", f"/%2e/{stripped}"),
                ("path double encoded dot", f"/%252e/{stripped}"),
                ("path encoded slash", f"/%2f{stripped}"),
                ("path leading semicolon", f"/;/{stripped}"),
                ("path encoded space", f"/{stripped}%20"),
                ("path encoded tab", f"/{stripped}%09"),
                ("path parameter", f"/{stripped}/.;/"),
                ("path case variation", f"/{stripped.upper()}"),
            ]
            for label, mutated in path_tests:
                if mutated == base:
                    continue
                path_variants.append((
                    label,
                    urlunsplit((scheme, netloc, mutated, query, "")),
                    {},
                ))
        injected_headers = [
            ("header X-Forwarded-For", {"X-Forwarded-For": "127.0.0.1"}),
            ("header X-Real-IP", {"X-Real-IP": "127.0.0.1"}),
            ("header X-Originating-IP", {"X-Originating-IP": "127.0.0.1"}),
            ("header X-Remote-IP", {"X-Remote-IP": "127.0.0.1"}),
            ("header X-Client-IP", {"X-Client-IP": "127.0.0.1"}),
            ("header X-Forwarded-Host", {"X-Forwarded-Host": "localhost"}),
            ("header X-Host", {"X-Host": "localhost"}),
            ("header X-Forwarded-Prefix", {"X-Forwarded-Prefix": base}),
            ("header X-Custom-IP-Authorization",
             {"X-Custom-IP-Authorization": "127.0.0.1"}),
            ("header Forwarded", {"Forwarded": "for=127.0.0.1;proto=https"}),
        ]
        header_variants = [
            (label, url, dict(headers)) for label, headers in injected_headers
        ]
        rewrite_variants = [
            ("header X-Original-URL", origin + "/", {"X-Original-URL": base}),
            ("header X-Rewrite-URL", origin + "/", {"X-Rewrite-URL": base}),
        ]
        ordered: list[tuple[str, str, dict[str, str]]] = []
        for index in range(max(len(header_variants), len(path_variants),
                               len(rewrite_variants))):
            if index < len(header_variants):
                ordered.append(header_variants[index])
            if index < len(path_variants):
                ordered.append(path_variants[index])
            if index < len(rewrite_variants):
                ordered.append(rewrite_variants[index])
        unique: list[tuple[str, str, dict[str, str]]] = []
        seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
        for label, target, headers in ordered:
            key = (target, tuple(sorted(headers.items())))
            if key in seen:
                continue
            seen.add(key)
            unique.append((label, target, headers))
        return unique[: self.bypass_max_variants]

    def _bypass_response_ok(
        self, origin: str, target_url: str, result: HttpResult, validate
    ) -> bool:
        if not result.ok or result.status not in (200, 201, 202, 203, 204, 206):
            return False
        target_path = urlsplit(target_url).path or "/"
        if self._is_catch_all(origin, target_path, result):
            return False
        if result.text and content_looks_like_login(result.text):
            return False
        if validate is _any_status_ok:
            lowered = result.body.lower()
            markers = (b"dashboard", b"logout", b"sign out", b"admin panel",
                       b"user management", b"admin")
            if not any(marker in lowered for marker in markers):
                return False
        try:
            return bool(validate(result.body, result.headers, result.status))
        except Exception:
            return False

    @staticmethod
    def _same_bypass_body(first: HttpResult, second: HttpResult) -> bool:
        if sha_prefix(first.body) == sha_prefix(second.body):
            return True
        if not similar_length(len(first.body), len(second.body), 0.10):
            return False
        return SequenceMatcher(
            None, first.body[:8192].lower(), second.body[:8192].lower()
        ).ratio() > 0.98

    @staticmethod
    def _bypass_poc(
        original: str, target: str, headers: dict[str, str]
    ) -> list[str]:
        commands = [
            "# control: request without the bypass; expect HTTP 401/403",
            "curl -sS --max-time 15 -o /dev/null -w 'control: HTTP %{http_code}\\n' "
            + shlex.quote(original),
            "# bypass: read-only GET; nothing is modified; full body is saved",
        ]
        header_list = [f"{name}: {value}" for name, value in headers.items()]
        commands += full_capture(
            target,
            evidence_slug(target, "bypass"),
            headers=header_list,
        )
        return commands

    def _try_bypass(
        self,
        probe: Probe,
        url: str,
        path: str,
        baseline: HttpResult,
        title: str,
        severity: str,
        description: str,
        remediation: str,
        validate,
        confidence: str,
    ) -> None:
        host_key = (urlsplit(url).hostname or "").lower()
        if self._bypass_paths.get(host_key, 0) >= self.bypass_max_paths:
            return
        if self._bypass_requests >= self.bypass_max_requests:
            return
        self._bypass_paths[host_key] = self._bypass_paths.get(host_key, 0) + 1
        origin = _origin(url)
        attempt = {
            "host": probe.host,
            "path": path,
            "baseline": baseline.status,
            "baseline_bytes": len(baseline.body),
            "variants": 0,
            "bypass": False,
            "technique": None,
        }
        for technique, target_url, headers in self._bypass_variants(url, path):
            if self._bypass_requests >= self.bypass_max_requests:
                break
            if technique.startswith(("header X-Original-URL",
                                     "header X-Rewrite-URL")) \
                    and validate is _any_status_ok:
                continue
            self._bypass_requests += 1
            attempt["variants"] += 1
            result = self.client.get(
                target_url, headers=headers, follow=False,
                read_limit=self.evidence_limit, max_bytes=self.evidence_limit,
            )
            if not self._bypass_response_ok(origin, target_url, result, validate):
                continue
            confirmation = self.client.get(
                target_url, headers=headers, follow=False,
                read_limit=self.evidence_limit, max_bytes=self.evidence_limit,
            )
            if not self._bypass_response_ok(
                    origin, target_url, confirmation, validate):
                continue
            if not self._same_bypass_body(result, confirmation):
                continue
            control = self.client.get(
                url, follow=False,
                read_limit=self.evidence_limit, max_bytes=self.evidence_limit,
            )
            if not control.ok or control.status not in (401, 403):
                continue
            finding_severity = severity
            if path in ("/admin/", "/phpmyadmin/", "/manager/html") \
                    and severity in ("info", "low"):
                finding_severity = "medium"
            finding = Finding(
                title=f"401/403 bypass: {title}",
                severity=finding_severity,
                category="access-control-bypass",
                host=probe.host,
                url=target_url,
                description=(
                    "The endpoint returned a 401/403 response without the bypass, "
                    "but returned protected content when the request was modified. "
                    "This indicates an access-control decision that can be bypassed."
                ),
                remediation=(
                    "Enforce authorization at the application layer, canonicalize "
                    "paths before access checks, and do not trust proxy or rewrite "
                    "headers from untrusted clients."
                ),
                confidence=confidence,
                verified=True,
                verification=(
                    f"baseline HTTP {baseline.status}; bypass HTTP "
                    f"{result.status} reproduced twice with {technique}; "
                    f"control still HTTP {control.status}"
                ),
                poc=self._bypass_poc(url, target_url, headers),
            )
            baseline_capture = self.evidence.write_response(
                baseline, f"bypass-baseline {path}"
            )
            self.evidence.attach(
                finding,
                result,
                f"bypass {path}",
                intro=(
                    f"Baseline: HTTP {baseline.status} "
                    f"({len(baseline.body)} bytes)\n"
                    f"Bypass: HTTP {result.status} "
                    f"({len(result.body)} bytes, "
                    f"sha256:{sha_prefix(confirmation.body)})\n"
                    f"Technique: {technique}\n"
                    "Control: original request still HTTP "
                    f"{control.status} after the bypass"
                ),
                extra=[("baseline without the bypass", baseline_capture)],
            )
            self._add(self._stamp(
                finding, reproductions=2, stable=True, result=result))
            attempt.update({
                "bypass": True,
                "technique": technique,
                "bypass_url": target_url,
                "bypass_status": result.status,
                "control_status": control.status,
            })
            break
        self.bypass_attempts.append(attempt)

    def _check_files(self, probe: Probe) -> None:
        assert probe.url is not None
        origin = _origin(probe.url)
        origin_host = (urlsplit(probe.url).hostname or "").lower()
        for path, severity, title, description, remediation, validate, confidence \
                in FILE_CHECKS:
            url = _join(origin, path)
            if not in_scope(origin_host, self.client.scopes):
                return
            result = self.client.get(url, follow=False, read_limit=16384)
            if not result.ok or result.status is None:
                continue
            if result.status in BLOCKED_STATUSES:
                if self.bypass and result.status in (401, 403):
                    self._try_bypass(
                        probe, url, path, result, title, severity,
                        description, remediation, validate, confidence,
                    )
                continue
            try:
                matched = validate(result.body, result.headers, result.status)
            except Exception:
                matched = False
            if not matched:
                continue
            request_path = urlsplit(url).path or "/"
            if self._is_catch_all(origin, request_path, result):
                continue
            confirmation = self.client.get(
                url, follow=False,
                read_limit=self.evidence_limit, max_bytes=self.evidence_limit,
            )
            reproduced = False
            if confirmation.ok and confirmation.status is not None:
                try:
                    reproduced = bool(validate(
                        confirmation.body, confirmation.headers,
                        confirmation.status,
                    ))
                except Exception:
                    reproduced = False
            if reproduced and self._is_catch_all(
                    origin, request_path, confirmation):
                reproduced = False
            same_body: bool | None = None
            if reproduced:
                same_body = sha_prefix(confirmation.body) == sha_prefix(result.body)
                verification = (
                    "signature matched on two independent requests; "
                    f"sha256:{sha_prefix(confirmation.body)}"
                    + ("" if same_body else " (body changed between requests)")
                )
            else:
                verification = (
                    "signature matched once; a second request did not reproduce it"
                )
            finding = Finding(
                title=title,
                severity=severity,
                category="exposure",
                host=probe.host,
                url=url,
                description=description,
                remediation=remediation,
                confidence=confidence if reproduced else CONFIDENCE_MANUAL,
                verified=reproduced,
                verification=verification,
            )
            self._stamp(
                finding,
                reproductions=2 if reproduced else 1,
                stable=same_body,
                result=confirmation if reproduced else result,
            )
            self.evidence.attach(
                finding,
                confirmation if reproduced else result,
                f"{title} {path}",
                intro=f"Detected file: {path}\nSignature: matched",
            )
            self._add(finding)

    def _check_client_secrets(self) -> None:
        sources: dict[str, HttpResult] = {}
        for probe in self.probes:
            if not probe.live or not probe.result or not probe.result.text:
                continue
            text = probe.result.text
            content_type = probe.result.content_type
            if "html" not in content_type and "<script" not in text[:4096].lower():
                continue
            sources[probe.result.final_url] = probe.result
        for url, result in self._crawled.items():
            if url not in sources and result.text:
                sources[url] = result

        groups: dict[tuple[str, str, str], dict] = {}
        scripts: list[str] = []
        for url, result in list(sources.items())[: self.max_file_hosts]:
            self.secret_files += 1
            self._collect_secret_hits(url, result, groups)
            for src in SCRIPT_RE.findall(result.text):
                candidate = urljoin(url, src.strip())
                if not candidate.lower().startswith(("http://", "https://")):
                    continue
                if not self._in_client_scope(candidate):
                    continue
                if candidate not in scripts:
                    scripts.append(candidate)

        for script in scripts[:12]:
            if script in self._client_sources:
                continue
            result = self.client.get(
                script, follow=False, read_limit=1048576, max_bytes=1048576)
            self.secret_files += 1
            if not result.ok or result.status != 200 or not result.body:
                continue
            self._client_sources[script] = result
            self._collect_secret_hits(script, result, groups)
            for map_path in SOURCE_MAP_RE.findall(result.text)[:2]:
                map_url = urljoin(script, map_path.strip())
                if not self._in_client_scope(map_url):
                    continue
                self._check_source_map(map_url, script)

        for entry in list(groups.values())[:8]:
            hit = entry["hit"]
            files = sorted(entry["files"])
            first_url, first_result = entry["sources"][0]
            verified, verification, stable = self._secret_reproduced(
                first_url, first_result, hit)
            host = (urlsplit(first_url).hostname or "").lower()
            self._emit_secret_finding(
                host=host,
                sources=entry["sources"],
                hit=hit,
                context="Exposure: " + ", ".join(files[:6]),
                confidence=CONFIDENCE_CONFIRMED if verified else CONFIDENCE_FIRM,
                verified=verified,
                verification=verification,
                stable=stable,
                title=f"{hit.kind} exposed in client-side content",
            )

    def _check_bundles(self) -> None:
        def fetch(url: str) -> HttpResult:
            return self.client.get(
                url, follow=False, read_limit=1048576, max_bytes=1048576)

        page_text = {
            (probe.host or "").lower(): probe.result.text
            for probe in self.probes if probe.result is not None
        }
        produced, reports, meta = bundle_recon.analyze(
            [probe for probe in self.probes if probe.live and probe.url],
            fetch,
            self.client.scopes,
            cache=self._client_sources,
            max_hosts=4,
            max_assets=10,
            max_requests=60,
        )
        self.bundle_reports = reports
        self.bundle_meta = meta
        for finding, result in produced:
            self._stamp(
                finding,
                reproductions=finding.reproductions,
                stable=finding.stable,
                text=page_text.get(finding.host.lower(), ""),
            )
            if self.evidence.enabled and result is not None:
                label = finding.title.split(":", 1)[-1].strip()[:48]
                self.evidence.attach(
                    finding, result, f"bundle {label} {finding.host}")
                finding.evidence = (
                    finding.evidence
                    + f"\n\nRaw response stored privately: {finding.evidence_file}"
                    + f"\nSHA-256: {finding.evidence_sha256}"
                    + f"\nBytes: {finding.evidence_bytes}"
                )
            self._add(finding)

    def _collect_secret_hits(
        self,
        url: str,
        result: HttpResult,
        groups: dict[tuple[str, str, str], dict],
    ) -> None:
        host = (urlsplit(url).hostname or "").lower()
        for hit in scan_text(result.text):
            key = (host, hit.kind, hit.fingerprint)
            entry = groups.get(key)
            if entry is None:
                entry = {"hit": hit, "files": set(), "sources": []}
                groups[key] = entry
            entry["files"].add(url)
            if url not in [item[0] for item in entry["sources"]]:
                entry["sources"].append((url, result))

    def _secret_reproduced(
        self,
        url: str,
        result: HttpResult,
        hit,
    ) -> tuple[bool, str, bool | None]:
        again = self.client.get(
            url, follow=False, read_limit=1048576, max_bytes=1048576)
        if not again.ok or again.status != 200:
            return False, (
                "pattern matched once; a second request did not return HTTP 200"
            ), None
        same = sha_prefix(again.body) == sha_prefix(result.body)
        present = any(item.fingerprint == hit.fingerprint
                      for item in scan_text(again.text))
        partial = ""
        for candidate in (result, again):
            if getattr(candidate, "truncated", False):
                declared = (candidate.headers or {}).get("content-length")
                partial = (
                    f"; the file was read partially ({len(candidate.body)} of "
                    f"{declared or 'unknown'} bytes), so matches beyond the "
                    "captured prefix were not examined"
                )
                break
        if present:
            return True, (
                "same value re-detected on a second independent request; "
                f"value sha256 prefix {hit.fingerprint}"
                + ("" if same else " (body changed between requests)")
                + partial
            ), same
        return False, (
            "pattern matched once; it was absent on the second request"
            + partial
        ), None

    def _emit_secret_finding(
        self,
        *,
        host: str,
        sources: list[tuple[str, HttpResult]],
        hit,
        context: str,
        confidence: str,
        verified: bool,
        verification: str,
        title: str,
        stable: bool | None = None,
    ) -> None:
        first_url, first_result = sources[0]
        truncated_sources = [
            (url, result) for url, result in sources
            if getattr(result, "truncated", False)
        ]
        analysis_lines = [
            f"Finding: {hit.kind}",
            f"Redacted value: {hit.redacted}",
            f"Value SHA-256 prefix: {hit.fingerprint}",
            f"Occurrences: {len(sources)} file(s)",
            "Files:",
            *[f"- {url}" for url, _ in sources[:10]],
            "",
            "Context: " + hit.context,
            "",
            "Why it matters: " + hit.note,
            context,
        ]
        if truncated_sources:
            analysis_lines.extend([
                "",
                "Truncated reads (only the captured prefix was scanned):",
                *[
                    f"- {url}: captured {len(result.body)} of "
                    f"{(result.headers or {}).get('content-length', 'unknown')} "
                    "bytes"
                    for url, result in truncated_sources[:6]
                ],
            ])
        if hit.decoy:
            analysis_lines.extend([
                "",
                "Test/publishable credential: " + hit.decoy_reason
                + ". This value may be public by design or only valid against "
                  "a sandbox and was assigned a reduced severity.",
            ])
        analysis_lines.extend([
            "",
            "Handling: the value is never used, replayed, or authorized with. "
            "Report text redacts it; the raw response is kept only in the "
            "private evidence directory.",
        ])
        analysis = "\n".join(analysis_lines)
        poc = [
            "# Read-only confirmation only; never authenticate with the value.",
            f"curl -sS {shlex.quote(first_url)} | sha256sum",
            "grep -nE " + shlex.quote(hit.pattern)
            + f" <(curl -sS {shlex.quote(first_url)}) | cut -c1-80",
        ]
        for url, _result in truncated_sources[:2]:
            poc.extend([
                f"curl -sSI {shlex.quote(url)} | grep -i '^content-length:'",
                f"curl -sS {shlex.quote(url)} | wc -c",
            ])
        if truncated_sources:
            poc.append(
                "# Read-only: a Content-Length larger than the captured byte "
                "count means only a prefix was scanned.")
        poc.append(
            "# Redact the matched value before sharing outside the private report.")
        finding = Finding(
            title=title,
            severity=hit.severity,
            category="secrets",
            host=host,
            url=first_url,
            description=(
                f"A string shaped like {hit.kind} is served to any visitor. "
                + hit.note
                + " Confirm in the program scope that this credential belongs "
                "to the target and has real privileges before reporting it."
                + (" Some sources exceeded the 1 MiB scan cap, so more matches "
                   "may exist beyond the captured prefix."
                   if truncated_sources else "")
            ),
            remediation="Remove the value from client-delivered content, move "
                        "the call server-side, and rotate the credential if it was "
                        "live.",
            confidence=confidence,
            verified=verified,
            verification=verification,
            poc=poc,
        )
        if hit.decoy:
            finding.decoy_suspected = True
            finding.decoy_reason = hit.decoy_reason
        self._stamp(
            finding,
            reproductions=2 if verified else 1,
            stable=stable,
            result=first_result,
        )
        if hit.decoy:
            note = f"Test/publishable credential marker: {hit.decoy_reason}"
            finding.verification = (
                f"{finding.verification} | {note}"
                if finding.verification else note
            )
        if self.evidence.enabled:
            self.evidence.attach(
                finding, first_result, f"secret {hit.kind} {host}",
                intro=analysis)
            finding.evidence = (
                analysis
                + f"\n\nRaw response stored privately: {finding.evidence_file}"
                + f"\nSHA-256: {finding.evidence_sha256}"
                + f"\nBytes: {finding.evidence_bytes}"
            )
        else:
            finding.evidence = analysis
        self._add(finding)
        self.secret_hits.append({
            "host": host,
            "kind": hit.kind,
            "severity": hit.severity,
            "files": [url for url, _ in sources],
            "redacted": hit.redacted,
            "sha256_prefix": hit.fingerprint,
            "decoy": hit.decoy,
            "decoy_reason": hit.decoy_reason,
        })

    def _check_source_map(self, map_url: str, script_url: str) -> None:
        if any(entry["url"] == map_url for entry in self.source_maps):
            return
        result = self.client.get(
            map_url, follow=False, read_limit=1048576, max_bytes=1048576)
        if not result.ok or result.status != 200:
            return
        text = result.text[:400000]
        if '"mappings"' not in text and '"sources"' not in text:
            return
        sources = re.findall(r'"sources"\s*:\s*\[([^\]]*)\]', text, re.IGNORECASE)
        source_count = len(re.findall(r'"[^"]+"', sources[0])) if sources else 0
        has_mappings = '"mappings"' in text
        entry = {
            "url": map_url,
            "script": script_url,
            "status": result.status,
            "sources": source_count,
            "mappings": has_mappings,
        }
        self.source_maps.append(entry)
        finding = Finding(
            title="JavaScript source map published",
            severity="low" if source_count else "info",
            category="exposure",
            host=(urlsplit(map_url).hostname or "").lower(),
            url=map_url,
            description=(
                "A source map is downloadable"
                + (f" and lists {source_count} original source path(s)" if source_count
                   else "")
                + ". Developers can reconstruct readable source and internal "
                "comments; impact depends on what the bundle already exposes. "
                "Often treated as informational by bug bounty programs."
            ),
            remediation="Do not publish .map files in production, or restrict them "
                        "to internal networks.",
            confidence=CONFIDENCE_CONFIRMED,
            verified=True,
            verification="source map JSON observed directly (HTTP 200, mappings/"
                         "sources keys present)",
            poc=[
                f"curl -sS {shlex.quote(map_url)} | head -c 400",
                "# The map itself is the evidence; do not attempt to use it to "
                "access privileged functionality.",
            ],
        )
        analysis = "\n".join([
            f"Source map: {map_url}",
            f"Referenced by: {script_url}",
            f"Original sources listed: {source_count}",
            f"Has mappings: {'yes' if has_mappings else 'no'}",
            "Raw response stored privately for reproduction.",
        ])
        finding.evidence = analysis
        if self.evidence.enabled:
            self.evidence.attach(
                finding, result, f"source map {map_url.split('/')[-1]}",
                intro=analysis)
            finding.evidence = (
                analysis
                + f"\n\nRaw response stored privately: {finding.evidence_file}"
                + f"\nSHA-256: {finding.evidence_sha256}"
            )
        self._add(self._stamp(
            finding, reproductions=1, stable=True, result=result))

    def _check_url_tokens(self) -> None:
        candidates = list(self.urls)
        for probe in self.probes:
            if probe.url:
                candidates.append(probe.url)
        seen: set[tuple[str, str, str]] = set()
        for url in candidates[:400]:
            if not self._in_client_scope(url):
                continue
            parsed = urlsplit(url)
            for name, value in parse_qsl(parsed.query, keep_blank_values=False):
                lowered = name.lower()
                if lowered not in HIGH_RISK_PARAMS and lowered not in LOW_RISK_PARAMS:
                    continue
                if len(value) < 6:
                    continue
                key = ((parsed.hostname or "").lower(), parsed.path, lowered)
                if key in seen:
                    continue
                seen.add(key)
                severity = self._url_token_severity(
                    parsed.scheme, lowered, value)
                if severity is None:
                    continue
                self.url_token_count += 1
                redacted_url = urlunsplit((
                    parsed.scheme, parsed.netloc, parsed.path,
                    urlencode([(name, "<redacted>")]), "",
                ))
                finding = Finding(
                    title=f"Credential-like parameter '{name}' in URL",
                    severity=severity,
                    category="url-tokens",
                    host=(parsed.hostname or "").lower(),
                    url=redacted_url,
                    description=(
                        f"The URL carries a parameter named '{name}' whose name "
                        "indicates a credential. URLs appear in proxy logs, "
                        "browser history, Referer headers, and analytics, so the "
                        "value can leak without any network attacker. The value is "
                        "withheld here and was never replayed. Confirm it is a live "
                        "credential before reporting."
                    ),
                    remediation="Move credentials into headers or POST bodies, use "
                                "short-lived single-use links, and avoid logging "
                                "query strings.",
                    evidence=(
                        f"Parameter: {name}\n"
                        f"Scheme: {parsed.scheme}\n"
                        f"Value: <redacted> (SHA-256 prefix "
                        f"{sha_prefix(value.encode('utf-8', 'replace'), 12)})\n"
                        f"Location: {parsed.path}\n"
                        "Observed in crawl output; no active request was sent with "
                        "this URL."
                    ),
                    confidence=CONFIDENCE_FIRM,
                    verified=False,
                    verification="parameter name and scheme observed in crawl "
                                 "output; value redacted and never replayed",
                    poc=[
                        "# Reproduction intentionally withheld: the URL embeds a "
                        "credential.",
                        "# Do not replay a live token; ask the program for a "
                        "fresh test token if proof is required.",
                        "# Evidence: parameter name, scheme, and location are "
                        "recorded above.",
                    ],
                )
                self._add(self._stamp(
                    finding, reproductions=0, stable=None))

    def _url_token_severity(
        self,
        scheme: str,
        name: str,
        value: str,
    ) -> str | None:
        jwt = decode_jwt(value)
        plaintext = scheme == "http"
        if jwt is not None and not jwt.is_public and (jwt.subject or jwt.scope):
            return "high" if plaintext else "medium"
        if name in HIGH_RISK_PARAMS:
            return "medium" if plaintext else "low"
        if name in LOW_RISK_PARAMS:
            return "low" if plaintext else "info"
        return None

    def _check_robots_paths(self) -> None:
        for host in sorted(self.robots)[:4]:
            probe = next(
                (item for item in self.probes
                 if item.host == host and item.url), None)
            if not probe or not probe.url:
                continue
            origin = _origin(probe.url)
            reachable: list[str] = []
            secret_finds: list[tuple[str, HttpResult, object]] = []
            checked = 0
            for path in self.robots.get(host) or []:
                if checked >= 6:
                    break
                if not path.startswith("/") or any(ch in path for ch in "*$"):
                    continue
                url = urljoin(origin, path)
                if not self._in_client_scope(url):
                    continue
                checked += 1
                result = self.client.get(url, follow=False, read_limit=65536)
                if not result.ok or result.status != 200 or not result.text:
                    continue
                if content_looks_like_login(result.text):
                    continue
                if self._is_catch_all(origin, urlsplit(url).path or "/", result):
                    continue
                reachable.append(path)
                if self.scan_secrets:
                    for hit in scan_text(result.text, max_hits=3):
                        secret_finds.append((url, result, hit))
                        break
            if reachable:
                self._add(self._stamp(Finding(
                    title="robots.txt Disallow paths are publicly reachable",
                    severity="info",
                    category="exposure",
                    host=host,
                    url=urljoin(origin, reachable[0]),
                    description=(
                        "robots.txt lists paths that are served without an "
                        "authentication challenge. Disallow is a crawler hint, "
                        "not access control, so this is informational unless the "
                        "content is sensitive."
                    ),
                    remediation="Enforce authorization on these paths instead of "
                                "relying on robots.txt.",
                    evidence=(
                        "Reachable Disallow paths:\n"
                        + "\n".join(f"- {path}" for path in reachable[:12])
                        + "\n\nrobots.txt Disallow is advisory; verify each path "
                          "manually for sensitive content."
                    ),
                    confidence=CONFIDENCE_FIRM,
                    verified=True,
                    verification="HTTP 200 observed on the listed paths",
                ), reproductions=1))
            for url, result, hit in secret_finds[:3]:
                verified, verification, stable = self._secret_reproduced(
                    url, result, hit)
                self._emit_secret_finding(
                    host=host,
                    sources=[(url, result)],
                    hit=hit,
                    context="Location: robots.txt Disallow path (not access "
                            "control).",
                    confidence=CONFIDENCE_CONFIRMED if verified else CONFIDENCE_FIRM,
                    verified=verified,
                    verification=verification,
                    stable=stable,
                    title=f"{hit.kind} exposed at a robots.txt path",
                )

    def _redirect_urls(self) -> list[str]:
        selected: list[str] = []
        for url in self.urls:
            if not self._in_client_scope(url):
                continue
            query = urlsplit(url).query
            if not query:
                continue
            names = {name.lower() for name, _ in parse_qsl(query, keep_blank_values=True)}
            if names & REDIRECT_PARAMS:
                selected.append(url)
        return selected[:15]

    def _check_redirects(self) -> None:
        marker = "webwarden.invalid"
        target = "https://webwarden.invalid/poc"
        for url in self._redirect_urls():
            parsed = urlsplit(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            for index, (name, _value) in enumerate(pairs):
                if name.lower() not in REDIRECT_PARAMS:
                    continue
                new_pairs = list(pairs)
                new_pairs[index] = (name, target)
                candidate = urlunsplit((
                    parsed.scheme, parsed.netloc, parsed.path,
                    urlencode(new_pairs, doseq=True), "",
                ))
                result = self.client.get(candidate, follow=False)
                if not result.ok or result.status is None:
                    continue
                if not (300 <= result.status < 400):
                    continue
                location = result.headers.get("location", "")
                location_host = (urlsplit(location).hostname or "").lower()
                if location_host != marker:
                    continue
                second_target = "https://webwarden-verify.invalid/poc"
                second_pairs = list(pairs)
                second_pairs[index] = (name, second_target)
                second_candidate = urlunsplit((
                    parsed.scheme, parsed.netloc, parsed.path,
                    urlencode(second_pairs, doseq=True), "",
                ))
                second = self.client.get(second_candidate, follow=False)
                second_location = second.headers.get("location", "")
                reproduced = (
                    second.ok and second.status is not None
                    and 300 <= second.status < 400
                    and (urlsplit(second_location).hostname or "").lower()
                    == "webwarden-verify.invalid"
                )
                self._add(self._stamp(Finding(
                    title="Open redirect",
                    severity="medium",
                    category="redirect",
                    host=parsed.hostname or "",
                    url=candidate,
                    description="A query parameter controls the redirect target, which "
                                "can be abused for phishing and OAuth token leakage.",
                    remediation="Allowlist redirect destinations or use relative paths only.",
                    evidence=f"Parameter: {name}\nHTTP {result.status}\n"
                             f"Location: {location}",
                    confidence=CONFIDENCE_CONFIRMED,
                    verified=reproduced,
                    verification=(
                        "redirect reproduced with two distinct external hosts"
                        if reproduced else
                        "redirect observed once; a second host was not reflected"
                    ),
                ), reproductions=2 if reproduced else 1,
                    stable=True if reproduced else None, result=result))
                break

    def _id_urls(self) -> list[str]:
        selected: list[str] = []
        auth_host = self.auth_host
        for url in self.urls:
            if not self._in_client_scope(url):
                continue
            host = (urlsplit(url).hostname or "").lower()
            if auth_host and host != auth_host:
                continue
            if ID_RE.search(urlsplit(url).path) or ID_RE.search(urlsplit(url).query):
                selected.append(url)
        return list(dict.fromkeys(selected))[:12]

    def _in_client_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return bool(host) and in_scope(host, self.client.scopes)

    def _check_idor(self) -> None:
        candidates = self._id_urls()
        if not self.auth_a or not candidates:
            return
        for url in candidates:
            baseline = self.client.get(
                url, auth=True, auth_headers=self.auth_a,
                read_limit=self.evidence_limit, max_bytes=self.evidence_limit,
                follow=False,
            )
            if not baseline.ok or baseline.status != 200:
                continue
            if not baseline.body or content_looks_like_login(baseline.text):
                continue
            anonymous = self.client.get(
                url, follow=False,
                read_limit=self.evidence_limit, max_bytes=self.evidence_limit,
            )
            intro = (
                f"Authenticated: HTTP {baseline.status}, {len(baseline.body)} bytes, "
                f"sha256:{sha_prefix(baseline.body)}\n"
                f"Anonymous: HTTP {anonymous.status}, {len(anonymous.body)} bytes"
            )
            anonymous_capture = self.evidence.write_response(
                anonymous, f"idor-anonymous {urlsplit(url).path}"
            )
            flagged = False
            if anonymous.ok and anonymous.status == 200 \
                    and anonymous.content_type == baseline.content_type \
                    and similar_length(len(anonymous.body), len(baseline.body)) \
                    and not content_looks_like_login(anonymous.text):
                finding = Finding(
                    title="Object accessible without authentication (possible IDOR/BOLA)",
                    severity="medium",
                    category="access-control",
                    host=(urlsplit(url).hostname or ""),
                    url=url,
                    description="An object that an authenticated user can read is also "
                                "returned to unauthenticated clients with a similar payload.",
                    remediation="Enforce object-level authorization on every request.",
                    confidence=CONFIDENCE_MANUAL,
                    verified=False,
                    verification="anonymous response matched the authenticated "
                                 "response (HTTP 200, similar length); object "
                                 "ownership still needs manual confirmation",
                )
                self.evidence.attach(
                    finding, baseline, f"idor-authenticated {urlsplit(url).path}",
                    intro=intro,
                    extra=[("anonymous request", anonymous_capture)],
                )
                self._add(self._stamp(
                    finding, reproductions=1, stable=None, result=anonymous))
                flagged = True

            if not flagged and self.auth_b:
                other = self.client.get(
                    url, auth=True, auth_headers=self.auth_b,
                    read_limit=self.evidence_limit,
                    max_bytes=self.evidence_limit, follow=False,
                )
                if other.ok and other.status == 200 and other.body \
                        and not content_looks_like_login(other.text) \
                        and other.body != baseline.body:
                    other_capture = self.evidence.write_response(
                        other, f"idor-session-b {urlsplit(url).path}"
                    )
                    finding = Finding(
                        title="Cross-account object access differs (possible IDOR)",
                        severity="medium",
                        category="access-control",
                        host=(urlsplit(url).hostname or ""),
                        url=url,
                        description="Session B received different data for an object "
                                    "read with session A. Confirm whether B is entitled "
                                    "to this object; if not, it is an IDOR/BOLA.",
                        remediation="Verify object ownership against the authenticated "
                                    "principal before returning data.",
                        confidence=CONFIDENCE_MANUAL,
                        verified=False,
                        verification="session A and session B received different "
                                     "payloads for the same object; entitlement "
                                     "still needs manual confirmation",
                    )
                    self.evidence.attach(
                        finding, baseline,
                        f"idor-session-a {urlsplit(url).path}",
                        intro=intro + f"\nSession B: HTTP {other.status}, "
                                      f"{len(other.body)} bytes, "
                                      f"sha256:{sha_prefix(other.body)}",
                        extra=[
                            ("anonymous request", anonymous_capture),
                            ("session B request", other_capture),
                        ],
                    )
                    self._add(self._stamp(
                        finding, reproductions=1, stable=None, result=other))

    def _check_injection(self) -> None:
        if self.injection_requests <= 0:
            self.injection_meta = {
                "enabled": False,
                "note": "injection probes disabled or request budget is zero",
            }
            return

        def fetch(url: str) -> HttpResult:
            return self.client.get(url, follow=False, read_limit=131072)

        candidates = list(self.urls)
        for probe in self.probes:
            if probe.url:
                candidates.append(probe.url)
        produced, meta = injection_scan.analyze(
            candidates,
            fetch,
            self.client.scopes,
            self._is_catch_all,
            max_urls=8,
            max_params=10,
            max_requests=self.injection_requests,
        )
        self.injection_meta = meta
        self.injection_count = len(produced)
        for finding, result in produced:
            self._stamp(
                finding,
                reproductions=finding.reproductions,
                stable=finding.stable,
                result=result,
            )
            if self.evidence.enabled and result is not None:
                label = finding.title.split(" in parameter", 1)[0][:48]
                self.evidence.attach(
                    finding, result, f"injection {label} {finding.host}")
                finding.evidence = (
                    finding.evidence
                    + f"\n\nRaw response stored privately: {finding.evidence_file}"
                    + f"\nSHA-256: {finding.evidence_sha256}"
                    + f"\nBytes: {finding.evidence_bytes}"
                )
            self._add(finding)

    def _check_backdoors(self) -> None:
        if self.backdoor_requests <= 0:
            self.backdoor_meta = {
                "enabled": False,
                "note": "backdoor probes disabled or request budget is zero",
            }
            return

        def fetch(url: str) -> HttpResult:
            return self.client.get(url, follow=False, read_limit=131072)

        origins: list[tuple[str, str]] = []
        for probe in self.probes:
            if not probe.live or not probe.url:
                continue
            origins.append((probe.host, _origin(probe.url)))
        produced, meta = backdoor_scan.analyze(
            origins,
            fetch,
            self.client.scopes,
            self._is_catch_all,
            max_hosts=4,
            max_requests=self.backdoor_requests,
        )
        self.backdoor_meta = meta
        self.backdoor_count = len(produced)
        for finding, result in produced:
            self._stamp(
                finding,
                reproductions=finding.reproductions,
                stable=finding.stable,
                result=result,
            )
            if self.evidence.enabled and result is not None:
                self.evidence.attach(
                    finding, result, f"backdoor {urlsplit(finding.url).path}")
                finding.evidence = (
                    finding.evidence
                    + f"\n\nRaw response stored privately: {finding.evidence_file}"
                    + f"\nSHA-256: {finding.evidence_sha256}"
                    + f"\nBytes: {finding.evidence_bytes}"
                )
            self._add(finding)
