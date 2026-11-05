"""Conservative subdomain-takeover detection.

A candidate is reported only when both conditions hold:

* the host has a CNAME pointing at a known third-party service, and
* the already-fetched root page contains that service's specific
  "resource not found / unclaimed" marker.

The check is read-only: it reuses the probe body and performs DNS lookups.
It never attempts to claim the hostname or creates provider resources.
"""

from __future__ import annotations

from dataclasses import dataclass

from .dnsq import Resolver
from .models import CONFIDENCE_MANUAL, Finding
from .recon import Probe
from .util import in_scope


@dataclass(frozen=True)
class Provider:
    name: str
    suffixes: tuple[str, ...]
    markers: tuple[str, ...]


PROVIDERS = (
    Provider(
        "GitHub Pages",
        ("github.io",),
        (
            "there isn't a github pages site here",
            "for root urls (like http://example.com/) you must provide an "
            "index.html file",
        ),
    ),
    Provider(
        "Heroku",
        ("herokuapp.com", "herokussl.com"),
        ("no such app", "there's nothing here, yet."),
    ),
    Provider(
        "AWS S3",
        ("s3.amazonaws.com", "s3-website", "s3.dualstack"),
        ("nosuchbucket", "the specified bucket does not exist"),
    ),
    Provider(
        "Azure App Service",
        ("azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"),
        ("error 404 - web app not found", "this web app is stopped"),
    ),
    Provider(
        "Netlify",
        ("netlify.app", "netlify.com"),
        ("not found - request id",),
    ),
    Provider(
        "Vercel",
        ("vercel.app", "now.sh"),
        ("deployment_not_found", "the deployment could not be found"),
    ),
    Provider(
        "Cloudflare Pages",
        ("pages.dev",),
        ("project not found",),
    ),
    Provider(
        "GitBook",
        ("gitbook.io",),
        ("if you're the owner of this website",),
    ),
    Provider(
        "Shopify",
        ("myshopify.com",),
        ("sorry, this shop is currently unavailable",),
    ),
    Provider(
        "ReadMe",
        ("readme.io",),
        ("the requested page could not be found",),
    ),
    Provider(
        "Statuspage",
        ("statuspage.io",),
        ("this page is either not public or does not exist",),
    ),
    Provider(
        "Webflow",
        ("webflow.io",),
        ("this site has been disabled",),
    ),
    Provider(
        "Surge",
        ("surge.sh",),
        ("project not found",),
    ),
    Provider(
        "Bitbucket Cloud",
        ("bitbucket.io",),
        ("repository not found",),
    ),
)


def match_provider(cname: str) -> Provider | None:
    target = cname.lower().rstrip(".")
    for provider in PROVIDERS:
        for suffix in provider.suffixes:
            if target == suffix or target.endswith("." + suffix):
                return provider
    return None


def _marker(body: str, provider: Provider) -> str | None:
    lowered = body[:300000].lower()
    for marker in provider.markers:
        if marker in lowered:
            return marker
    return None


def detect_takeovers(
    probes: list[Probe],
    resolver: Resolver,
    scopes: list[str],
    max_hosts: int = 60,
) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    attempts: list[dict] = []
    seen: set[str] = set()
    for probe in probes:
        if len(seen) >= max_hosts:
            break
        host = (probe.host or "").lower().rstrip(".")
        if not host or host in seen:
            continue
        if not probe.live or not probe.result or not probe.url:
            continue
        seen.add(host)
        try:
            cnames = resolver.query(host, "CNAME")
        except (OSError, ValueError):
            continue
        if not cnames:
            continue
        cname = cnames[0].lower().rstrip(".")
        provider = match_provider(cname)
        if not provider:
            continue
        if in_scope(cname, scopes):
            continue
        marker = _marker(probe.result.text, provider)
        attempt = {
            "host": host,
            "url": probe.url,
            "cname": cname,
            "provider": provider.name,
            "http_status": probe.result.status,
            "marker": marker,
            "takeover": bool(marker),
        }
        attempts.append(attempt)
        if not marker:
            continue
        findings.append(Finding(
            title=f"Possible subdomain takeover ({provider.name})",
            severity="high",
            category="takeover",
            host=host,
            url=probe.url,
            description=(
                f"The host has a CNAME to {cname} and the response contains "
                f"{provider.name}'s unclaimed-resource marker. If the provider "
                "resource is still unclaimed, an unrelated party could serve "
                "content on this hostname."
            ),
            remediation=(
                "Remove the dangling CNAME or reclaim the provider resource. "
                "Do not attempt to claim it yourself; confirm ownership first."
            ),
            evidence=(
                f"CNAME: {host} -> {cname}\n"
                f"HTTP status: {probe.result.status}\n"
                f"Provider marker: {marker}"
            ),
            confidence=CONFIDENCE_MANUAL,
            verified=False,
            verification=(
                "dangling CNAME and provider not-found page observed; "
                "claimability was not tested"
            ),
            poc=[
                f"dig +short CNAME {host}",
                f"curl -sS -o /dev/null -w '%{{http_code}}\\n' {probe.url}",
            ],
        ))
    meta = {
        "enabled": True,
        "hosts_checked": len(seen),
        "candidates": attempts,
        "takeovers": len(findings),
        "note": (
            "A candidate requires a third-party CNAME plus that provider's "
            "unclaimed-resource page. Claimability must be verified manually."
        ),
    }
    return findings, meta
