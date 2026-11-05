"""Decoy, canary, and test-credential heuristics.

These helpers never change what was observed. They mark findings that a bug
bounty program may have planted on purpose (honeytokens, decoy pages) or that
carry a test/publishable credential, so the report does not present them as a
confirmed vulnerability.
"""

from __future__ import annotations

import re

DECOY_MARKERS = (
    (re.compile(r"(?i)\bhoney ?pot\b"), "response mentions a honeypot"),
    (re.compile(r"(?i)\bhoney ?token\b"), "response mentions a honeytoken"),
    (re.compile(r"(?i)\bcanary ?token\b"), "response mentions a canary token"),
    (re.compile(r"(?i)\bdecoy\b"), "response mentions a decoy"),
    (re.compile(r"(?i)you (?:have|'ve) been (?:caught|logged|recorded)"),
     "response claims the requester was recorded"),
    (re.compile(r"(?i)\bdo not report\b"), "response says not to report it"),
    (re.compile(r"(?i)\b(?:fake|dummy) (?:credential|secret|data|account)\b"),
     "response labels the data as fake"),
    (re.compile(r"(?i)\bsecurity (?:test|exercise) (?:page|target)\b"),
     "response identifies itself as a security test"),
)

# Values that are designed to be public or that only work against a test API.
TEST_VALUE_MARKERS = (
    (re.compile(r"^sk_test_"), "Stripe test secret key (no live payment impact)"),
    (re.compile(r"^pk_(?:live|test)_"), "Stripe publishable key (public by design)"),
    (re.compile(r"^rzp_test_"), "Razorpay test key (no live payment impact)"),
    (re.compile(r"^test_|_test$"), "test-scoped credential"),
    (re.compile(r"(?i)^(?:sandbox|dummy|fake)_"), "sandbox/dummy credential"),
)

SECRET_SEVERITY_OVERRIDE = {
    "Stripe test secret key (no live payment impact)": "info",
    "Stripe publishable key (public by design)": "info",
    "Razorpay test key (no live payment impact)": "info",
    "test-scoped credential": "low",
    "sandbox/dummy credential": "info",
}


def markers(text: str) -> list[str]:
    """Return decoy/canary markers present in a response body."""
    if not text:
        return []
    head = text[:200000]
    found: list[str] = []
    for pattern, reason in DECOY_MARKERS:
        if pattern.search(head) and reason not in found:
            found.append(reason)
    return found


def classify_credential(value: str) -> tuple[str | None, str]:
    """Return (severity override, reason) for test/publishable credentials."""
    if not value:
        return None, ""
    for pattern, reason in TEST_VALUE_MARKERS:
        if pattern.search(value):
            return SECRET_SEVERITY_OVERRIDE.get(reason), reason
    return None, ""
