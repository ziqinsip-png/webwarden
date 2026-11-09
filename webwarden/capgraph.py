"""Capability graph: automatic multi-hop chains over observed findings.

The hand-written rules in :mod:`chains` describe specific pairs with their
nuance. This module adds the general case: every finding *provides*
capabilities, and a rule becomes usable only when its ``needs`` are already on
the path. That is what lets three ordinary findings (cross-account read,
reflection, weak cookie) become one account-takeover path without a rule
written for that exact trio.

Only paths of three or more links are emitted; two-link combinations are
already covered by the explicit rules and would otherwise duplicate them.
"""

from __future__ import annotations

import hashlib

from .chains import (BOUNDARY_NOTE, Chain, _chain, _link, _read_only,
                     _with_severity)
from .models import Finding

CAPS_BY_CATEGORY: dict[str, frozenset[str]] = {
    "access-control": frozenset({"data.read.other_user"}),
    "access-control-bypass": frozenset({"http.read.unauthenticated"}),
    "cors": frozenset({"http.read.unauthenticated"}),
    "cookies": frozenset({"session.cookie.readable"}),
    "xss": frozenset({"js.exec.origin"}),
    "sqli": frozenset({"db.read", "db.schema"}),
    "ssti": frozenset({"server.template.eval"}),
    "lfi": frozenset({"file.read"}),
    "ssrf": frozenset({"internal.reach"}),
    "backdoor": frozenset({"server.exec"}),
    "secrets": frozenset({"credential.obtain"}),
    "tokens": frozenset({"credential.obtain"}),
    "exposure": frozenset({"config.read"}),
    "redirect": frozenset({"nav.redirect.attacker"}),
    "crlf": frozenset({"header.injection"}),
    "takeover": frozenset({"domain.claim"}),
}

IMPACT_GAINS = frozenset({
    "data.exfil", "account.takeover", "server.exec", "credential.obtain",
    "data.read.other_user", "config.read",
})


class GraphRule:
    """A directed edge: usable only when ``needs`` already exist on the path."""

    __slots__ = ("name", "sources", "target", "needs", "gains", "title",
                 "summary", "impact", "severity")

    def __init__(self, name: str, sources: set[str], target: str,
                 needs: set[str], gains: set[str], title: str, summary: str,
                 impact: str, severity: str) -> None:
        self.name = name
        self.sources = frozenset(sources)
        self.target = target
        self.needs = frozenset(needs)
        self.gains = frozenset(gains)
        self.title = title
        self.summary = summary
        self.impact = impact
        self.severity = severity


RULES: tuple[GraphRule, ...] = (
    GraphRule(
        "other-user-data->script",
        sources={"access-control"},
        target="xss",
        needs={"data.read.other_user"},
        gains={"data.exfil"},
        title="Another user's data is reachable and can be rendered as script",
        summary=(
            "An object read that ignores the caller is combined with a "
            "reflection on the same host: the data can be rendered inside a "
            "victim session and read back by the injected markup."),
        impact=(
            "An attacker who controls the link can read the other account's "
            "data in the victim's browser instead of only in their own."),
        severity="high",
    ),
    GraphRule(
        "cross-origin-read->script",
        sources={"cors", "access-control-bypass"},
        target="xss",
        needs={"http.read.unauthenticated"},
        gains={"data.exfil"},
        title="Cross-origin readable data can be rendered as script",
        summary=(
            "A response that an arbitrary origin can read is combined with a "
            "reflection on the same host, so a hostile page can both fetch and "
            "render the victim's data."),
        impact=(
            "A hostile page can read the response and drive markup inside the "
            "victim's session on the same origin."),
        severity="high",
    ),
    GraphRule(
        "script->cookie",
        sources={"xss"},
        target="cookies",
        needs={"js.exec.origin"},
        gains={"account.takeover"},
        title="Script on the origin can read the session cookie",
        summary=(
            "Injected markup runs on the same origin as a session cookie that "
            "lacks HttpOnly, so the cookie is readable by script."),
        impact=(
            "Session material leaves the browser; whoever holds it can act as "
            "the user without a password."),
        severity="critical",
    ),
)

def caps_for(finding: Finding) -> frozenset[str]:
    caps = set(CAPS_BY_CATEGORY.get(finding.category.lower(), ()))
    title = finding.title.lower()
    if finding.category == "exposure":
        if "directory listing" in title:
            caps.add("file.read")
        elif "json endpoint" in title:
            caps.add("data.read.other_user")
    return frozenset(caps)


def _node_key(finding: Finding) -> str:
    return f"{finding.category}|{finding.host.lower()}|{finding.url}"


def _eligible(findings: list[Finding]) -> list[Finding]:
    return [item for item in findings if not item.decoy_suspected]


def graph_chains(findings: list[Finding]) -> list[Chain]:
    """Breadth-first over the capability graph, three links or deeper only."""
    nodes = _eligible(findings)
    edges: dict[str, list[tuple[GraphRule, Finding]]] = {}
    for source in nodes:
        for target in nodes:
            if source is target or source.host.lower() != target.host.lower():
                continue
            for rule in RULES:
                if source.category.lower() in rule.sources \
                        and target.category.lower() == rule.target:
                    edges.setdefault(_node_key(source), []).append(
                        (rule, target))

    seen: set[str] = set()
    chains: list[Chain] = []
    for start in nodes:
        queue = [([start], frozenset(caps_for(start)), frozenset(),
                  [start.category])]
        while queue:
            path, caps, gains, kinds = queue.pop(0)
            if len(path) >= 4:
                continue
            for rule, nxt in edges.get(_node_key(path[-1]), ()):
                if any(item.url == nxt.url and item.title == nxt.title
                       for item in path):
                    continue
                if not rule.needs <= caps:
                    continue
                new_caps = caps | caps_for(nxt)
                new_gains = gains | rule.gains
                new_path = path + [nxt]
                new_kinds = kinds + [nxt.category]
                if len(new_path) >= 3 and new_gains & IMPACT_GAINS:
                    signature = "|".join(sorted(new_kinds))
                    if signature not in seen:
                        seen.add(signature)
                        chains.append(_build(new_path, new_gains, rule))
                queue.append((new_path, new_caps, new_gains, new_kinds))
    return chains


def _build(path: list[Finding], gains: frozenset[str], last: GraphRule) -> Chain:
    roles = ["origin"] + ["pivot"] * (len(path) - 2) + ["impact"]
    links = [_with_severity(_link(item, roles[index]), item)
             for index, item in enumerate(path)]
    host = path[0].host.lower()
    digest = hashlib.sha1("|".join(_node_key(item) for item in path).encode())
    return _chain(
        chain_id=f"graph-{host}-{digest.hexdigest()[:8]}",
        title=last.title,
        summary=(
            f"{last.summary} Path: "
            + " -> ".join(item.category for item in path)
            + f". Gains: {', '.join(sorted(gains))}."),
        impact=last.impact,
        links=links,
        proof=[_read_only(item.url) for item in path],
        limitations=(
            BOUNDARY_NOTE + " The steps between links are an inference over "
            "observed findings, so this chain is manual-verification material, "
            "not a demonstrated compromise."),
        hypothesis=True,
    )


__all__ = ["CAPS_BY_CATEGORY", "GraphRule", "RULES", "caps_for",
           "graph_chains"]
