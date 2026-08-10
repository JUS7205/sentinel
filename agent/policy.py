"""Declarative policy engine — a 1:1 Python port of sentinel/src/policy.rs.

A policy is a set of rules evaluated against a runtime `Snapshot`. Matching is
monotonic (any match contributes its severity); the highest severity wins.
The engine is pure: a Snapshot and a Policy in, a Verdict out. No I/O, no
platform code — that is what makes it unit-testable without a live agent.
"""

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    INFO = "info"
    WARN = "warn"
    DENY = "deny"


class Action(Enum):
    ALLOW = "allow"
    FLAG = "flag"
    DENY = "deny"


_RANK = {Severity.INFO: 0, Severity.WARN: 1, Severity.DENY: 2}


@dataclass
class Rule:
    """One declarative rule. Mirrors the Rust `Rule` struct."""

    name: str
    severity: Severity = Severity.WARN
    external_connection: bool = False
    remote_contains: Optional[str] = None
    sensitive_write: bool = False
    process_name_contains: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(
            name=d.get("name", ""),
            severity=Severity(d.get("severity", "warn")),
            external_connection=bool(d.get("external_connection", False)),
            remote_contains=d.get("remote_contains"),
            sensitive_write=bool(d.get("sensitive_write", False)),
            process_name_contains=d.get("process_name_contains"),
        )


@dataclass
class Policy:
    """An ordered list of rules. The highest severity that matches wins."""

    rules: List[Rule] = field(default_factory=list)

    @classmethod
    def from_json(cls, raw: str) -> "Policy":
        import json

        return cls.from_dict(json.loads(raw))

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        return cls(rules=[Rule.from_dict(r) for r in d.get("rules", [])])

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        with open(path, encoding="utf-8-sig") as fh:
            return cls.from_json(fh.read())


@dataclass
class Verdict:
    """The engine's decision."""

    action: Action
    reasons: List[str]


def is_private(remote: str) -> bool:
    """RFC1918 + loopback + link-local classification (port of the Rust helper)."""
    host = remote.rsplit(":", 1)[0].strip("[]") if ":" in remote else remote
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 4:
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
        )
    return ip.is_loopback or ip.is_private


def has_external(connections: List["Connection"]) -> bool:
    """True if any connection reaches a non-private (external) address."""
    return any(not is_private(c.remote_addr) for c in connections)


def evaluate(policy: Policy, snapshot: "Snapshot") -> Verdict:
    """Evaluate a snapshot against a policy. Pure and total."""
    top = Severity.INFO
    reasons: List[str] = []

    names: List[str] = []
    if snapshot.tree is not None:
        snapshot.tree.walk(lambda p: names.append(p.name.lower()))

    for rule in policy.rules:
        matched = False

        if rule.external_connection and has_external(snapshot.connections):
            matched = True
        if rule.remote_contains is not None:
            sub = rule.remote_contains.lower()
            if any(sub in c.remote_addr.lower() for c in snapshot.connections):
                matched = True
        if rule.sensitive_write and any(e.sensitive for e in snapshot.fs_events):
            matched = True
        if rule.process_name_contains is not None:
            sub = rule.process_name_contains.lower()
            if any(sub in n for n in names):
                matched = True

        if matched:
            reasons.append(rule.name)
            if _RANK[rule.severity] > _RANK[top]:
                top = rule.severity

    action = {
        Severity.INFO: Action.ALLOW,
        Severity.WARN: Action.FLAG,
        Severity.DENY: Action.DENY,
    }[top]
    return Verdict(action=action, reasons=reasons)
