"""Policy engine tests — a 1:1 mirror of the Rust unit tests in
sentinel/src/policy.rs, plus JSON-roundtrip coverage."""

import json

import pytest

from agent.policy import Action, Policy, Rule, Severity, Verdict, evaluate
from agent.snapshot import Connection, FsEvent, Process, Snapshot


def conn(remote: str, pid: int = 1) -> Connection:
    return Connection(pid=pid, local_addr="0.0.0.0:0", remote_addr=remote, state="ESTABLISHED")


def snapshot(tree=None, connections=None, fs_events=None) -> Snapshot:
    return Snapshot(pid=1, tree=tree, connections=connections or [], fs_events=fs_events or [])


def test_external_connection_triggers_deny():
    policy = Policy(
        rules=[Rule(name="no external egress", severity=Severity.DENY, external_connection=True)]
    )
    verdict = evaluate(policy, snapshot(connections=[conn("32.195.92.226:443")]))
    assert verdict.action == Action.DENY
    assert verdict.reasons == ["no external egress"]


def test_private_connection_is_allowed():
    policy = Policy(
        rules=[Rule(name="no external egress", severity=Severity.DENY, external_connection=True)]
    )
    verdict = evaluate(policy, snapshot(connections=[conn("192.168.0.1:443")]))
    assert verdict.action == Action.ALLOW


def test_remote_contains_substring_flags():
    policy = Policy(
        rules=[Rule(name="blocked host", severity=Severity.DENY, remote_contains="evil.example")]
    )
    verdict = evaluate(policy, snapshot(connections=[conn("evil.example:443")]))
    assert verdict.action == Action.DENY


def test_sensitive_write_flags():
    policy = Policy(rules=[Rule(name="no cred write", severity=Severity.DENY, sensitive_write=True)])
    fs = [FsEvent(pid=1, path=r"C:\Users\x\.env", sensitive=True)]
    verdict = evaluate(policy, snapshot(fs_events=fs))
    assert verdict.action == Action.DENY


def test_process_name_rule_matches_tree():
    policy = Policy(
        rules=[Rule(name="known bad binary", severity=Severity.DENY, process_name_contains="cheatengine")]
    )
    root = Process(pid=1, parent_pid=0, name="agent.exe")
    root.children.append(Process(pid=2, parent_pid=1, name="CheatEngine.exe"))
    verdict = evaluate(policy, snapshot(tree=root))
    assert verdict.action == Action.DENY


def test_empty_policy_allows():
    verdict = evaluate(Policy(), snapshot(connections=[conn("8.8.8.8:53")]))
    assert verdict.action == Action.ALLOW


def test_highest_severity_wins():
    policy = Policy(
        rules=[
            Rule(name="watch", severity=Severity.WARN, external_connection=True),
            Rule(name="block", severity=Severity.DENY, sensitive_write=True),
        ]
    )
    fs = [FsEvent(pid=1, path=r"C:\Users\x\.env", sensitive=True)]
    verdict = evaluate(policy, snapshot(connections=[conn("8.8.8.8:53")], fs_events=fs))
    assert verdict.action == Action.DENY
    assert verdict.reasons == ["watch", "block"]


def test_policy_json_roundtrip_matches_rust_schema():
    raw = json.dumps(
        {
            "rules": [
                {"name": "no external egress from agent", "severity": "deny", "external_connection": True},
                {"name": "credential write", "severity": "deny", "sensitive_write": True},
            ]
        }
    )
    policy = Policy.from_json(raw)
    assert len(policy.rules) == 2
    assert policy.rules[0].severity == Severity.DENY
    verdict = evaluate(policy, snapshot(fs_events=[FsEvent(pid=1, path=".env", sensitive=True)]))
    assert verdict.action == Action.DENY


def test_policy_deny_json_evaluates_demo_snapshot():
    policy = Policy.from_file("policy.deny.json")
    snap = Snapshot(
        pid=1337,
        tree=Process(pid=1337, name="agent.exe"),
        connections=[conn("45.83.192.12:443", pid=1337)],
        fs_events=[FsEvent(pid=1337, path=r"C:\Users\agent\.env", sensitive=True)],
    )
    verdict = evaluate(policy, snap)
    assert verdict.action == Action.DENY
    assert "blocklist host" not in verdict.reasons  # no evil.example here


def test_verdict_shape():
    policy = Policy(rules=[Rule(name="x", severity=Severity.WARN, external_connection=True)])
    verdict = evaluate(policy, snapshot(connections=[conn("8.8.8.8:53")]))
    assert isinstance(verdict, Verdict)
    assert verdict.action == Action.FLAG
    assert "x" in verdict.reasons
