"""AgentGuard enforcement tests: kill-switch, flag pass-through, decorator."""

import pytest

from agent.guard import AgentGuard, DeniedError
from agent.policy import Action, Policy, Rule, Severity
from agent.snapshot import Connection, Process, Snapshot


def make_guard(policy, snapshot, kill=None):
    return AgentGuard(policy, lambda: snapshot, kill=kill)


def test_deny_raises_and_invokes_kill_switch():
    policy = Policy(
        rules=[Rule(name="no external egress", severity=Severity.DENY, external_connection=True)]
    )
    snap = Snapshot(
        pid=7,
        tree=Process(pid=7, name="agent.exe"),
        connections=[Connection(pid=7, local_addr="10.0.0.5:1234", remote_addr="45.83.192.12:443", state="ESTABLISHED")],
    )
    kills = []
    guard = make_guard(policy, snap, kill=lambda s, v: kills.append(s.pid))
    with pytest.raises(DeniedError):
        guard.check()
    assert kills == [7]
    assert guard.denials == 1


def test_flag_warns_but_allows():
    policy = Policy(
        rules=[Rule(name="watch it", severity=Severity.WARN, external_connection=True)]
    )
    snap = Snapshot(
        pid=7,
        connections=[Connection(pid=7, local_addr="10.0.0.5:1234", remote_addr="8.8.8.8:53", state="ESTABLISHED")],
    )
    guard = make_guard(policy, snap)
    verdict = guard.check()
    assert verdict.action == Action.FLAG
    assert guard.flags == 1
    assert guard.denials == 0


def test_allow_passes_through():
    guard = make_guard(Policy(), Snapshot(pid=7))
    verdict = guard.check()
    assert verdict.action == Action.ALLOW


def test_guarded_decorator_clean_call():
    guard = make_guard(Policy(), Snapshot(pid=7))

    @guard.guarded(name="web_fetch")
    def web_fetch(url: str) -> str:
        return f"fetched {url}"

    assert web_fetch("https://internal.example/doc") == "fetched https://internal.example/doc"


def test_guarded_decorator_denied_call():
    policy = Policy(
        rules=[Rule(name="no external egress", severity=Severity.DENY, external_connection=True)]
    )
    snap = Snapshot(
        pid=7,
        connections=[Connection(pid=7, local_addr="10.0.0.5:1234", remote_addr="45.83.192.12:443", state="ESTABLISHED")],
    )
    guard = make_guard(policy, snap)

    @guard.guarded(name="send_email")
    def send_email(to: str) -> str:
        return f"sent to {to}"

    with pytest.raises(DeniedError):
        send_email("collector@attacker.com")
    assert guard.denials == 1
