# sentinel-agent (Phase 3 — Python adapter)

The enforcement half of the Sentinel spine: a Python policy guard that wraps
an agent's tool-call layer and makes `allow` / `flag` / `deny` decisions at
runtime — the Python analogue of the Rust CLI's kill-switch.

The policy engine here is a **1:1 port of the Rust engine** (`src/policy.rs`).
The same policy JSON evaluates identically in both engines: signatures are
data, not code.

## Layout

```text
agent/
  policy.py     # policy engine (port of src/policy.rs) — pure, unit-tested
  snapshot.py   # runtime snapshot model — consumes `sentinel observe` JSON
  guard.py      # AgentGuard: enforcement point + kill-switch hook + decorator
  __main__.py   # CLI: offline enforcement, exit codes 0/1/2
tests/          # 19 tests, green (mirror the Rust unit tests 1:1)
```

## Offline enforcement (deterministic, no live agent)

```bash
# Deny path — exits 2, prints the kill-switch message
python -m agent enforce --demo --policy policy.deny.json

# Allow path — exits 0
python -m agent enforce snapshot.json --policy policy.json
```

Exit codes match `pulse verdict` conventions: `0` = ALLOW, `1` = FLAG,
`2` = DENY. Drop it into CI or a cron as a gate.

## Guarding an agent's tools

```python
from agent.guard import AgentGuard, DeniedError
from agent.policy import Policy
from agent.snapshot import Snapshot

guard = AgentGuard(
    Policy.from_file("policy.deny.json"),
    lambda: Snapshot.from_file("snapshot.json"),   # or a live provider
    kill=lambda snap, verdict: print(f"terminate tree root {snap.pid}"),
)

@guard.guarded(name="send_email")
def send_email(to: str) -> str: ...

try:
    send_email("collector@attacker.com")   # raises DeniedError
except DeniedError:
    ...
```

`flag` verdicts log a warning and let the call proceed; `deny` raises after
the kill-switch hook runs.

## Live snapshots

`agent.guard.LiveSnapshot(watch_pid)` builds a snapshot from `psutil` (process
tree + PID-attributed TCP table). It raises honestly if `psutil` is missing —
no fabricated data, same policy as the Rust observer's platform stubs.

## Tests

```bash
python -m pytest agent/tests -q   # 19 passed
```

The policy tests mirror the Rust unit tests 1:1 (`external_connection` →
deny, private connection → allow, substring host block, sensitive write,
process-name-in-tree, empty policy, severity precedence).
