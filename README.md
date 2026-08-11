# sentinel

[![CI](https://github.com/JUS7205/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/JUS7205/sentinel/actions/workflows/ci.yml)

Runtime guard for AI agents — process tree, network egress, and filesystem
watch with a policy engine and a kill-switch. The thesis: the attacks that
actually land on autonomous agents (prompt injection → silent exfiltration,
tool-output poisoning, agent hijack) happen in **runtime behavior**, not in
the text a prompt filter sees. So this treats the agent the way an
anti-cheat engine treats a game: watch what it does, and stop it when it
violates policy.

I built this after years on the anti-cheat side. The same primitives that
detect a cheater who never touches game memory are the ones an agent guard
needs — observation at the syscall boundary, not after the fact.

## Status

| Phase | Scope | State |
|-------|-------|-------|
| 0 — Spike | Cross-platform process-tree enumeration (Windows + Linux) | done, tests green |
| 1 — Observe | Network connections via `GetExtendedTcpTable`, PID-attributed; `observe` CLI emitting JSON | done, tests green |
| 2 — Enforce | Filesystem watch, static policy engine, `enforce` CLI with Windows kill-switch | done, tests green |
| 3 — MVP | Python agent adapter (`agent/`), guarded tool-calls, dashboard + anomaly baseline | adapter done (19 tests); dashboard + baseline next |
| 4 — v1 | Behavioral anomaly baseline, session replay, auto-containment, multi-agent | planned |
| 5 — stretch | ML anomaly detection, triage copilots, autonomous red-team loop, eBPF/Win32 parity | planned |

Docs: [MITRE ATLAS mapping](docs/atlas.md) · [runtime guard vs prompt filter](docs/runtime-vs-prompt.md) · [agent adapter](agent/README.md)

## What's here today

`tree_for(pid)` returns the full process subtree under one API on Windows and
Linux:

```rust
use sentinel::tree_for;

let pid = std::process::id();
let tree = tree_for(pid).expect("current pid should be observable");
println!("this agent spawned {} process(es) total", tree.size());
tree.walk(&mut |p| println!("  pid {}: {}", p.pid, p.name));
```

- **Windows** — `CreateToolhelp32Snapshot` + `Process32First/Next`, no admin
  required. Names resolved via `K32EnumProcessModules`.
- **Linux/macOS** — `/proc/<pid>/status` parsing (`PPid`, `Name`).
- `ProcessTree::all()` enumerates the whole host forest for the watchdog.

`sentinel observe <pid>` composes the tree with the connection table and
emits a JSON snapshot — connections attributed to owning PIDs via
`GetExtendedTcpTable`, the same call an EDR uses to answer *why is this agent
holding a socket to an unknown host?*

```bash
cargo run --bin sentinel-cli           # observe self
cargo run --bin sentinel-cli <pid>     # observe a target agent
```

`sentinel enforce <pid> --policy policy.json` evaluates a declarative policy
against the live snapshot and, on `deny`, calls `TerminateProcess` on the
watched root. The engine is pure and unit-tested: a `Snapshot` in, a
`Verdict { allow | flag | deny, reasons }` out. Rules are data, not code —
`policy.deny.json` flags external egress, blocklisted hosts, credential
writes, and known-bad binaries. The fs watcher marks credential drops
(`.env`, `id_rsa`, `*.pem`, …) as sensitive.

## Real output

`examples/observe-self.json` is a live run of `sentinel observe` on this
machine (Windows, via `GetExtendedTcpTable`) — not a fixture. On this host it
sees no open sockets for a freshly spawned CLI process, which is honest: a
process that opens none has none reported.

## Build & test

```bash
cargo build
cargo test                        # 15 tests
python -m pytest agent/tests -q   # agent adapter: 19 tests
```

Requires Rust 1.74+. CI runs fmt + clippy + tests on Windows and Linux, plus
the agent's pytest suite.

## Architecture

```mermaid
flowchart LR
  A[Agent process] -->|spawns| B[Process tree]
  A -->|sockets| C[Network egress]
  A -->|writes| D[Filesystem]
  B & C & D --> E[sentinel observe]
  E --> F[sentinel::policy]
  F -->|allow| G[run]
  F -->|flag| H[alert]
  F -->|deny| I([kill-switch: TerminateProcess])
```

```text
sentinel-observer   (Rust)  — process/network/fs observation      ◀ today: all three
sentinel-policy     (Rust)  — declarative rules + anomaly baseline
sentinel-agent      (Py)    — wraps an agent's tool-call layer     ◀ today: `agent/` (Phase 3)
sentinel-dash       (Next)  — live threat graph + kill-switch      ◀ ghostkit
```

Local heuristic scoring uses a Qwen 3B model served via `llama_cpp.server`.

## Known limits (honest list)

- The Linux connection path returns an empty list rather than fabricated data
  — parity is scheduled with Phase 1.
- The kill-switch is Windows-only (`TerminateProcess`) for now.
- `sysmon`-level telemetry (ETW/Win32) is future work; today we read the
  observable surface directly.

## License

Apache-2.0 + Commons Clause. Commercial rights reserved to the copyright
owner — you may use/modify/host it freely for non-commercial purposes and as a
capability showcase, but may not sell it or a product derived from it without a
commercial license (see LICENSE).
