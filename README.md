# Sentinel

> An anti-cheat engine for AI agents. Runtime behavioral guard — not a prompt filter.

The industry ships prompt-level filters. The real attacks against autonomous
agents — prompt injection → silent exfiltration, tool-output poisoning,
agent hijack — live in **runtime behavior**, not text. Sentinel applies
anti-cheat / EDR discipline to agents: it watches an agent's process tree,
network, and filesystem at runtime and enforces a policy, with a kill-switch.

This is a work in progress. What exists today is the **Phase 0 spike**: a
cross-platform process-tree observer that proves we can map, from any running
agent's PID, every process it has spawned.

## Status

| Phase | Scope | State |
|-------|-------|-------|
| 0 — Spike | Cross-platform process-tree enumeration (Windows + Linux) | ✅ done, tests green |
| 1 — MVP | Network + filesystem observation, static policy, Python adapter, dashboard w/ kill-switch | 🟡 next |
| 2 — v1 | Behavioral anomaly baseline, session replay, auto-containment, multi-agent | ⚪ planned |
| 3 — stretch | ML anomaly detection, autonomous red-team loop, eBPF/Win32 parity | ⚪ planned |

## What the code does (today)

`tree_for(pid)` returns the full process subtree rooted at `pid`, on both
Windows and Linux, behind one API:

```rust
use sentinel::tree_for;

let pid = std::process::id();
let tree = tree_for(pid).expect("current pid should be observable");
println!("this agent spawned {} process(es) total", tree.size());
tree.walk(&mut |p| println!("  pid {}: {}", p.pid, p.name));
```

- **Windows** — `CreateToolhelp32Snapshot` + `Process32First/Next` (user-mode,
  no admin). Process names resolved via `K32EnumProcessModules`.
- **Linux/macOS** — `/proc/<pid>/status` parsing (`PPid`, `Name`).
- The watchdog (`ProcessTree::all()`) enumerates the whole host forest.

The same primitive an anti-cheat engine uses to map a target is the first
thing a runtime guard needs before it can watch what an agent *does*.

## Build & test

```bash
cargo build
cargo test      # 3 tests, green on Windows + Linux
```

Requires Rust 1.74+. On Windows, the `windows-sys` feature set pulls the
Toolhelp + Process Status APIs.

## Architecture (target)

```
sentinel-observer   (Rust)  — process/network/fs observation  ◀ today: process tree
sentinel-policy     (Rust)  — declarative rules + anomaly baseline → ALLOW/DENY/FLAG
sentinel-agent      (Py)    — wraps an agent's tool-call layer, enforces verdicts
sentinel-dash       (Next)  — live threat graph, kill-switch, session replay
```

Local heuristic scoring uses a Qwen 3B model served via `llama_cpp.server`.

## Principles

- **Real before pretty.** Every module ships compiling and tested.
- **Runtime, not text.** Behavior is the attack surface.
- **Gold-only.** No committed databases, configs, or boilerplate.

## License

MIT.
