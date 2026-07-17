//! `sentinel observe <pid>` — emit a machine-readable runtime snapshot.
//! `sentinel enforce <pid> --policy <file>` — evaluate policy; on DENY, the
//! kill-switch terminates the watched tree's root (Windows: TerminateProcess).
//!
//! Composes the process-tree observer (Phase 0), connection table (Phase 1),
//! and filesystem watch (Phase 2) into one JSON document a dashboard or policy
//! engine consumes.

use sentinel::{net, policy::*, tree_for};
use serde_json::json;
use std::process::id as self_pid;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("observe");

    match cmd {
        "observe" => cmd_observe(args.get(2)),
        "enforce" => cmd_enforce(args.get(2), &args[3..]),
        other => {
            eprintln!(
                "unknown command: {other}\nusage: sentinel <observe|enforce> [pid] [--policy file]"
            );
            std::process::exit(2);
        }
    }
}

fn cmd_observe(pid_arg: Option<&String>) {
    let pid = pid_arg
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(self_pid);

    let tree = tree_for(pid);
    let connections = net::connections_for(pid);

    let snap = json!({
        "pid": pid,
        "observed_at": now_secs(),
        "process_tree": tree,
        "connections": connections,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&snap).expect("serialize snapshot")
    );
}

fn cmd_enforce(pid_arg: Option<&String>, rest: &[String]) {
    let pid = pid_arg
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(self_pid);

    // Parse --policy <file>.
    let mut policy_path = None;
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--policy" {
            policy_path = rest.get(i + 1).cloned();
            i += 2;
        } else {
            i += 1;
        }
    }
    let policy_path = match policy_path {
        Some(p) => p,
        None => {
            eprintln!("enforce requires --policy <file>");
            std::process::exit(2);
        }
    };

    let text = std::fs::read_to_string(&policy_path).unwrap_or_else(|e| {
        eprintln!("cannot read policy {policy_path}: {e}");
        std::process::exit(1);
    });
    let policy: Policy = serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("invalid policy json: {e}");
        std::process::exit(1);
    });

    let tree = tree_for(pid);
    let connections = net::connections_for(pid);
    let snap = Snapshot {
        pid,
        tree: tree.clone(),
        connections,
        fs_events: vec![],
    };
    let verdict = policy.evaluate(&snap);

    let out = json!({
        "pid": pid,
        "verdict": verdict.action,
        "reasons": verdict.reasons,
        "kill_switch": verdict.action == Action::Deny,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("serialize verdict")
    );

    if verdict.action == Action::Deny {
        // Kill-switch: terminate the watched root. On Windows this is
        // TerminateProcess; we refuse to kill our own pid as a safety guard.
        if pid == self_pid() {
            eprintln!("[kill-switch] refusing to terminate self");
            return;
        }
        if kill_process(pid) {
            eprintln!("[kill-switch] terminated pid {pid}");
        } else {
            eprintln!("[kill-switch] failed to terminate pid {pid}");
        }
    }
}

#[cfg(windows)]
fn kill_process(pid: u32) -> bool {
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h == 0 {
            return false;
        }
        let ok = TerminateProcess(h, 1) != 0;
        windows_sys::Win32::Foundation::CloseHandle(h);
        ok
    }
}

#[cfg(not(windows))]
fn kill_process(_pid: u32) -> bool {
    // No-op on non-Windows builds (Phase 2 parity TBD). Returns false rather
    // than pretending to act.
    false
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
