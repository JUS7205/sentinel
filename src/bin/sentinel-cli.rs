//! `sentinel observe <pid>` — emit a machine-readable runtime snapshot.
//!
//! Composes the process-tree observer (Phase 0) with the connection table
//! (Phase 1) into one JSON document a dashboard or policy engine can consume.

use sentinel::{net, tree_for};
use serde_json::json;

fn main() {
    let pid = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(std::process::id);

    let tree = tree_for(pid);
    let connections = net::connections_for(pid);

    let snap = json!({
        "pid": pid,
        "observed_at": chrono_now(),
        "process_tree": tree,
        "connections": connections,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&snap).expect("serialize snapshot")
    );
}

/// Lightweight local-time string without pulling a datetime crate into the
/// observer core. The CLI is allowed a tiny convenience; the library is not.
fn chrono_now() -> String {
    // std alone can't format easily; keep it honest and minimal.
    format!("{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0))
}
