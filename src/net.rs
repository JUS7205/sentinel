//! Network connection enumeration (Phase 1).
//!
//! The process tree tells us *what* an agent spawned. The connection table
//! tells us *who it's talking to* — the exfiltration channel. On Windows we use
//! `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)`, the same call a firewall or
//! EDR uses to attribute a socket to a PID.

use serde::Serialize;

/// A single TCP connection attributed to the owning process.
#[derive(Debug, Clone, Serialize)]
pub struct Connection {
    pub pid: u32,
    /// `local_ip:port`
    pub local_addr: String,
    /// `remote_ip:port`
    pub remote_addr: String,
    /// TCP state name (ESTABLISHED, LISTEN, TIME_WAIT, ...)
    pub state: String,
}

/// All IPv4 TCP connections on the host, attributed to PIDs.
pub fn all_connections() -> Vec<Connection> {
    #[cfg(windows)]
    {
        crate::net::windows::collect_all()
    }
    #[cfg(not(windows))]
    {
        crate::net::unix::collect_all()
    }
}

/// Connections owned by a specific PID.
pub fn connections_for(pid: u32) -> Vec<Connection> {
    all_connections()
        .into_iter()
        .filter(|c| c.pid == pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_enumeration_does_not_panic() {
        // A host may legitimately have zero IPv4 TCP sockets, but the call
        // must never panic — that's the contract we rely on in the observer.
        let _ = all_connections();
    }

    #[test]
    fn connections_for_self_is_safe() {
        let pid = std::process::id();
        let v = connections_for(pid);
        assert!(v.iter().all(|c| c.pid == pid));
    }
}

#[cfg(windows)]
mod windows;
#[cfg(unix)]
mod unix;
