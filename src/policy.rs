//! Static policy engine (Phase 2).
//!
//! A policy is a set of declarative rules evaluated against a runtime
//! `Snapshot` (process tree + connections + fs events). The engine is pure:
//! given a snapshot and a policy it returns a `Verdict` with reasons. No I/O,
//! no platform code — that's what makes it unit-testable without a live agent.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::{net::Connection, Process};

/// A runtime observation the policy is scored against.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub pid: u32,
    pub tree: Option<Process>,
    pub connections: Vec<Connection>,
    pub fs_events: Vec<FsEvent>,
}

/// A filesystem write the observer recorded (path + whether it looks sensitive).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FsEvent {
    pub pid: u32,
    pub path: String,
    pub sensitive: bool,
}

/// One declarative rule. Matching is monotonic: any match contributes its
/// severity to the verdict.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Rule {
    /// Human label shown in `reasons`.
    pub name: String,
    /// Severity this rule contributes.
    #[serde(default)]
    pub severity: Severity,
    /// Connection to a non-private (external) IP.
    #[serde(default)]
    pub external_connection: bool,
    /// Substring that, if present in any connection's remote address, flags it.
    #[serde(default)]
    pub remote_contains: Option<String>,
    /// Any sensitive fs write by the watched tree.
    #[serde(default)]
    pub sensitive_write: bool,
    /// Process name (substring, case-insensitive) seen anywhere in the tree.
    #[serde(default)]
    pub process_name_contains: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Deny,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Warn
    }
}

impl Severity {
    fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Warn => 1,
            Severity::Deny => 2,
        }
    }
}

/// A policy is an ordered list of rules. The highest severity that matches
/// wins; `reasons` lists every matched rule.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Policy {
    pub rules: Vec<Rule>,
}

/// The engine's decision.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Verdict {
    pub action: Action,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Flag,
    Deny,
}

impl Policy {
    /// Evaluate a snapshot. Pure and total.
    pub fn evaluate(&self, snap: &Snapshot) -> Verdict {
        let mut top = Severity::Info;
        let mut reasons = Vec::new();

        // Gather names present anywhere in the tree once.
        let mut names = Vec::new();
        if let Some(t) = &snap.tree {
            t.walk(&mut |p| names.push(p.name.to_lowercase()));
        }

        for rule in &self.rules {
            let mut matched = false;

            if rule.external_connection && has_external(&snap.connections) {
                matched = true;
            }
            if let Some(sub) = &rule.remote_contains {
                if snap
                    .connections
                    .iter()
                    .any(|c| c.remote_addr.to_lowercase().contains(&sub.to_lowercase()))
                {
                    matched = true;
                }
            }
            if rule.sensitive_write && snap.fs_events.iter().any(|e| e.sensitive) {
                matched = true;
            }
            if let Some(sub) = &rule.process_name_contains {
                if names.iter().any(|n| n.contains(&sub.to_lowercase())) {
                    matched = true;
                }
            }

            if matched {
                reasons.push(rule.name.clone());
                if rule.severity.rank() > top.rank() {
                    top = rule.severity;
                }
            }
        }

        let action = match top {
            Severity::Info => Action::Allow,
            Severity::Warn => Action::Flag,
            Severity::Deny => Action::Deny,
        };
        Verdict { action, reasons }
    }
}

/// True if any connection reaches a non-private (external) IP.
pub fn has_external(conns: &[Connection]) -> bool {
    conns.iter().any(|c| {
        if let Some(ip) = c.remote_addr.split(':').next().and_then(|s| s.parse::<IpAddr>().ok()) {
            !is_private(ip)
        } else {
            false
        }
    })
}

/// RFC1918 + loopback + link-local classification.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || o[0] == 127
                || o[0] == 169 && o[1] == 254
                || o[0] == 172 && (o[1] >= 16 && o[1] <= 31)
                || o[0] == 192 && o[1] == 168
        }
        IpAddr::V6(_) => ip.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Connection;

    fn conn(remote: &str, pid: u32) -> Connection {
        Connection {
            pid,
            local_addr: "0.0.0.0:0".into(),
            remote_addr: remote.into(),
            state: "ESTABLISHED".into(),
        }
    }

    #[test]
    fn external_connection_triggers_deny() {
        let policy = Policy {
            rules: vec![Rule {
                name: "no external egress".into(),
                severity: Severity::Deny,
                external_connection: true,
                ..Default::default()
            }],
        };
        let snap = Snapshot {
            pid: 1,
            tree: None,
            connections: vec![conn("32.195.92.226:443", 1)],
            fs_events: vec![],
        };
        let v = policy.evaluate(&snap);
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.reasons, vec!["no external egress"]);
    }

    #[test]
    fn private_connection_is_allowed() {
        let policy = Policy {
            rules: vec![Rule {
                name: "no external egress".into(),
                severity: Severity::Deny,
                external_connection: true,
                ..Default::default()
            }],
        };
        let snap = Snapshot {
            pid: 1,
            tree: None,
            connections: vec![conn("192.168.0.1:443", 1)],
            fs_events: vec![],
        };
        assert_eq!(policy.evaluate(&snap).action, Action::Allow);
    }

    #[test]
    fn remote_contains_substring_flags() {
        let policy = Policy {
            rules: vec![Rule {
                name: "blocked host".into(),
                severity: Severity::Deny,
                remote_contains: Some("evil.example".into()),
                ..Default::default()
            }],
        };
        let snap = Snapshot {
            pid: 1,
            tree: None,
            connections: vec![conn("evil.example:443", 1)],
            fs_events: vec![],
        };
        assert_eq!(policy.evaluate(&snap).action, Action::Deny);
    }

    #[test]
    fn sensitive_write_flags() {
        let policy = Policy {
            rules: vec![Rule {
                name: "no cred write".into(),
                severity: Severity::Deny,
                sensitive_write: true,
                ..Default::default()
            }],
        };
        let snap = Snapshot {
            pid: 1,
            tree: None,
            connections: vec![],
            fs_events: vec![FsEvent {
                pid: 1,
                path: "C:\\Users\\x\\.env".into(),
                sensitive: true,
            }],
        };
        assert_eq!(policy.evaluate(&snap).action, Action::Deny);
    }

    #[test]
    fn process_name_rule_matches_tree() {
        let policy = Policy {
            rules: vec![Rule {
                name: "known bad binary".into(),
                severity: Severity::Deny,
                process_name_contains: Some("cheatengine".into()),
                ..Default::default()
            }],
        };
        let mut root = Process {
            pid: 1,
            parent_pid: 0,
            name: "agent.exe".into(),
            children: vec![],
        };
        root.children.push(Process {
            pid: 2,
            parent_pid: 1,
            name: "CheatEngine.exe".into(),
            children: vec![],
        });
        let snap = Snapshot {
            pid: 1,
            tree: Some(root),
            connections: vec![],
            fs_events: vec![],
        };
        assert_eq!(policy.evaluate(&snap).action, Action::Deny);
    }

    #[test]
    fn empty_policy_allows() {
        let snap = Snapshot {
            pid: 1,
            tree: None,
            connections: vec![conn("8.8.8.8:53", 1)],
            fs_events: vec![],
        };
        assert_eq!(Policy::default().evaluate(&snap).action, Action::Allow);
    }
}
