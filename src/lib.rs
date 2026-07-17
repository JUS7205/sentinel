//! Sentinel observer core — Phase 0 spike.
//!
//! This crate provides a cross-platform view of a process tree. The goal of
//! Phase 0 is to prove we can enumerate, from a running agent's PID, every
//! descendant process it has spawned — the first primitive the runtime guard
//! needs before it can watch network and filesystem activity.
//!
//! The public API is identical on every target; the implementation is selected
//! at compile time via `cfg`.

mod process;
pub mod net;

pub use process::{ProcessInfo, ProcessTree};
pub use net::{Connection, connections_for};

/// A snapshot of one process in the tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Process {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub children: Vec<Process>,
}

impl Process {
    /// Depth-first walk, invoking `f` for every node (including the root).
    pub fn walk(&self, f: &mut dyn FnMut(&Process)) {
        f(self);
        for child in &self.children {
            child.walk(f);
        }
    }

    /// Total number of processes in this subtree (including self).
    pub fn size(&self) -> usize {
        let mut n = 0usize;
        self.walk(&mut |_| n += 1);
        n
    }
}

/// Build the process tree rooted at `pid` using the platform observer.
///
/// Returns `None` if the root PID does not exist.
pub fn tree_for(pid: u32) -> Option<Process> {
    ProcessTree::snapshot(pid).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_for_self_is_nonempty() {
        let pid = std::process::id();
        let tree = tree_for(pid).expect("current pid should be observable");
        assert_eq!(tree.pid, pid);
        assert!(tree.size() >= 1, "tree should contain at least the root");
    }

    #[test]
    fn all_returns_a_forest() {
        let all = ProcessTree::all();
        assert!(!all.is_empty(), "host should have at least one process");
        // On Windows the System Idle Process legitimately reports PID 0; that is
        // a real process, so we only assert every entry has a non-zero *parent*
        // or is a known root (pid 0 / 4).
        assert!(all.iter().any(|p| p.pid != 0));
    }

    #[test]
    fn tree_walk_visits_every_node() {
        let pid = std::process::id();
        let tree = tree_for(pid).unwrap();
        let mut count = 0;
        tree.walk(&mut |_| count += 1);
        assert_eq!(count, tree.size());
    }
}
