//! Cross-platform process-tree enumeration.
//!
//! The public surface (`ProcessInfo`, `ProcessTree`) is platform-agnostic.
//! The actual collection lives in `windows.rs` / `unix.rs`, selected by `cfg`.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::collect_all;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::collect_all;

/// One row of process metadata, as discovered on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
}

/// Static entry point for the rest of the crate.
pub struct ProcessTree;

impl ProcessTree {
    /// Return a forest (list of roots) of every process currently on the host.
    pub fn all() -> Vec<ProcessInfo> {
        collect_all()
    }

    /// Build the tree rooted at `root_pid`.
    ///
    /// Walks the full host forest, finds `root_pid`, and returns its subtree.
    /// Returns `Ok(None)` when the PID is unknown; `Err` on a collection failure.
    pub fn snapshot(root_pid: u32) -> Result<Option<crate::Process>, String> {
        let all = Self::all();
        let info_by_pid = build_index(&all);

        // Root must exist.
        let root_info = match info_by_pid.get(&root_pid) {
            Some(i) => i.clone(),
            None => return Ok(None),
        };

        // Attach each child to its parent.
        let mut children: std::collections::HashMap<u32, Vec<u32>> =
            std::collections::HashMap::new();
        for info in &all {
            children.entry(info.parent_pid).or_default().push(info.pid);
        }

        let root = build_node(root_pid, &info_by_pid, &children);
        // Sanity: the built root's pid must match.
        if root.pid != root_info.pid {
            return Err("tree construction mismatch".into());
        }
        Ok(Some(root))
    }
}

fn build_index(all: &[ProcessInfo]) -> std::collections::HashMap<u32, ProcessInfo> {
    all.iter().map(|p| (p.pid, p.clone())).collect()
}

fn build_node(
    pid: u32,
    info: &std::collections::HashMap<u32, ProcessInfo>,
    children: &std::collections::HashMap<u32, Vec<u32>>,
) -> crate::Process {
    let meta = info.get(&pid).cloned().unwrap_or(ProcessInfo {
        pid,
        parent_pid: 0,
        name: "<unknown>".into(),
    });
    let kids = children
        .get(&pid)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|c| build_node(c, info, children))
        .collect();
    crate::Process {
        pid: meta.pid,
        parent_pid: meta.parent_pid,
        name: meta.name,
        children: kids,
    }
}
