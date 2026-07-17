//! Unix (Linux/macOS) process enumeration via `/proc`.
//!
//! On Linux every process exposes `/proc/<pid>/stat` and `/proc/<pid>/status`.
//! We parse `PPid` from `status` and the comm from `stat`. This is the
//! user-mode primitive; the eBPF path (Phase 2+) will supersede it for
//! live syscall tracing.

use crate::process::ProcessInfo;
use std::fs;

pub(super) fn collect_all() -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return out,
    };
    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let name = fname.to_string_lossy();
        // Only numeric entries are processes.
        if name.chars().any(|c| !c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let (ppid, comm) = match read_proc(pid) {
            Some(v) => v,
            None => continue,
        };
        out.push(ProcessInfo {
            pid,
            parent_pid: ppid,
            name: comm,
        });
    }
    out
}

fn read_proc(pid: u32) -> Option<(u32, String)> {
    // `/proc/<pid>/status` has `PPid:\t<num>` and `Name:\t<comm>`.
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let mut ppid = 0u32;
    let mut comm = String::new();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Name:") {
            comm = rest.trim().to_string();
        }
    }
    if comm.is_empty() {
        comm = format!("<pid {}>", pid);
    }
    Some((ppid, comm))
}
