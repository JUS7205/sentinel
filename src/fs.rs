//! Filesystem observation (Phase 2).
//!
//! The runtime guard needs to know when an agent *writes* — to a credentials
//! file, a temp drop, or outside its sandbox. Enumerating another process's
//! open handles requires undocumented APIs, so instead we watch a set of
//! *watched paths* and report writes since a baseline. The diff logic is pure
//! and unit-tested against synthetic file metadata; the `scan_dir` collector
//! is the only place that touches the OS.

use serde::Serialize;
use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::policy::FsEvent;

/// One recorded file state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileState {
    pub path: String,
    pub size: u64,
    pub modified_secs: u64,
}

/// A baseline over a set of paths, captured at one instant.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub files: Vec<FileState>,
}

/// Extensions / names we treat as sensitive (credential, secret, archive drop).
const SENSITIVE_EXTS: &[&str] = &["env", "key", "pem", "pfx", "p12", "kdbx", "ago", "db"];
const SENSITIVE_NAMES: &[&str] = &["id_rsa", ".env", ".git-credentials", "token", "secret"];

/// True if a path looks like a credentials/secret drop.
pub fn is_sensitive(path: &str) -> bool {
    let p = Path::new(path);
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    // A dotfile like `.env` has no extension(); treat its full name as a stem.
    if SENSITIVE_NAMES.iter().any(|n| name == *n || name.contains(n)) {
        return true;
    }
    if let Some(ext) = p.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()) {
        return SENSITIVE_EXTS.contains(&ext.as_str());
    }
    false
}

/// Collect file states under `roots` (non-recursive by default; recursive if
/// `recursive`). Missing/unreadable paths are skipped silently.
pub fn scan_dir(roots: &[String], recursive: bool) -> Vec<FileState> {
    let mut out = Vec::new();
    for root in roots {
        let p = Path::new(root);
        if !p.exists() {
            continue;
        }
        collect(p, recursive, &mut out);
    }
    out
}

fn collect(dir: &Path, recursive: bool, out: &mut Vec<FileState>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if path.is_dir() {
            if recursive {
                collect(&path, recursive, out);
            }
            continue;
        }
        if let Ok(meta) = ent.metadata() {
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.push(FileState {
                path: path.to_string_lossy().replace('\\', "/"),
                size: meta.len(),
                modified_secs: modified,
            });
        }
    }
}

/// Diff a baseline against a fresh scan. Returns events for files that are new
/// or modified (size or mtime changed). `pid` is attributed to each event.
pub fn diff(baseline: &Baseline, fresh: &[FileState], pid: u32) -> Vec<FsEvent> {
    let mut events = Vec::new();
    let prev: std::collections::HashMap<&str, &FileState> = baseline
        .files
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect();
    for f in fresh {
        let changed = match prev.get(f.path.as_str()) {
            None => true, // new file
            Some(old) => old.size != f.size || old.modified_secs != f.modified_secs,
        };
        if changed {
            events.push(FsEvent {
                pid,
                path: f.path.clone(),
                sensitive: is_sensitive(&f.path),
            });
        }
    }
    events
}

impl Baseline {
    pub fn from_files(files: Vec<FileState>) -> Self {
        Baseline { files }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitivity_classification() {
        assert!(is_sensitive("C:/x/.env"));
        assert!(is_sensitive("key.pem"));
        assert!(is_sensitive("id_rsa"));
        assert!(!is_sensitive("readme.md"));
        assert!(!is_sensitive("image.png"));
    }

    #[test]
    fn diff_detects_new_and_modified() {
        let base = Baseline::from_files(vec![
            FileState { path: "a.txt".into(), size: 10, modified_secs: 100 },
            FileState { path: "b.txt".into(), size: 20, modified_secs: 100 },
        ]);
        let fresh = vec![
            FileState { path: "a.txt".into(), size: 10, modified_secs: 100 }, // unchanged
            FileState { path: "b.txt".into(), size: 25, modified_secs: 200 }, // modified
            FileState { path: "c.txt".into(), size: 5, modified_secs: 300 },  // new
        ];
        let ev = diff(&base, &fresh, 7);
        assert_eq!(ev.len(), 2);
        assert!(ev.iter().all(|e| e.pid == 7));
        assert!(ev.iter().any(|e| e.path == "b.txt"));
        assert!(ev.iter().any(|e| e.path == "c.txt"));
    }

    #[test]
    fn diff_marks_sensitive_write() {
        let base = Baseline::default();
        let fresh = vec![FileState {
            path: "C:/x/.env".into(),
            size: 1,
            modified_secs: 1,
        }];
        let ev = diff(&base, &fresh, 1);
        assert_eq!(ev.len(), 1);
        assert!(ev[0].sensitive);
    }

    #[test]
    fn scan_dir_recursive_finds_files() {
        let tmp = std::env::temp_dir().join("sentinel_fs_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("sub")).unwrap();
        std::fs::write(tmp.join("top.txt"), b"x").unwrap();
        std::fs::write(tmp.join("sub/deep.env"), b"secret").unwrap();
        let roots = vec![tmp.to_string_lossy().replace('\\', "/")];
        let files = scan_dir(&roots, true);
        assert!(files.iter().any(|f| f.path.ends_with("top.txt")));
        assert!(files.iter().any(|f| f.path.ends_with("deep.env")));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
