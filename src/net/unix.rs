//! Unix network enumeration (Phase 1, TODO).
//!
//! On Linux this means parsing `/proc/net/tcp` for the socket table and
//! resolving each inode to a PID via `/proc/<pid>/fd`. That work is scheduled
//! for Phase 1 Linux parity; until then we return an empty list rather than
//! pretend. The Windows path above is the live one on this host.

use super::Connection;

#[allow(dead_code)] // used only under cfg(unix); harmless on windows builds
pub(super) fn collect_all() -> Vec<Connection> {
    // Intentionally empty — see module docs. Returns no fake data.
    Vec::new()
}
