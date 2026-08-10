"""sentinel_agent — Python adapter for the Sentinel runtime guard (Phase 3).

Mirrors the Rust policy engine (src/policy.rs) so a policy JSON file can be
evaluated by either engine: signatures are data, not code.
"""

from .policy import Action, Rule, Severity, Verdict, evaluate
from .snapshot import Connection, FsEvent, Process, Snapshot

__all__ = [
    "Action",
    "Rule",
    "Severity",
    "Verdict",
    "evaluate",
    "Connection",
    "FsEvent",
    "Process",
    "Snapshot",
]
