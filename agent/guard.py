"""AgentGuard — the enforcement half of the Phase 3 adapter.

Wraps an agent's tool-call layer. Before every guarded tool call, the guard
refreshes the runtime snapshot, evaluates the policy, and on `deny` raises
`DeniedError` after invoking the kill-switch hook (the Python analogue of the
Rust CLI's `TerminateProcess`). `flag` logs a warning and allows the call;
`allow` passes through untouched.
"""

import functools
import logging
import os
import threading
from typing import Callable, Optional

from .policy import Action, Policy, Verdict, evaluate
from .snapshot import Connection, Process, Snapshot

log = logging.getLogger("sentinel_agent")


class DeniedError(Exception):
    """Raised when the guard denies an action (the kill-switch path)."""


SnapshotProvider = Callable[[], Snapshot]


class AgentGuard:
    """A policy enforcement point in front of an agent's tools."""

    def __init__(
        self,
        policy: Policy,
        snapshot_provider: SnapshotProvider,
        kill: Optional[Callable[[Snapshot, Verdict], None]] = None,
        name: str = "guard",
    ) -> None:
        self.policy = policy
        self.snapshot_provider = snapshot_provider
        self.kill = kill
        self.name = name
        self._lock = threading.Lock()
        self.denials = 0
        self.flags = 0

    def check(self) -> Verdict:
        """Evaluate the current snapshot and enforce the verdict."""
        snapshot = self.snapshot_provider()
        with self._lock:
            verdict = evaluate(self.policy, snapshot)
            if verdict.action == Action.DENY:
                self.denials += 1
                if self.kill is not None:
                    self.kill(snapshot, verdict)
                raise DeniedError(
                    f"{self.name}: denied ({', '.join(verdict.reasons) or 'no reason'})"
                )
            if verdict.action == Action.FLAG:
                self.flags += 1
                log.warning(
                    "%s: flagged (%s)", self.name, ", ".join(verdict.reasons)
                )
            return verdict

    def guarded(self, fn: Optional[Callable] = None, *, name: Optional[str] = None):
        """Decorator: enforce policy before every call of a tool function."""

        def deco(func: Callable) -> Callable:
            tool = name or getattr(func, "__name__", "tool")

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                self.check()
                return func(*args, **kwargs)

            wrapper.__name__ = tool
            return wrapper

        if fn is not None:
            return deco(fn)
        return deco


class LiveSnapshot:
    """Snapshot provider backed by psutil.

    Honest by design: if psutil is not installed, it raises rather than
    fabricating data. The offline/test path uses JSON snapshots from
    `sentinel observe` output (see tests/).
    """

    def __init__(self, watch_pid: Optional[int] = None) -> None:
        self.watch_pid = watch_pid or os.getpid()

    def __call__(self) -> Snapshot:
        try:
            import psutil
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "psutil is required for live snapshots; "
                "use a JSON snapshot provider in offline mode"
            ) from exc
        return self._snapshot(psutil, self.watch_pid)

    def _snapshot(self, psutil, root_pid: int) -> Snapshot:
        root = psutil.Process(root_pid)
        tree = _process_tree(root, psutil)
        connections = []
        for conn in psutil.net_connections(kind="tcp"):
            if conn.pid is not None and _in_tree(tree, conn.pid):
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                connections.append(
                    Connection(pid=conn.pid, local_addr=laddr, remote_addr=raddr, state=conn.status)
                )
        return Snapshot(pid=root_pid, tree=tree, connections=connections, fs_events=[])


def _process_tree(root, psutil):
    """Build the Process subtree rooted at `root` (psutil.Process)."""

    def build(proc):
        children = []
        try:
            for child in proc.children(recursive=False):
                children.append(build(child))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return Process(
            pid=proc.pid, parent_pid=proc.ppid(), name=proc.name(), children=children
        )

    return build(root)


def _in_tree(root: Process, pid: int) -> bool:
    found = False

    def walk(p: Process) -> None:
        nonlocal found
        if p.pid == pid:
            found = True

    root.walk(walk)
    return found
