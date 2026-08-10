"""Runtime snapshot model for the Python adapter.

A `Snapshot` is the same shape the Rust observer emits (`sentinel observe
<pid>` -> JSON): a process tree, a PID-attributed connection table, and
filesystem events. `Snapshot.from_json` consumes that output so the policy
engine can be exercised against real observer data.
"""

import json
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Process:
    pid: int
    parent_pid: int = 0
    name: str = ""
    children: List["Process"] = field(default_factory=list)

    def walk(self, visitor) -> None:
        visitor(self)
        for child in self.children:
            child.walk(visitor)

    def size(self) -> int:
        return 1 + sum(c.size() for c in self.children)

    @classmethod
    def from_dict(cls, d: dict) -> "Process":
        return cls(
            pid=int(d.get("pid", 0)),
            parent_pid=int(d.get("parent_pid", 0)),
            name=d.get("name", ""),
            children=[cls.from_dict(c) for c in d.get("children", [])],
        )


@dataclass
class Connection:
    pid: int
    local_addr: str
    remote_addr: str
    state: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Connection":
        return cls(
            pid=int(d.get("pid", 0)),
            local_addr=d.get("local_addr", ""),
            remote_addr=d.get("remote_addr", ""),
            state=d.get("state", ""),
        )


@dataclass
class FsEvent:
    pid: int
    path: str
    sensitive: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "FsEvent":
        return cls(
            pid=int(d.get("pid", 0)),
            path=d.get("path", ""),
            sensitive=bool(d.get("sensitive", False)),
        )


@dataclass
class Snapshot:
    pid: int
    tree: Optional[Process] = None
    connections: List[Connection] = field(default_factory=list)
    fs_events: List[FsEvent] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Snapshot":
        return cls(
            pid=int(d.get("pid", 0)),
            tree=(
                Process.from_dict(d["process_tree"])
                if d.get("process_tree")
                else None
            ),
            connections=[
                Connection.from_dict(c) for c in d.get("connections", [])
            ],
            fs_events=[FsEvent.from_dict(e) for e in d.get("fs_events", [])],
        )

    @classmethod
    def from_json(cls, raw: str) -> "Snapshot":
        return cls.from_dict(json.loads(raw))

    @classmethod
    def from_file(cls, path: str) -> "Snapshot":
        with open(path, encoding="utf-8-sig") as fh:
            return cls.from_json(fh.read())
