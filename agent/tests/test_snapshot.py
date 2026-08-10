"""Snapshot parsing tests — consumes the exact JSON shape the Rust observer
(`sentinel observe`) emits."""

from agent.snapshot import Connection, FsEvent, Process, Snapshot

OBSERVE_JSON = """{
  "pid": 8656,
  "observed_at": "1784310400",
  "process_tree": {
    "pid": 8656,
    "name": "agent.exe",
    "children": [
      {"pid": 8657, "name": "python.exe", "children": []}
    ]
  },
  "connections": [
    {
      "pid": 8656,
      "local_addr": "192.168.0.159:63869",
      "remote_addr": "32.195.92.226:443",
      "state": "ESTABLISHED"
    }
  ]
}"""


def test_from_json_parses_observe_output():
    snap = Snapshot.from_json(OBSERVE_JSON)
    assert snap.pid == 8656
    assert snap.tree is not None
    assert snap.tree.size() == 2
    assert snap.tree.children[0].name == "python.exe"
    assert len(snap.connections) == 1
    assert snap.connections[0].remote_addr == "32.195.92.226:443"


def test_missing_sections_default_empty():
    snap = Snapshot.from_json('{"pid": 1}')
    assert snap.tree is None
    assert snap.connections == []
    assert snap.fs_events == []


def test_tree_walk_visits_all():
    root = Process(pid=1, name="a.exe")
    root.children.append(Process(pid=2, name="b.exe"))
    root.children.append(Process(pid=3, name="c.exe"))
    root.children[0].children.append(Process(pid=4, name="d.exe"))
    pids = []
    root.walk(lambda p: pids.append(p.pid))
    assert sorted(pids) == [1, 2, 3, 4]
    assert root.size() == 4


def test_fs_event_flags():
    snap = Snapshot.from_json(
        '{"pid": 1, "fs_events": [{"pid": 1, "path": ".env", "sensitive": true}]}'
    )
    assert snap.fs_events[0].sensitive is True
    assert isinstance(snap.fs_events[0], FsEvent)
