"""CLI: enforce a policy against a snapshot (offline, deterministic).

Usage:
    python -m agent enforce snapshot.json --policy policy.deny.json
    python -m agent enforce --demo

Exit codes: 0 = ALLOW, 1 = FLAG, 2 = DENY (mirrors `pulse verdict` conventions).
"""

import argparse
import json
import sys

from .guard import AgentGuard, DeniedError
from .policy import Action, Policy
from .snapshot import Snapshot

DEMO_SNAPSHOT = {
    "pid": 1337,
    "process_tree": {"pid": 1337, "name": "agent.exe", "children": []},
    "connections": [
        {"pid": 1337, "local_addr": "10.0.0.5:64123",
         "remote_addr": "45.83.192.12:443", "state": "ESTABLISHED"}
    ],
    "fs_events": [
        {"pid": 1337, "path": "C:\\Users\\agent\\.env", "sensitive": True}
    ],
}

EXIT_CODES = {Action.ALLOW: 0, Action.FLAG: 1, Action.DENY: 2}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", nargs="?", help="path to a snapshot JSON (omit with --demo)")
    parser.add_argument("--policy", required=True, help="path to a policy JSON")
    parser.add_argument("--demo", action="store_true", help="run against the built-in demo snapshot")
    args = parser.parse_args(argv)

    if args.demo:
        snapshot = Snapshot.from_dict(DEMO_SNAPSHOT)
    elif args.snapshot:
        snapshot = Snapshot.from_file(args.snapshot)
    else:
        parser.error("provide a snapshot path or --demo")

    policy = Policy.from_file(args.policy)
    guard = AgentGuard(
        policy,
        lambda: snapshot,
        kill=lambda snap, v: print(
            f"[kill-switch] terminated tree root pid={snap.pid}", file=sys.stderr
        ),
    )

    try:
        verdict = guard.check()
    except DeniedError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_CODES[Action.DENY]

    print(json.dumps({"action": verdict.action.value, "reasons": verdict.reasons}))
    return EXIT_CODES[verdict.action]


if __name__ == "__main__":
    sys.exit(main())
