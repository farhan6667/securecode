#!/usr/bin/env python3
"""Turn the agent command guard on or off. Run it in YOUR OWN terminal:

    py -I guard_switch.py status
    py -I guard_switch.py off
    py -I guard_switch.py on

Off switches off only the PreToolUse command guard (scripts/agent_guard.py): the questions about unknown commands,
installs, force pushes and so on, and its hard denials. Everything else stays on: the secure-coding rules, the check
after every edit, the stop gate, the secret shield, the injection watch, "Run Security Test", "Run Advisory QA", the
scanners, the report and the signed updates.

A managed install (managed-settings.json or the runtime under Program Files) ignores this switch: ask your
administrator. Turning the guard off or on needs a person at a terminal, so an agent that runs this script without
one is refused. The setting lives in config/guard-policy.json in the runtime folder, which the guard stops agents
from editing while it is on. An update keeps the setting.
"""
from __future__ import annotations
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(os.path.abspath(__file__)).parent
sys.path.insert(0, str(HERE))
import agent_guard as G  # noqa: E402


class SwitchRefused(Exception):
    """The switch is not used here (managed install, missing or invalid policy) or there is no person at a terminal."""


def state(path: Path | None = None, markers: list[str] | None = None) -> tuple[str, str]:
    """("off" | "on" | "managed", why)"""
    mode, why = G.load_policy(path, markers)
    if mode != "owner":
        return "managed", why
    return ("off" if G.guard_is_off(path, markers) else "on"), why


def write_switch(want: str, path: Path | None = None, markers: list[str] | None = None, need_terminal: bool = True) -> str:
    """Change the setting. A person at a terminal is required here as well as in main(), so that importing this function
    from another script does not skip the check. This stops accidents and simple prompt injection; it is not
    authentication, and code an agent writes and runs itself can still edit the file."""
    if need_terminal and not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise SwitchRefused("turning the guard on or off needs a person at a terminal")
    p = Path(path) if path is not None else G.policy_path()
    mode, why = G.load_policy(p, markers)
    if mode != "owner":
        raise SwitchRefused("this is a managed install, or the guard policy file is missing or not valid, so the switch is "
                              f"not used ({why}). Ask your administrator, or run install-global.py to repair the policy.")
    data = json.loads(p.read_bytes().decode("utf-8-sig"), object_pairs_hook=G._no_dupes)
    if want == "off":
        data["guard"] = "off"
        data["note"] = "command guard switched off by the owner with guard_switch.py; run it with 'on' to turn it back on"
    else:
        data.pop("guard", None)
        data.pop("note", None)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".policy-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2) + "\n")
        for attempt in range(5):                  # Windows: the hook may have the file open for a moment
            try:
                os.replace(tmp, p)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.2)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return state(p, markers)[0]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] not in ("on", "off", "status"):
        print(__doc__)
        return 2
    cmd = args[0]
    if cmd == "status":
        st, why = state()
        print(f"command guard: {st.upper()} ({why})")
        if st == "off":
            print("Still on: secure-coding rules, edit check, stop gate, output shield, security tests, scanners, signed updates.")
        return 0
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Refused: turning the guard on or off needs a person at a terminal. Open your own terminal and run this "
              "command there.", file=sys.stderr)
        return 3
    try:
        new = write_switch(cmd)
    except SwitchRefused as e:
        print(f"Refused: {e}", file=sys.stderr)
        return 4
    except Exception as e:
        print(f"Could not change the guard setting ({type(e).__name__}). Close other programs that use it and try again.",
              file=sys.stderr)
        return 5
    print(f"command guard is now {new.upper()}.")
    if new == "off":
        print("Only the command guard is off. The secure-coding rules, edit check, stop gate, output shield, security tests, "
              "scanners and signed updates are still on. Turn it back on with: guard_switch.py on")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
