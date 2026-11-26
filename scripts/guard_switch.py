#!/usr/bin/env python3
"""Turn the agent command guard on or off. Run it in YOUR OWN terminal:

    py -I guard_switch.py status
    py -I guard_switch.py off
    py -I guard_switch.py on
    py -I guard_switch.py mode adaptive|coding|strict
    py -I guard_switch.py workspace add <folder>
    py -I guard_switch.py workspace clear
    py -I guard_switch.py unattended on|off
    py -I guard_switch.py held
    py -I guard_switch.py held clear

unattended on: for a task you leave running (overnight, in any permission mode, any AI tool). Every question the guard
would ask becomes a refusal with the reason, so the session never waits on a prompt nobody answers, and the agent
carries on with the rest of the work. It never allows what a question would have stopped. SECURECODE_UNATTENDED=1 in
the environment does the same for one run. held: what was refused while nobody was there, to read in the morning.

Off switches off only the PreToolUse command guard (scripts/agent_guard.py): the questions about unknown commands,
installs, force pushes and so on, and its hard denials. Everything else stays on: the secure-coding rules, the check
after every edit, the stop gate, the secret shield, the injection watch, "Run Security Test", "Run Advisory QA", the
scanners, the report and the signed updates.

A managed install (managed-settings.json or the runtime under Program Files) ignores this switch: ask your
administrator. Turning the guard off or on needs a person at a terminal, so an agent that runs this script without
one is refused. The setting lives in config/guard-policy.json in the runtime folder, which the guard stops agents
from editing while it is on. An update keeps the setting.

mode: "adaptive" (default) lets the guard stay quiet about shell syntax it cannot follow but whose commands it checked
(coding mode) and read it strictly after a risk signal in the session; "coding" and "strict" pin it. workspace: folders
next to your project that the agent may READ (never write); every secret rule still applies there.
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
    def mutate(data):
        if want == "off":
            data["guard"] = "off"
            data["note"] = "command guard switched off by the owner with guard_switch.py; run it with 'on' to turn it back on"
        else:
            data.pop("guard", None)
            data.pop("note", None)
    return _update(mutate, path, markers, need_terminal)


def write_mode(value: str, path: Path | None = None, markers: list[str] | None = None, need_terminal: bool = True) -> str:
    """adaptive (the default, so the key is removed), coding or strict."""
    if value not in G.GMODES:
        raise SwitchRefused(f"the guard mode must be one of {', '.join(G.GMODES)}")

    def mutate(data):
        if value == "adaptive":
            data.pop("adaptive", None)
        else:
            data["adaptive"] = value
    _update(mutate, path, markers, need_terminal)
    return value


def write_workspace(op: str, folder: str | None = None, path: Path | None = None, markers: list[str] | None = None,
                    need_terminal: bool = True) -> list:
    """Add a folder the agent may read (never write), or clear the list. The folder must exist, be absolute and be a place
    the guard would accept as a root (not a drive root, not the home folder, not above or inside a protected place)."""
    if op == "add":
        if not folder or not os.path.isabs(folder) or not os.path.isdir(folder):
            raise SwitchRefused("give the full path of an existing folder")
        real = os.path.realpath(folder)
        n = G.split_norm(os.path.abspath(real), None)
        if not n or not G.GuardEnv({"cwd": real}).root_ok(n) or not G.ws_ok(n):
            raise SwitchRefused("that folder is not allowed as a workspace (a drive root, your home folder, or a protected place)")
    elif op != "clear":
        raise SwitchRefused("workspace takes add <folder> or clear")
    out: list = []

    def mutate(data):
        cur = [x for x in data.get("workspace_roots", []) if isinstance(x, str)] if isinstance(data.get("workspace_roots"), list) else []
        if op == "clear":
            cur = []
        elif real not in cur and len(cur) < 8:
            cur.append(real)
        if cur:
            data["workspace_roots"] = cur
        else:
            data.pop("workspace_roots", None)
        out[:] = cur
    _update(mutate, path, markers, need_terminal)
    return out


def write_unattended(on: bool, path: Path | None = None, markers: list[str] | None = None, need_terminal: bool = True) -> bool:
    """Unattended mode: every question the guard would ask becomes a refusal with the reason, kept on the held list.
    It never allows anything a question would have stopped."""
    def mutate(data):
        if on:
            data["unattended"] = True
        else:
            data.pop("unattended", None)
    _update(mutate, path, markers, need_terminal)
    return on


def held_report(project: str, limit: int = 40) -> str:
    """The held list of a project as text: what was refused while nobody was there, grouped, newest groups last."""
    rows = G.held_read(project)
    if not rows:
        return "Held list: empty. Nothing was refused in this project while nobody was there."
    groups: dict = {}
    for r in rows:
        k = (r["kind"], r["tool"], r["command"], r["reason"])
        g = groups.setdefault(k, {"n": 0, "first": r["ts"], "last": r["ts"]})
        g["n"] += 1
        g["last"] = r["ts"]
    names = {"refused": "REFUSED (would have asked you)", "blocked": "BLOCKED (always refused)", "offer": "WAITING FOR YOU",
             "full": "LIST FULL"}
    out = [f"Held list: {len(rows)} event(s), {len(groups)} different, from {rows[0]['ts']} to {rows[-1]['ts']}."]
    for (kind, tool, cmd, why), g in list(groups.items())[-limit:]:
        out.append(f"- {names.get(kind, kind)} x{g['n']} [{tool or '-'}] {cmd or '-'}")
        out.append(f"    why: {why}  (last {g['last']})")
    if len(groups) > limit:
        out.append(f"... {len(groups) - limit} older group(s) not shown.")
    out.append("Run a refused command yourself if you want it. Clear the list with: guard_switch.py held clear")
    return "\n".join(out)


def _update(mutate, path: Path | None, markers: list[str] | None, need_terminal: bool) -> str:
    if need_terminal and not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise SwitchRefused("changing the guard setting needs a person at a terminal")
    p = Path(path) if path is not None else G.policy_path()
    mode, why = G.load_policy(p, markers)
    if mode != "owner":
        raise SwitchRefused("this is a managed install, or the guard policy file is missing or not valid, so the switch is "
                              f"not used ({why}). Ask your administrator, or run install-global.py to repair the policy.")
    data = json.loads(p.read_bytes().decode("utf-8-sig"), object_pairs_hook=G._no_dupes)
    mutate(data)
    if len(json.dumps(data, indent=2)) > G.POLICY_MAX - 200:
        raise SwitchRefused("the policy file would get too large; clear some workspace folders first")
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
    ok = (len(args) == 1 and args[0] in ("on", "off", "status", "held")) or (len(args) == 2 and args[0] == "mode") or \
        (args[:1] == ["workspace"] and (args[1:] == ["clear"] or (len(args) == 3 and args[1] == "add"))) or \
        (len(args) == 2 and args[0] == "unattended" and args[1] in ("on", "off")) or args == ["held", "clear"]
    if not ok:
        print(__doc__)
        return 2
    cmd = args[0]
    project = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    if args == ["held"]:
        # ASCII with escapes: a recorded command can hold any character, and a piped Windows console (cp1252) or a
        # terminal escape sequence must not break or repaint the output
        sys.stdout.write(held_report(project).encode("ascii", "backslashreplace").decode("ascii") + "\n")
        return 0
    if cmd == "status":
        st, why = state()
        print(f"command guard: {st.upper()} ({why})")
        print(f"guard mode: {G.guard_pref()} (adaptive = coding until a risk signal, then strict); "
              f"workspace folders: {G.policy_list('workspace_roots') or 'none'}")
        held_on = G.held_switch()
        print(f"unattended mode: {('ON, but the command guard is OFF, so nothing is refused' if st == 'off' else 'ON (questions become refusals, kept on the held list)') if held_on else 'off'}; "
              f"held list for this folder: {len(G.held_read(project))} event(s) (guard_switch.py held)")
        if st == "off":
            print("Still on: secure-coding rules, edit check, stop gate, output shield, security tests, scanners, signed updates.")
        return 0
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Refused: turning the guard on or off needs a person at a terminal. Open your own terminal and run this "
              "command there.", file=sys.stderr)
        return 3
    try:
        if cmd == "held":
            G.held_clear(project)
            print("held list cleared for this folder.")
            return 0
        if cmd == "unattended":
            on = write_unattended(args[1] == "on")
            print("unattended mode is now ON: the guard refuses, with a reason, what it would have asked, and keeps it on "
                  "the held list. Nothing is allowed that a question would have stopped." if on else "unattended mode is now OFF.")
            return 0
        if cmd == "mode":
            print(f"guard mode is now {write_mode(args[1]).upper()}.")
            return 0
        if cmd == "workspace":
            print(f"workspace folders (read only): {write_workspace(args[1], args[2] if len(args) > 2 else None) or 'none'}")
            return 0
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
