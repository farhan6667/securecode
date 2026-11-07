"""Replay of the SHAPES of real guard asks (made-up commands, none of them real).

In one real working session on a developer's PC the guard asked 34 times in about 80 minutes, all of them for the "unknown"
class and about three quarters of them noise. The groups were: a full path to Python, a PowerShell assignment without
spaces, shell syntax the guard does not model ($( ), ( ), PowerShell member access), a variable prefix, a read in a sibling
folder, inline Python, xargs, and commands that run on a remote server. This file keeps one made-up command per shape, so
that a change that makes the guard noisier again fails a test.

7.1.0 removes the first two groups (see test_ps_assignment.py and test_guard_auto_mode.py). The rest still ask in an attended
session and are planned for 7.2; the number of asks below may only go down.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402

PY = sys.executable.replace("\\", "/")

FIXED_IN_7_1 = {
    "full path to python": [(f'"{PY}" -m pytest -q', "Bash"), (f'"{PY}" -m unittest tests.test_x -v 2>&1 | tail -45', "Bash"),
                            (f'PYTHONUTF8=1 "{PY}" -m pytest tests/test_a.py -q', "Bash"), (f'"{PY}" scripts/secgate.py . --mode ci', "Bash")],
    "powershell assignment without spaces": [('$env:PYTHONUTF8="1"; git status', "PowerShell"), ('$x="a"; Write-Output $x', "PowerShell"),
                                             ('$env:X="v"', "PowerShell"), ('$p="src"; Get-ChildItem $p', "PowerShell")],
    "everyday": [(c, "Bash") for c in ("git status", "git diff", "npm test", "pytest -q", "make test", "docker compose ps",
                                        "cargo test", "go test ./...")],
}

STILL_ASKS_IN_AN_ATTENDED_SESSION = {
    "powershell member access": [("(Get-Item README.md).Length", "PowerShell"), ("$f = Get-Content a.txt", "PowerShell"),
                                 ("(Get-Content a.txt).Count", "PowerShell")],
    "command substitution": [("echo $(date)", "Bash"), ("ls $(pwd)", "Bash"), ("wc -l $(git ls-files)", "Bash")],
    "variable prefix": [("X_URL=http://localhost:8000 python -m pytest -q", "Bash"), ('A="b" git status', "Bash"),
                        ("FOO=1 BAR=2 git log -1", "Bash")],
    "read in a sibling folder": [("grep -rn foo ../other-repo/src", "Bash"), ("ls ../other-repo", "Bash"), ("cat ../notes/todo.md", "Bash")],
    "inline code": [("python - <<'EOF'\nprint(1)\nEOF", "Bash"), ('python -c "print(1)"', "Bash"), ('node -e "console.log(1)"', "Bash")],
    "xargs": [("git ls-files | xargs wc -l", "Bash"), ("ls | xargs -n1 echo", "Bash")],
    "remote server": [('ssh host "systemctl status app"', "Bash"), ('ssh host "systemctl restart app"', "Bash")],
}
MAX_ASKS_NOW = sum(len(v) for v in STILL_ASKS_IN_AN_ATTENDED_SESSION.values())      # the count may only go down


@pytest.fixture(autouse=True)
def _project(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(ROOT))


def verdict(cmd, tool, pm=None, mode="owner"):
    e = {"tool_name": tool, "tool_input": {"command": cmd}, "cwd": str(ROOT)}
    if pm:
        e["permission_mode"] = pm
    r = G.check(e, mode) if pm is None else G.decide(e, mode)
    return r[0] if r else "allow"


@pytest.mark.parametrize("group", sorted(FIXED_IN_7_1))
def test_the_groups_fixed_in_7_1_do_not_ask(group):
    for cmd, tool in FIXED_IN_7_1[group]:
        assert verdict(cmd, tool) == "allow", (group, cmd)


def test_the_number_of_asks_only_goes_down():
    asks = [(g, c) for g, items in STILL_ASKS_IN_AN_ATTENDED_SESSION.items() for c, t in items if verdict(c, t) != "allow"]
    assert len(asks) <= MAX_ASKS_NOW, f"the guard got noisier: {len(asks)} asks, was {MAX_ASKS_NOW}: {asks}"
    # and when a group is fixed, move it to FIXED_IN_7_1 so that it stays fixed
    fixed_now = [(g, c) for g, items in STILL_ASKS_IN_AN_ATTENDED_SESSION.items() for c, t in items if verdict(c, t) == "allow"]
    assert not fixed_now, f"these no longer ask; move them to FIXED_IN_7_1: {fixed_now}"


@pytest.mark.parametrize("pm", ["auto", "dontAsk", "bypassPermissions"])
def test_no_shape_ever_stops_an_unattended_run_with_a_question(pm):
    every = [x for d in (FIXED_IN_7_1, STILL_ASKS_IN_AN_ATTENDED_SESSION) for items in d.values() for x in items]
    for cmd, tool in every:
        assert verdict(cmd, tool, pm) in ("allow", "deny"), (pm, cmd)


def test_managed_mode_is_not_quieter_than_it_was_for_the_still_asking_shapes():
    for items in STILL_ASKS_IN_AN_ATTENDED_SESSION.values():
        for cmd, tool in items:
            assert verdict(cmd, tool, mode="managed") in ("deny", "ask"), cmd
