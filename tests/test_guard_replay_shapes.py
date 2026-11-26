"""Replay of the SHAPES of real guard asks (made-up commands, none of them real).

In one real working session on a developer's PC the guard asked 34 times in about 80 minutes, all of them for the "unknown"
class and about three quarters of them noise. The groups were: a full path to Python, a PowerShell assignment without
spaces, shell syntax the guard does not model ($( ), ( ), PowerShell member access), a variable prefix, a read in a sibling
folder, inline Python, xargs, and commands that run on a remote server. This file keeps one made-up command per shape, so
that a change that makes the guard noisier again fails a test.

7.1.0 removed the first two groups. 7.2.0 models the rest: the inner command of every one of them is still run through the
positive model (see test_guard_adaptive_mode.py and test_guard_invariants.py for what must never change), and a change
that makes any of them ask again fails here. What still asks is on purpose: a command that changes a server.
"""
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402

PY = sys.executable.replace("\\", "/")

QUIET_NOW = {
    "full path to python": [(f'"{PY}" -m pytest -q', "Bash"), (f'"{PY}" -m unittest tests.test_x -v 2>&1 | tail -45', "Bash"),
                            (f'PYTHONUTF8=1 "{PY}" -m pytest tests/test_a.py -q', "Bash"), (f'"{PY}" scripts/secgate.py . --mode ci', "Bash")],
    "powershell assignment without spaces": [('$env:PYTHONUTF8="1"; git status', "PowerShell"), ('$x="a"; Write-Output $x', "PowerShell"),
                                             ('$env:X="v"', "PowerShell"), ('$p="src"; Get-ChildItem $p', "PowerShell")],
    "everyday": [(c, "Bash") for c in ("git status", "git diff", "npm test", "pytest -q", "make test", "docker compose ps",
                                        "cargo test", "go test ./...")],
    # 7.2
    "powershell member access": [("(Get-Item README.md).Length", "PowerShell"), ("$f = Get-Content a.txt", "PowerShell"),
                                 ("(Get-Content a.txt).Count", "PowerShell"), ("Write-Output (Get-Date)", "PowerShell")],
    "command substitution": [("echo $(date)", "Bash"), ("ls $(pwd)", "Bash"), ("wc -l $(git ls-files)", "Bash"),
                             ("git commit -m \"$(cat <<'EOF'\nfix: don't break it (see #1)\n\nbody\nEOF\n)\"", "Bash")],
    "variable prefix": [("X_URL=http://localhost:8000 python -m pytest -q", "Bash"), ('A="b" git status', "Bash"),
                        ("FOO=1 BAR=2 git log -1", "Bash")],
    "read in a sibling folder": [("grep -rn foo ../other-repo/src", "Bash"), ("ls ../other-repo", "Bash"), ("cat ../notes/todo.md", "Bash")],
    "inline code": [("python - <<'EOF'\nprint(1)\nEOF", "Bash"), ('python -c "print(1)"', "Bash"), ('node -e "console.log(1)"', "Bash")],
    "xargs": [("git ls-files | xargs wc -l", "Bash"), ("ls | xargs -n1 echo", "Bash")],
    "read-only remote server": [('ssh host "systemctl status app"', "Bash"), ('ssh host "journalctl -u app -n 50"', "Bash"),
                                ('ssh host "docker ps"', "Bash")],
}
# What still asks, on purpose: the command changes a server or can run anything.
ASKS_ON_PURPOSE = {
    "remote server change": [('ssh host "systemctl restart app"', "Bash"), ('ssh host "ssh-keygen -t ed25519"', "Bash")],
}
MAX_ASKS_NOW = 0               # of the shapes in QUIET_NOW; the count may only stay at 0
HARD_ACCEPTANCE = 8            # DI's bar: from 34 measured asks down to at most this many


def _workspace_usable() -> bool:
    """The sibling-folder shapes need the checkout's parent to be an acceptable workspace folder. It is not when the checkout sits
    directly in the home folder (the home folder is never a workspace) or under a system or app-data folder."""
    n = G.split_norm(str(ROOT.parent), None)
    return bool(n and G.GuardEnv({"cwd": str(ROOT)}).root_ok(n) and G.ws_ok(n))


SIBLING = "read in a sibling folder"


def _quiet():
    return {k: v for k, v in QUIET_NOW.items() if k != SIBLING or _workspace_usable()}


@pytest.fixture(autouse=True)
def _project(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(ROOT))
    monkeypatch.setenv("SECURECODE_CACHE_DIR", str(tmp_path / "cache"))
    pol = tmp_path / "guard-policy.json"
    pol.write_text(json.dumps({"mode": "owner", "workspace_roots": [str(ROOT.parent)]}), encoding="utf-8")
    monkeypatch.setattr(G, "policy_path", lambda: pol)
    monkeypatch.setattr(G, "managed_markers", lambda: [])


def verdict(cmd, tool, pm=None, mode="owner", gm=None):
    e = {"tool_name": tool, "tool_input": {"command": cmd}, "cwd": str(ROOT)}
    if pm:
        e["permission_mode"] = pm
    r = G.check(e, mode, gm) if pm is None else G.decide(e, mode, gm)
    return r[0] if r else "allow"


def asks_in(groups, **kw):
    return [(g, c) for g, items in groups.items() for c, t in items if verdict(c, t, **kw) != "allow"]


@pytest.mark.parametrize("group", sorted(QUIET_NOW))
def test_the_groups_do_not_ask_in_coding_mode(group):
    if group == SIBLING and not _workspace_usable():
        pytest.skip("the checkout's parent folder cannot be a workspace here (it is the home folder or a system folder)")
    for cmd, tool in QUIET_NOW[group]:
        assert verdict(cmd, tool, gm="coding") == "allow", (group, cmd)


def test_the_number_of_asks_stays_under_the_bar():
    asks = asks_in(_quiet(), gm="coding")
    assert len(asks) <= MAX_ASKS_NOW, f"the guard got noisier: {len(asks)} asks: {asks}"
    on_purpose = asks_in(ASKS_ON_PURPOSE, gm="coding")
    assert len(asks) + len(on_purpose) <= HARD_ACCEPTANCE
    assert len(on_purpose) == sum(len(v) for v in ASKS_ON_PURPOSE.values()), "a change that is meant to ask no longer asks"


def test_strict_mode_asks_for_the_syntax_shapes_as_7_1_did():
    # the strict reading (a risk signal, or a pinned policy) is as careful as 7.1 for what the guard cannot follow
    syntax = ("powershell member access", "command substitution", "inline code", "xargs", "read-only remote server")
    for g in syntax:
        for cmd, tool in QUIET_NOW[g]:
            assert verdict(cmd, tool, gm="strict") != "allow", (g, cmd)


@pytest.mark.parametrize("pm", ["auto", "dontAsk", "bypassPermissions"])
def test_no_shape_ever_stops_an_unattended_run_with_a_question(pm):
    every = [x for d in (QUIET_NOW, ASKS_ON_PURPOSE) for items in d.values() for x in items]
    for cmd, tool in every:
        assert verdict(cmd, tool, pm) in ("allow", "deny"), (pm, cmd)


def test_managed_mode_is_not_quieter_for_the_syntax_shapes():
    for g in ("powershell member access", "command substitution", "inline code", "xargs", "read-only remote server"):
        for cmd, tool in QUIET_NOW[g]:
            assert verdict(cmd, tool, mode="managed") in ("deny", "ask"), cmd
    for items in ASKS_ON_PURPOSE.values():
        for cmd, tool in items:
            assert verdict(cmd, tool, mode="managed") in ("deny", "ask"), cmd
