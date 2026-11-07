"""7.1 PowerShell assignment without spaces: `$env:X="v"` and `$x="a"` are read like `$env:X = "v"` and `$x = "a"`.

Before, the glued form was read as "a command name built at run time" and asked, with a wrong reason, while the spaced form
passed. A real session showed this was more than half of all asks.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402


@pytest.fixture(autouse=True)
def _project(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))


def dec(cmd, mode="owner", pm=None):
    e = {"tool_name": "PowerShell", "tool_input": {"command": cmd}, "cwd": str(ROOT)}
    if pm:
        e["permission_mode"] = pm
    r = G.decide(e, mode)
    return r[0] if r else "allow"


# (glued, spaced): the same statement written two ways
PAIRS = [('$env:X="v"', '$env:X = "v"'), ('$x="a"', '$x = "a"'), ("$x=1", "$x = 1"), ("$env:A='b'", "$env:A = 'b'"),
         ('$env:PYTHONUTF8="1"', '$env:PYTHONUTF8 = "1"'), ("$env:X=$env:Y", "$env:X = $env:Y"),
         ('$env:PATH="x"', '$env:PATH = "x"'), ('$env:NODE_OPTIONS="--require ./e.js"', '$env:NODE_OPTIONS = "--require ./e.js"'),
         ('$env:LD_PRELOAD="x"', '$env:LD_PRELOAD = "x"'), ('$env:PYTHONSTARTUP="x.py"', '$env:PYTHONSTARTUP = "x.py"'),
         ('$env:GIT_SSH_COMMAND="x"', '$env:GIT_SSH_COMMAND = "x"'), ('$env:HTTPS_PROXY="http://e"', '$env:HTTPS_PROXY = "http://e"'),
         ('$env:BASH_ENV="x"', '$env:BASH_ENV = "x"'), ('$env:IFS="x"', '$env:IFS = "x"')]


@pytest.mark.parametrize("glued,spaced", PAIRS)
@pytest.mark.parametrize("mode", ["owner", "managed"])
def test_the_glued_form_is_read_like_the_spaced_form(glued, spaced, mode):
    assert dec(glued, mode) == dec(spaced, mode), (glued, mode)


@pytest.mark.parametrize("glued,spaced", PAIRS)
def test_the_glued_form_is_read_like_the_spaced_form_in_every_run_style(glued, spaced):
    for pm in ("auto", "bypassPermissions"):
        assert dec(glued, "owner", pm) == dec(spaced, "owner", pm), (glued, pm)


@pytest.mark.parametrize("cmd", ['$env:X="v"', '$x="a"', "$x=1", '$env:PYTHONUTF8="1"; git status',
                                 '$a="b"; Write-Output $a', '$env:X="v";$y="w"', '$p="src"; Get-ChildItem $p', "$env:X=$env:Y"])
def test_everyday_glued_assignments_are_not_asked(cmd):
    assert dec(cmd) == "allow", cmd
    assert dec(cmd, "owner", "auto") == "allow", cmd


@pytest.mark.parametrize("cmd", ['$env:PATH="x"', '$env:NODE_OPTIONS="--require ./e.js"; node x.js', '$env:LD_PRELOAD="x"; git status',
                                 '$env:PYTHONSTARTUP="x.py"', '$env:GIT_SSH_COMMAND="x"; git push', '$env:BASH_ENV="x"',
                                 '$x="$(rm -rf /)"', "$x=@(1,2)", "$f=Get-Content a.txt", "$x=(Get-Date)", '$x="a"; $(rm x)'])
def test_what_can_change_what_programs_run_or_runs_code_still_asks(cmd):
    assert dec(cmd) == "ask", cmd
    assert dec(cmd, "owner", "auto") == "deny", cmd


def test_a_glued_assignment_cannot_hide_a_following_command():
    assert dec('$x="a"; git push --force origin main') == "ask"
    assert dec('$x="a"; git push --force origin main', "owner", "auto") == "deny"
    assert dec('$env:X="v"; cat .env') == "deny"
    assert dec('$env:X="v"; cat .env', "owner", "bypassPermissions") == "deny"


def test_a_glued_assignment_value_feeds_the_variable_like_the_spaced_form():
    # the stored value is used when the variable is then read as a path
    assert dec('$p="src"; Get-Content $p/a.txt') == dec('$p = "src"; Get-Content $p/a.txt')
    assert dec('$p=".env"; Get-Content $p') == dec('$p = ".env"; Get-Content $p') != "allow"
