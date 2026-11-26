"""7.2: a quoted program path that contains a space is a path, not an unknown command.

Before 7.2 `"C:/Users/John Doe/proj/.venv/Scripts/python.exe" -m pytest` asked with "the command name contains spaces", so
every developer whose home, OneDrive or project folder has a space was asked on each full-path venv call.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402


@pytest.fixture
def proj(tmp_path, monkeypatch):
    p = tmp_path / "John Doe" / "my proj"
    (p / ".venv" / "Scripts").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(p))
    return p


def verdict(cmd, proj, tool="Bash", mode="owner"):
    r = G.check({"tool_name": tool, "tool_input": {"command": cmd}, "cwd": str(proj)}, mode)
    return r[0] if r else "allow"


def test_a_venv_python_in_a_folder_with_spaces_does_not_ask(proj):
    py = str(proj / ".venv" / "Scripts" / "python.exe").replace("\\", "/")
    assert verdict(f'"{py}" -m pytest -q', proj) == "allow"
    assert verdict(f'"{py}" -m pytest -q tests/ 2>&1 | tail -20', proj) == "allow"


def test_a_script_by_a_quoted_path_with_spaces_inside_the_project_does_not_ask(proj):
    (proj / "my tools").mkdir()
    s = str(proj / "my tools" / "runit.sh").replace("\\", "/")
    assert verdict(f'"{s}" --fast', proj) == "allow"


def test_a_quoted_command_line_without_a_path_still_asks(proj):
    assert verdict('"git status"', proj) != "allow"
    assert verdict('"npm install"', proj) != "allow"


def test_a_basename_with_a_space_is_not_taken_for_a_program(proj):
    # the whole word is the program name; here that name is "git.exe status", which is not a program the guard knows
    p = str(proj / "bin" / "git.exe status").replace("\\", "/")
    assert verdict(f'"{p}"', proj) != "allow"
    assert verdict('"C:/Windows/System32/cmd.exe /c del x"', proj) != "allow"


def test_a_program_with_spaces_outside_the_project_still_asks(proj):
    other = Path.home() / "Other Folder" / "tool.exe"
    assert verdict(f'"{str(other)}" run'.replace("\\", "/"), proj) != "allow"


def test_a_secret_path_with_spaces_is_still_denied(proj):
    assert verdict('cat "' + str(proj / ".env").replace("\\", "/") + '"', proj) == "deny"
    assert verdict('"' + str(proj / ".env.production").replace("\\", "/") + '"', proj) in ("deny", "ask")
