"""7.1 guard audit lines say which AI tool asked, as a fixed list: claude, cursor, codex, gemini, antigravity, other."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402


def adapter(name):
    spec = importlib.util.spec_from_file_location("audit_agent_" + name, ROOT / "scripts" / "adapters" / f"{name}_hook.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def lines(project):
    p = project / ".security" / G.AUDIT_NAME
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(G, "managed_markers", lambda: [])
    return tmp_path


def test_the_claude_hook_event_has_no_agent_field_and_is_logged_as_claude(project):
    e = {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}, "cwd": str(project)}
    assert G.decide(e, "owner")[0] == "ask"
    got = lines(project)
    assert len(got) == 1 and got[0]["agent"] == "claude"


@pytest.mark.parametrize("name", ["cursor", "codex", "gemini", "antigravity"])
def test_each_adapter_is_logged_under_its_own_name(project, name):
    cmd = "git push --force origin main"
    mod = adapter(name)
    payload = {"cursor": {"hook_event_name": "beforeShellExecution", "command": cmd, "cwd": str(project)},
               "codex": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(project)},
               "gemini": {"tool_name": "run_shell_command", "tool_input": {"command": cmd}, "cwd": str(project)},
               "antigravity": {"workspacePaths": [str(project)], "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}}}[name]
    mod.handle(payload, "owner")
    got = lines(project)
    assert got and {x["agent"] for x in got} == {name}, got


@pytest.mark.parametrize("bad", ["evil", "CLAUDE", " claude", "", None, 7, ["cursor"], {"a": 1}, True])
def test_anything_not_on_the_list_is_other(project, bad):
    e = {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}, "cwd": str(project), "agent": bad}
    G.decide(e, "owner")
    assert [x["agent"] for x in lines(project)] == ["other"]


def test_the_model_cannot_set_the_agent_through_tool_input(project):
    e = {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main", "agent": "codex"}, "cwd": str(project)}
    G.decide(e, "owner")
    assert [x["agent"] for x in lines(project)] == ["claude"]


def test_the_field_is_in_every_kind_of_audit_line(project):
    for pm in (None, "auto", "bypassPermissions"):
        e = {"tool_name": "Read", "tool_input": {"file_path": str(Path.home() / ".npmrc")}, "cwd": str(project)}
        if pm:
            e["permission_mode"] = pm
        G.decide(e, "owner")
    got = lines(project)
    assert got and all(x.get("agent") == "claude" and x["decision"] for x in got), got
