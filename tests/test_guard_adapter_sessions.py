"""7.2: the adapters pass their tool's session id on, so a block in one session makes that session strict for every agent."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402


def adapter(name):
    spec = importlib.util.spec_from_file_location("adapter_sess_" + name, ROOT / "scripts" / "adapters" / f"{name}_hook.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setenv("SECURECODE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(G, "managed_markers", lambda: [])
    pol = tmp_path / "pol.json"
    pol.write_text(json.dumps({"mode": "owner"}), encoding="utf-8")
    monkeypatch.setattr(G, "policy_path", lambda: pol)
    return tmp_path


def payload(name, cmd, project, sid):
    return {"cursor": {"hook_event_name": "beforeShellExecution", "command": cmd, "cwd": str(project), "conversation_id": sid},
            "codex": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(project),
                      "session_id": sid},
            "gemini": {"tool_name": "run_shell_command", "tool_input": {"command": cmd}, "cwd": str(project), "session_id": sid},
            "antigravity": {"workspacePaths": [str(project)], "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}},
                            "conversationId": sid}}[name]


@pytest.mark.parametrize("name", ["cursor", "codex", "gemini", "antigravity"])
def test_a_block_makes_the_next_syntax_shape_strict_in_every_adapter(project, name):
    mod = adapter(name)
    sid = "sess-" + name
    mod.handle(payload(name, "cat .env", project, sid), "owner")                 # a block: this session is now strict
    assert G.session_risk({"session_id": sid}) == "a command was blocked earlier in this session"
    other = {"session_id": "other-" + name}
    assert G.session_risk(other) is None
