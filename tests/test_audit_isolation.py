"""The suite must not write fake asks into the repository's own guard audit (see conftest.py)."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402

AUDIT = ROOT / ".security" / "guard-audit.jsonl"


def size():
    try:
        return AUDIT.stat().st_size
    except OSError:
        return None


def ask_event(cwd=ROOT):
    return {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}, "cwd": str(cwd)}


def test_an_in_process_ask_with_the_repo_as_project_is_not_logged(monkeypatch):
    before = size()
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    assert G.decide(ask_event(), "owner")[0] == "ask"          # the cwd falls back to the repository
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(ROOT))
    assert G.decide(ask_event(), "managed")[0] == "deny"
    assert G.decide(ask_event(), "owner")[0] == "ask"
    assert size() == before


def test_an_ask_for_another_project_is_still_logged(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    assert G.decide(ask_event(tmp_path), "owner")[0] == "ask"
    lines = (tmp_path / ".security" / "guard-audit.jsonl").read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["decision"] == "ask"


def test_the_backstop_catches_a_subprocess_that_does_write(tmp_path):
    # a guard run as a subprocess with the repo as project does log (this is what the end-of-run size check is for)
    probe = tmp_path / "probe"
    probe.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
    env["CLAUDE_PROJECT_DIR"] = str(probe)                      # this test itself must not touch the real file
    subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "agent_guard.py")], input=json.dumps(ask_event(probe)),
                   capture_output=True, text=True, env=env, timeout=60, cwd=str(probe))
    assert size() == size()


def test_a_link_or_junction_named_scripts_cannot_switch_the_audit_off(tmp_path, monkeypatch):
    # review round 8: the own-folder rule compared real paths, so a project whose scripts folder pointed at the real one
    # (a junction on Windows needs no privilege, a symlink elsewhere) lost its audit trail
    proj = tmp_path / "proj"
    proj.mkdir()
    link = proj / "scripts"
    if os.name == "nt":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(ROOT / "scripts")], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
    else:
        os.symlink(ROOT / "scripts", link, target_is_directory=True)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    assert G.decide(ask_event(proj), "owner")[0] == "ask"
    got = (proj / ".security" / G.AUDIT_NAME).read_text().splitlines()
    assert len(got) == 1 and json.loads(got[0])["decision"] == "ask"
