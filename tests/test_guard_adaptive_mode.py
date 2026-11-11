"""7.2 adaptive mode: coding while the session looks normal, strict after a risk signal; the current mode is in the audit.

coding: shell syntax the guard cannot follow but whose commands it checked is allowed and audited.
strict: the 7.1 reading, the same shapes ask.
Escalation (adaptive policy): a block earlier in the session, three questions in ten minutes, a download in the last
fifteen minutes. A pinned policy ("coding" or "strict") never escalates; auto, don't-ask, bypass and managed are strict.
"""
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402

SYNTAX = "echo $(date)"
SESSION = "sess-adaptive-1"


@pytest.fixture
def env(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    cache = tmp_path / "cache"
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    monkeypatch.setenv("SECURECODE_CACHE_DIR", str(cache))
    monkeypatch.setattr(G, "managed_markers", lambda: [])
    pol = tmp_path / "guard-policy.json"
    monkeypatch.setattr(G, "policy_path", lambda: pol)

    def set_policy(**kw):
        pol.write_text(json.dumps({"mode": "owner", **kw}), encoding="utf-8")
    set_policy()
    return type("E", (), {"proj": proj, "cache": cache, "policy": staticmethod(set_policy)})


def ev(cmd, proj, session=SESSION, pm=None, tool="Bash"):
    e = {"tool_name": tool, "tool_input": {"command": cmd}, "cwd": str(proj), "session_id": session}
    if pm:
        e["permission_mode"] = pm
    return e


def verdict(e, mode="owner"):
    r = G.decide(e, mode)
    return r[0] if r else "allow"


def audit_lines(proj):
    f = proj / ".security" / G.AUDIT_NAME
    return [json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []


def test_the_default_is_adaptive_and_a_fresh_session_is_coding(env):
    assert G.guard_pref() == "adaptive"
    assert G.guard_mode(ev(SYNTAX, env.proj), "owner") == "coding"
    assert verdict(ev(SYNTAX, env.proj)) == "allow"


def test_an_allowed_syntax_shape_is_audited_with_the_mode(env):
    assert verdict(ev(SYNTAX, env.proj)) == "allow"
    rows = audit_lines(env.proj)
    assert len(rows) == 1 and rows[0]["decision"] == "coding-allowed" and rows[0]["guard_mode"] == "coding"
    assert rows[0]["mode"] == "owner" and rows[0]["agent"] == "claude"


def test_a_pinned_strict_policy_asks_and_says_so_in_the_audit(env):
    env.policy(adaptive="strict")
    assert verdict(ev(SYNTAX, env.proj)) == "ask"
    rows = audit_lines(env.proj)
    assert rows[-1]["decision"] == "ask" and rows[-1]["guard_mode"] == "strict"


def test_a_pinned_coding_policy_does_not_escalate(env):
    env.policy(adaptive="coding")
    for _ in range(4):
        assert verdict(ev("cat .env", env.proj)) == "deny"
    assert G.guard_mode(ev(SYNTAX, env.proj), "owner") == "coding"
    assert verdict(ev(SYNTAX, env.proj)) == "allow"


def test_a_block_earlier_in_the_session_makes_it_strict(env):
    assert verdict(ev(SYNTAX, env.proj)) == "allow"
    assert verdict(ev("cat .env", env.proj)) == "deny"
    assert G.session_risk(ev(SYNTAX, env.proj)) == "a command was blocked earlier in this session"
    assert G.guard_mode(ev(SYNTAX, env.proj), "owner") == "strict"
    assert verdict(ev(SYNTAX, env.proj)) == "ask"


def test_the_escalation_belongs_to_one_session(env):
    assert verdict(ev("cat .env", env.proj, session="a")) == "deny"
    assert verdict(ev(SYNTAX, env.proj, session="a")) == "ask"
    assert verdict(ev(SYNTAX, env.proj, session="b")) == "allow"


def test_a_burst_of_questions_makes_it_strict(env):
    for _ in range(3):
        assert verdict(ev("git push --force origin main", env.proj)) == "ask"
    assert G.session_risk(ev(SYNTAX, env.proj)) == "three questions in ten minutes"
    assert verdict(ev(SYNTAX, env.proj)) == "ask"


def test_questions_spread_over_time_do_not_escalate(env):
    d = G._state_file(ev(SYNTAX, env.proj))
    old = time.time() - 3000
    d.mkdir(parents=True, exist_ok=True)
    for i in range(3):
        (d / f"{int((old + i) * 1e9)}-ask-1").write_text("")
    assert G.session_risk(ev(SYNTAX, env.proj)) is None
    assert verdict(ev(SYNTAX, env.proj)) == "allow"


def test_a_download_makes_the_next_quarter_hour_strict(env):
    assert verdict(ev("curl -s http://localhost:8000/health", env.proj)) in ("allow", "ask")
    G._state_add(ev(SYNTAX, env.proj), "fetch")
    assert G.session_risk(ev(SYNTAX, env.proj)) == "something was downloaded in the last fifteen minutes"
    assert verdict(ev(SYNTAX, env.proj)) == "ask"
    assert G.session_risk(ev(SYNTAX, env.proj), now=time.time() + 1000) is None


def test_an_event_without_a_session_id_is_coding_and_writes_no_state(env):
    e = ev(SYNTAX, env.proj, session="")
    assert G.guard_mode(e, "owner") == "coding"
    verdict(ev("cat .env", env.proj, session=""))
    assert not env.cache.exists() or not list(env.cache.glob("guard-session-*"))


@pytest.mark.parametrize("pm", ["auto", "dontAsk"])
def test_unattended_runs_are_strict_and_refuse(env, pm):
    assert G.guard_mode(ev(SYNTAX, env.proj, pm=pm), "owner") == "strict"
    assert verdict(ev(SYNTAX, env.proj, pm=pm)) == "deny"


def test_bypass_asks_nothing_for_syntax(env):
    assert verdict(ev(SYNTAX, env.proj, pm="bypassPermissions")) == "allow"


def test_managed_mode_denies_the_syntax_shapes(env):
    assert verdict(ev(SYNTAX, env.proj), "managed") == "deny"


def test_an_unlisted_program_still_asks_in_coding_mode(env):
    assert verdict(ev("frobnicate --now", env.proj)) == "ask"
    assert verdict(ev("sudo id", env.proj)) == "ask"


def test_the_state_file_is_in_the_app_cache_never_in_the_project(env):
    verdict(ev("cat .env", env.proj))
    assert list(env.cache.glob("guard-session-*"))
    assert not list(env.proj.rglob("guard-session-*"))


def test_a_planted_or_oversized_state_file_is_ignored(env):
    d = G._state_file(ev(SYNTAX, env.proj))
    d.mkdir(parents=True, exist_ok=True)
    (d / "deny").write_text("x")
    (d / "1-deny-1").write_text("")                              # not a valid name
    (d / f"{int((time.time() + 9999) * 1e9)}-deny-1").write_text("")   # a time in the future
    (d / f"{int(time.time() * 1e9)}-bogus-1").write_text("")
    assert G.session_risk(ev(SYNTAX, env.proj)) is None
    (d.parent / "x").write_text("a file where the session folder should be")
    assert G.session_risk(ev(SYNTAX, env.proj, session="x")) is None


def test_a_bad_adaptive_value_makes_the_policy_malformed(env):
    env.policy(adaptive="loose")
    assert G.load_policy()[0] == "managed"
    assert G.guard_pref() == "strict"


def _sibling():
    # below the home folder and outside the temp folder (which the guard always treats as inside)
    return Path.home() / "Projects" / "zz-guard-sibling-probe"


def test_the_policy_workspace_roots_are_for_reads_only(env, tmp_path):
    sib = _sibling()
    env.policy(workspace_roots=[str(sib.parent)])
    assert verdict(ev(f"grep -rn foo {sib.as_posix()}/src", env.proj)) == "allow"
    assert verdict(ev(f"ls {sib.as_posix()}", env.proj)) == "allow"
    assert verdict(ev(f"cat {sib.as_posix()}/.env", env.proj)) == "deny"
    assert verdict(ev(f"rm {sib.as_posix()}/a.txt", env.proj)) == "ask"
    assert verdict(ev(f"echo x > {sib.as_posix()}/a.txt", env.proj)) == "ask"
    assert verdict(ev(f"cp {sib.as_posix()}/a.txt .", env.proj)) == "allow"        # a read of the sibling, a write in the project
    assert verdict(ev(f"cp x {sib.as_posix()}/a.txt", env.proj)) == "ask"


def test_without_workspace_roots_a_sibling_read_asks(env, tmp_path):
    sib = _sibling()
    assert verdict(ev(f"grep -rn foo {sib.as_posix()}/src", env.proj)) == "ask"


def test_workspace_roots_are_ignored_for_a_managed_policy(env, tmp_path, monkeypatch):
    sib = _sibling()
    env.policy(workspace_roots=[str(sib.parent)])
    monkeypatch.setattr(G, "managed_markers", lambda: [str(tmp_path / "guard-policy.json")])
    assert verdict(ev(f"grep -rn foo {sib.as_posix()}/src", env.proj), "managed") == "deny"


def test_a_workspace_root_that_is_the_home_folder_or_a_drive_root_is_refused(env):
    home = Path.home()
    env.policy(workspace_roots=[str(home), str(Path(home.anchor)), "relative/path"])
    g = G.GuardEnv({"cwd": str(env.proj)})
    assert g.ws == []
