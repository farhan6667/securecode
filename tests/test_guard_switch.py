"""7.1 command guard on/off switch (scripts/guard_switch.py, "guard": "off" in config/guard-policy.json).

Off switches off the PreToolUse command guard only. It is honoured in owner mode only, never for a managed install or a
broken policy file, it needs a person at a terminal to change, and an update keeps it.
"""
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402
import guard_switch as SW  # noqa: E402


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


INSTALL = load(ROOT / "install-global.py", "install_global_switch")


def policy(tmp_path, **kw):
    p = tmp_path / "guard-policy.json"
    p.write_text(json.dumps({"mode": "owner", "version": 1, **kw}), encoding="utf-8")
    return p


FORCE_PUSH = {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}, "cwd": str(ROOT)}


def test_off_is_read_only_from_an_owner_policy_that_says_off_exactly(tmp_path):
    assert G.guard_is_off(policy(tmp_path, guard="off"), markers=[])
    for bad in ("OFF", "Off", " off", "off ", "on", "", None, True, 1, ["off"], {"a": 1}):
        assert not G.guard_is_off(policy(tmp_path, guard=bad), markers=[]), bad
    assert not G.guard_is_off(policy(tmp_path), markers=[])


def test_off_is_never_honoured_for_managed_or_a_broken_policy(tmp_path, monkeypatch):
    p = tmp_path / "guard-policy.json"
    p.write_text(json.dumps({"mode": "managed", "version": 1, "guard": "off"}), encoding="utf-8")
    assert not G.guard_is_off(p, markers=[])
    # a managed install on the machine overrides the per-user file
    marker = tmp_path / "managed-settings.json"
    marker.write_text("{}", encoding="utf-8")
    assert not G.guard_is_off(policy(tmp_path, guard="off"), markers=[str(marker)])
    # missing, malformed, duplicate keys, oversized, unknown key
    assert not G.guard_is_off(tmp_path / "nope.json", markers=[])
    for text in ("{not json", '{"mode":"owner","mode":"owner","guard":"off"}', '{"mode":"owner","guard":"off","x":1}',
                 json.dumps({"mode": "owner", "guard": "off", "note": "x" * 5000})):
        p.write_text(text, encoding="utf-8")
        assert not G.guard_is_off(p, markers=[]), text[:30]


def test_decide_and_main_skip_everything_only_when_off(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(G, "policy_path", lambda: policy(tmp_path))
    monkeypatch.setattr(G, "managed_markers", lambda: [])
    assert G.decide(FORCE_PUSH)[0] == "ask"                    # on: the guard asks as before
    monkeypatch.setattr(G, "policy_path", lambda: policy(tmp_path, guard="off"))
    assert G.decide(FORCE_PUSH) is None                        # off: nothing
    monkeypatch.setattr(sys, "stdin", io.StringIO("this is not json"))
    assert G.main() == 0                                       # off: even a broken event is not blocked
    capsys.readouterr()
    monkeypatch.setattr(G, "policy_path", lambda: policy(tmp_path))
    monkeypatch.setattr(sys, "stdin", io.StringIO("this is not json"))
    assert G.main() == 2                                       # on: unreadable input still fails closed
    # an explicit mode (the tests, the adapters that pass one) is not affected by the file
    assert G.decide(FORCE_PUSH, "managed")[0] == "deny"


def test_off_does_not_touch_the_other_security_scripts():
    # the switch lives in agent_guard only; the shield, edit hook, stop gate and watch know nothing about it
    for name in ("secret_shield.py", "global_hook.py", "stop_gate.py", "injection_watch.py", "secgate.py"):
        assert "guard_is_off" not in (ROOT / "scripts" / name).read_text(encoding="utf-8"), name


def test_the_script_refuses_without_a_terminal(tmp_path):
    env = dict(os.environ)
    r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "guard_switch.py"), "off"], input="", capture_output=True,
                       text=True, env=env, timeout=60)
    assert r.returncode == 3 and "terminal" in r.stderr
    r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "guard_switch.py"), "nonsense"], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 2


def test_write_switch_round_trip_and_refusals(tmp_path):
    p = policy(tmp_path)
    assert SW.state(p, [])[0] == "on"
    assert SW.write_switch("off", p, [], need_terminal=False) == "off"
    data = json.loads(p.read_text())
    assert data["mode"] == "owner" and data["guard"] == "off" and set(data) <= G.POLICY_KEYS
    assert SW.write_switch("on", p, [], need_terminal=False) == "on"
    assert "guard" not in json.loads(p.read_text())
    with pytest.raises(SW.SwitchRefused):                       # managed policy: the switch is not used
        m = tmp_path / "m.json"
        m.write_text(json.dumps({"mode": "managed", "version": 1}), encoding="utf-8")
        SW.write_switch("off", m, [], need_terminal=False)
    marker = tmp_path / "managed-settings.json"
    marker.write_text("{}", encoding="utf-8")
    with pytest.raises(SW.SwitchRefused):                       # a managed install on the machine
        SW.write_switch("off", policy(tmp_path), [str(marker)], need_terminal=False)
    with pytest.raises(SW.SwitchRefused):                       # a missing policy is managed
        SW.write_switch("off", tmp_path / "missing.json", [], need_terminal=False)


def test_an_update_keeps_the_switch_and_a_mode_change_to_managed_drops_it(tmp_path):
    ad = tmp_path / "app"
    (ad / "config").mkdir(parents=True)
    pol = ad / "config" / "guard-policy.json"
    pol.write_text(json.dumps({"mode": "owner", "version": 1, "guard": "off", "note": "set by the owner"}), encoding="utf-8")
    assert INSTALL.install_guard_policy(ad) == "owner"                   # the daily update re-runs the installer
    assert json.loads(pol.read_text())["guard"] == "off"
    assert INSTALL.install_guard_policy(ad, "owner") == "owner"          # an explicit repair to owner keeps it
    assert json.loads(pol.read_text())["guard"] == "off"
    assert INSTALL.install_guard_policy(ad, "managed") == "managed"      # managed never carries the switch
    assert "guard" not in json.loads(pol.read_text())


def test_importing_write_switch_does_not_skip_the_terminal_check(tmp_path):
    # review finding: the terminal check lived only in main(), so a script that imported write_switch skipped it
    p = policy(tmp_path)
    with pytest.raises(SW.SwitchRefused, match="terminal"):
        SW.write_switch("off", p, [])
    assert "guard" not in json.loads(p.read_text())


@pytest.mark.parametrize("pm", [None, "auto", "bypassPermissions"])
def test_the_agent_may_not_run_or_name_the_runtime_switch_in_any_mode(pm, tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    local = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    for cmd in (f'python "{local}/OrgAISecureAppSec/scripts/guard_switch.py" off',
                'python "%LOCALAPPDATA%/OrgAISecureAppSec/scripts/guard_switch.py" off',
                'python ~/AppData/Local/OrgAISecureAppSec/scripts/guard_switch.py off',
                'cd "$LOCALAPPDATA/OrgAISecureAppSec/scripts" && python -I guard_switch.py off'):
        e = {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(ROOT)}
        if pm:
            e["permission_mode"] = pm
        r = G.decide(e, "owner")
        assert r and r[0] == "deny", (cmd, pm, r)
    # a developer working on this repository can still read and run the repo's own copy and its tests
    for cmd in ("py -I scripts/guard_switch.py status", "pytest tests/test_guard_switch.py -q"):
        e = {"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(ROOT)}
        if pm:
            e["permission_mode"] = pm
        r = G.decide(e, "owner")
        assert not (r and r[0] == "deny" and "guard switch" in r[1]), (cmd, pm, r)


def test_every_guard_adapter_honours_the_switch(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(G, "managed_markers", lambda: [])
    cursor = {"hook_event_name": "beforeShellExecution", "command": "git push --force", "cwd": str(ROOT)}
    codex = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git push --force"}, "cwd": str(ROOT)}
    gemini = {"tool_name": "run_shell_command", "tool_input": {"command": "git push --force"}, "cwd": str(ROOT)}
    anti = {"workspacePaths": [str(ROOT)], "toolCall": {"name": "run_command", "args": {"CommandLine": "git push --force"}}}
    adapters = Path(ROOT / "scripts" / "adapters")
    mods = {n: load_adapter(adapters / f"{n}_hook.py", n) for n in ("cursor", "codex", "gemini", "antigravity")}

    def verdicts():
        return (mods["cursor"].handle(cursor)["permission"], mods["codex"].handle(codex)[0],
                mods["gemini"].handle(gemini)[0], mods["antigravity"].handle(anti)["decision"])

    monkeypatch.setattr(G, "policy_path", lambda: policy(tmp_path))
    on = verdicts()
    assert on[0] != "allow" and on[1] == 2 and on[2] == 2 and on[3] != "allow", on
    monkeypatch.setattr(G, "policy_path", lambda: policy(tmp_path, guard="off"))
    assert verdicts() == ("allow", 0, 0, "allow"), verdicts()


def load_adapter(path, name):
    spec = importlib.util.spec_from_file_location("sw_adapter_" + name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_a_busy_policy_file_is_a_retry_not_a_refusal(tmp_path, monkeypatch):
    p = policy(tmp_path)
    calls = {"n": 0}
    real = os.replace

    def flaky(a, b):
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError("in use")
        return real(a, b)

    monkeypatch.setattr(SW.os, "replace", flaky)
    monkeypatch.setattr(SW.time, "sleep", lambda s: None)
    assert SW.write_switch("off", p, [], need_terminal=False) == "off" and calls["n"] == 3
    monkeypatch.setattr(SW.os, "replace", lambda a, b: (_ for _ in ()).throw(PermissionError("in use")))
    with pytest.raises(PermissionError):                       # not SwitchRefused: main() says "try again", not "refused"
        SW.write_switch("on", p, [], need_terminal=False)
    assert not list(tmp_path.glob(".policy-*.tmp"))


def test_a_repair_does_not_launder_an_invalid_off_file(tmp_path):
    ad = tmp_path / "app"
    (ad / "config").mkdir(parents=True)
    pol = ad / "config" / "guard-policy.json"
    for text in ('{"mode":"owner","mode":"owner","guard":"off"}', '{"mode":"owner","version":1,"guard":"off","extra":1}',
                 '{"mode":"owner","version":1,"guard":"off","note":"' + "x" * 6000 + '"}'):
        pol.write_text(text, encoding="utf-8")
        INSTALL.install_guard_policy(ad, "owner")                # an explicit repair
        assert "guard" not in json.loads(pol.read_text()), text[:40]
    pol.write_text(json.dumps({"mode": "owner", "version": 1, "guard": "off", "note": "n" * 500}), encoding="utf-8")
    INSTALL.install_guard_policy(ad, "owner")
    kept = json.loads(pol.read_text())
    assert kept["guard"] == "off" and len(kept["note"]) == 200


def test_off_drains_stdin_before_returning(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "policy_path", lambda: policy(tmp_path, guard="off"))
    monkeypatch.setattr(G, "managed_markers", lambda: [])
    fake = io.StringIO('{"x": 1}')
    monkeypatch.setattr(sys, "stdin", fake)
    assert G.main() == 0 and fake.read() == ""
