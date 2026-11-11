"""7.2: guard_switch.py mode and workspace (the owner's own settings; need a terminal, owner policy only)."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import guard_switch as S  # noqa: E402
import agent_guard as G  # noqa: E402


@pytest.fixture
def pol(tmp_path):
    p = tmp_path / "guard-policy.json"
    p.write_text(json.dumps({"mode": "owner", "version": 1}), encoding="utf-8")
    return p


def data(p):
    return json.loads(p.read_text(encoding="utf-8"))


def test_mode_is_written_and_adaptive_removes_the_key(pol):
    assert S.write_mode("strict", pol, [], need_terminal=False) == "strict"
    assert data(pol)["adaptive"] == "strict" and G.guard_pref(pol) == "strict"
    S.write_mode("coding", pol, [], need_terminal=False)
    assert G.guard_pref(pol) == "coding"
    S.write_mode("adaptive", pol, [], need_terminal=False)
    assert "adaptive" not in data(pol) and G.guard_pref(pol) == "adaptive"


def test_a_bad_mode_is_refused_and_nothing_changes(pol):
    before = pol.read_text()
    with pytest.raises(S.SwitchRefused):
        S.write_mode("loose", pol, [], need_terminal=False)
    assert pol.read_text() == before


def test_without_a_terminal_it_is_refused(pol):
    with pytest.raises(S.SwitchRefused):
        S.write_mode("strict", pol, [])                     # pytest has no terminal on stdin
    with pytest.raises(S.SwitchRefused):
        S.write_workspace("clear", None, pol, [])


def test_a_managed_or_missing_policy_is_refused(tmp_path, pol):
    with pytest.raises(S.SwitchRefused):
        S.write_mode("strict", pol, [str(pol)], need_terminal=False)       # a managed marker is present
    with pytest.raises(S.SwitchRefused):
        S.write_mode("strict", tmp_path / "missing.json", [], need_terminal=False)


def test_workspace_add_and_clear(pol, tmp_path):
    d = tmp_path / "sibling-folder"
    d.mkdir()
    got = S.write_workspace("add", str(d), pol, [], need_terminal=False)
    assert got == [str(Path(d).resolve())] and data(pol)["workspace_roots"] == got
    assert S.write_workspace("add", str(d), pol, [], need_terminal=False) == got        # no duplicate
    assert S.write_workspace("clear", None, pol, [], need_terminal=False) == []
    assert "workspace_roots" not in data(pol)


@pytest.mark.parametrize("bad", [str(Path.home()), str(Path(Path.home().anchor)), "relative/dir", "", None])
def test_workspace_refuses_the_home_folder_a_drive_root_and_relative_paths(pol, bad):
    with pytest.raises(S.SwitchRefused):
        S.write_workspace("add", bad, pol, [], need_terminal=False)


def test_the_other_settings_of_the_policy_survive(pol):
    pol.write_text(json.dumps({"mode": "owner", "version": 1, "guard": "off", "note": "n"}), encoding="utf-8")
    S.write_mode("strict", pol, [], need_terminal=False)
    d = data(pol)
    assert d["guard"] == "off" and d["adaptive"] == "strict" and d["mode"] == "owner"


def test_the_installer_keeps_the_owners_mode_and_folders_on_a_repair(tmp_path):
    sys.path.insert(0, str(ROOT))
    import importlib.util
    spec = importlib.util.spec_from_file_location("install_global_x", ROOT / "install-global.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    ad = tmp_path / "app"
    (ad / "config").mkdir(parents=True)
    f = ad / "config" / m.POLICY_NAME
    f.write_text(json.dumps({"mode": "owner", "version": 1, "adaptive": "strict", "workspace_roots": [str(tmp_path)],
                             "remote_wrappers": ["mosh"]}), encoding="utf-8")
    assert m.install_guard_policy(ad, "owner") == "owner"
    d = json.loads(f.read_text())
    assert d["adaptive"] == "strict" and d["workspace_roots"] == [str(tmp_path)] and d["remote_wrappers"] == ["mosh"]
    f.write_text(json.dumps({"mode": "owner", "adaptive": "loose", "workspace_roots": "x", "evil": 1}), encoding="utf-8")
    m.install_guard_policy(ad, "owner")
    d = json.loads(f.read_text())
    assert d == {"mode": "owner", "version": 1}              # an invalid file is not carried over
