"""Gaps found by an outside review and a fresh-install test of 7.0 (V7GAP-1 to V7GAP-4, V7GAP-A to V7GAP-G):
the installed skill and rules name the exact Python, the PowerShell signature check, the minimum Python version,
the --agent option for Cursor, Codex, Gemini CLI and Antigravity, the aisec/ folder in the release zip, doctor and
setup on a project folder, PowerShell-safe paths, install_file status, a failed update task as a failed check, and
--no-update-task. Every test uses a temp HOME, CLAUDE_CONFIG_DIR and LOCALAPPDATA; nothing touches the real ones."""
import ast, importlib.util, json, os, re, shlex, shutil, subprocess, sys, types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


G = load(ROOT / "install-global.py", "inst_gapfix")


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    for k in ("LOCALAPPDATA", "XDG_DATA_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(k, str(tmp_path / "env" / k.lower()))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude"))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(G, "HOME", tmp_path / "home")
    (tmp_path / "home").mkdir()


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# ---------- V7GAP-1: <PY> instead of a bare "python" ----------

def test_source_skill_and_rules_use_the_py_token_not_bare_python():
    for rel in (".claude/skills/security-review/SKILL.md", "AGENTS.md"):
        t = text(rel)
        assert "<PY>" in t, rel
        assert '`python "' not in t and '`python3 "' not in t, rel
    for f in (ROOT / ".claude").rglob("*.md"):
        assert not re.search(r'`python3? +"', f.read_text(encoding="utf-8")), f


def test_install_fills_py_in_skill_commands_rules_and_global_claude_md(tmp_path):
    ad = G.app_dir()
    G.install_runtime(ROOT, ad)
    G.install_skill()
    G.install_commands()
    G.install_user_claude_md()
    want = G.py_command()
    assert want.endswith(" -I") and want.startswith('"')
    installed = list((G.claude_dir() / "skills" / "org-appsec-security").rglob("*.md"))
    installed += list((G.claude_dir() / "commands").glob("*.md")) + [G.claude_dir() / "CLAUDE.md", ad / "AGENTS.md"]
    for f in installed:
        t = f.read_text(encoding="utf-8")
        assert "<PY>" not in t, f
        assert '`python "' not in t, f
    skill = (G.claude_dir() / "skills" / "org-appsec-security" / "SKILL.md").read_text(encoding="utf-8")
    assert f'`{want} "<APP>/scripts/secgate.py" . --mode ci' in skill
    assert f'`{want} "%LOCALAPPDATA%' in (ad / "AGENTS.md").read_text(encoding="utf-8")
    # Line endings of the package file are kept (the fill works on bytes).
    src = (ROOT / ".claude/skills/security-review/SKILL.md").read_bytes()
    dst = (G.claude_dir() / "skills" / "org-appsec-security" / "SKILL.md").read_bytes()
    assert (b"\r\n" in src) == (b"\r\n" in dst)


def test_a_second_install_like_an_update_fills_the_token_again():
    # An update re-runs install-global.py, which copies the package skill again (with <PY>) and fills it again.
    G.install_skill(); G.install_skill()
    skill = (G.claude_dir() / "skills" / "org-appsec-security" / "SKILL.md").read_text(encoding="utf-8")
    assert "<PY>" not in skill and skill.count(G.py_command()) >= 6


def test_py_command_quotes_paths_with_spaces_and_prefers_the_console_python(tmp_path, monkeypatch):
    d = tmp_path / "Program Files" / "Python 3"
    d.mkdir(parents=True)
    (d / "python.exe").write_text(""); (d / "pythonw.exe").write_text("")
    cmd = G.py_command(str(d / "pythonw.exe"))
    exe = shlex.split(cmd.replace("\\", "/"))[0]
    assert exe.endswith("python.exe") and " " in exe and cmd.endswith(" -I")
    monkeypatch.setattr(G, "SYSTEM", "linux")
    assert G.py_command("/opt/py $HOME/bin/python3") == "python3 -I"     # cannot be quoted safely: launcher name
    monkeypatch.setattr(G, "SYSTEM", "windows")
    assert G.py_command("C:/Users/a%PATH%b/python.exe") == "py -3 -I"
    assert G.cmd_path(r"C:\Users\Some One\py.exe", "windows") == "C:/Users/Some One/py.exe"
    for bad in ('C:/a"b', "C:/a`b", "C:/a$b", "C:/a!b", "C:/a\nb"):
        with pytest.raises(ValueError):
            G.cmd_path(bad, "windows")


def test_managed_install_fills_py_and_its_own_runtime_path(tmp_path):
    root = tmp_path / "pf"
    p = subprocess.run([sys.executable, "-I", str(ROOT / "install-managed.py"), "--root", str(root)],
                       capture_output=True, text=True, timeout=180, encoding="utf-8")
    assert p.returncode == 0, p.stderr
    agents = (root / "OrgAISecureAppSec" / "AGENTS.md").read_text(encoding="utf-8")
    assert "<PY>" not in agents and "%LOCALAPPDATA%\\OrgAISecureAppSec" not in agents
    assert str(root / "OrgAISecureAppSec") in agents


# ---------- V7GAP-2 and V7GAP-A: PowerShell signature check, aisec/ folder ----------

# The signature-check and zip-folder doc tests live in tests/test_v7_docs.py.


# ---------- V7GAP-C: doctor and setup on the project folder ----------

def test_docs_run_doctor_and_setup_on_a_project_folder():
    one = text("ONE_PROMPT_INSTALL.md").split("```", 2)[1]
    assert 'securecode.py doctor "<my project folder>"' in one
    assert 'securecode.py setup "<my project folder>"' in one
    assert 'securecode.py setup --yes "<my project folder>"' in one
    hand = text("README.md").split("<summary>Install by hand instead</summary>", 1)[1].split("</details>", 1)[0]
    assert re.search(r'securecode\.py doctor "[^"]+"', hand) and re.search(r'securecode\.py setup --yes "[^"]+"', hand)
    # The documented syntax is what securecode.py really parses.
    sc = load(ROOT / "scripts" / "securecode.py", "sc_gapfix_parse")
    assert sc.is_securecode_package(ROOT)


def test_securecode_notes_when_pointed_at_its_own_package(tmp_path):
    sc = load(ROOT / "scripts" / "securecode.py", "sc_gapfix")
    assert sc.is_securecode_package(ROOT)
    assert not sc.is_securecode_package(tmp_path)
    app = tmp_path / "OrgAISecureAppSec" / "scripts"
    app.mkdir(parents=True)
    (app / "securecode.py").write_text(""); (app / "secgate.py").write_text("")
    assert sc.is_securecode_package(app.parent)


# ---------- V7GAP-D: no %LOCALAPPDATA% where PowerShell would run it ----------

def test_readme_powershell_and_bash_blocks_do_not_use_cmd_variables():
    blocks = re.findall(r"```(\w*)\r?\n(.*?)```", text("README.md"), re.S)
    for lang, body in blocks:
        if lang in ("bash", "powershell", "sh", ""):
            assert "%LOCALAPPDATA%" not in body, (lang, body[:120])


# ---------- V7GAP-3: minimum Python ----------

def test_python_older_than_3_10_is_refused_with_the_found_version():
    with pytest.raises(RuntimeError) as e:
        G.check_python_version((3, 9, 18), exe="C:/Python39/python.exe")
    msg = str(e.value)
    assert "3.9.18" in msg and "3.10" in msg and "python.org" in msg and "C:/Python39/python.exe" in msg
    G.check_python_version((3, 10, 0))
    G.check_python_version((3, 14, 1))


def test_main_refuses_old_python_before_touching_anything(monkeypatch, tmp_path):
    monkeypatch.setattr(G, "sys", types.SimpleNamespace(version_info=(3, 8, 10, "final", 0), executable="old-python"))
    with pytest.raises(RuntimeError, match="3.8.10"):
        G.main(["--verify-only"])
    assert not G.app_dir().exists()


def test_scripts_with_union_none_annotations_import_on_old_pythons():
    # "X | None" in an annotation is evaluated at import time before 3.10 unless annotations are postponed.
    bad = []
    for f in list((ROOT / "scripts").rglob("*.py")) + list(ROOT.glob("*.py")):
        src = f.read_text(encoding="utf-8")
        if "from __future__ import annotations" in src:
            continue
        for n in ast.walk(ast.parse(src)):
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr) and any(
                    isinstance(x, ast.Constant) and x.value is None for x in (n.left, n.right)):
                bad.append(f"{f.relative_to(ROOT)}:{n.lineno}")
    assert not bad, bad
    assert "from __future__ import annotations" in text("scripts/run-nuclei-authorized.py")


# ---------- V7GAP-4: --agent for Cursor, Codex, Gemini CLI and Antigravity ----------

def app_with_runtime(tmp_path, name="OrgAISecureAppSec"):
    ad = tmp_path / "rt" / name
    G.install_runtime(ROOT, ad)
    return ad


def commands(data):
    out = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k == "command" and isinstance(v, str): out.append(v)
            else: out += commands(v)
    elif isinstance(data, list):
        for v in data: out += commands(v)
    return out


@pytest.mark.parametrize("agent,script", [("cursor", "adapters/cursor_hook.py"), ("codex", "adapters/codex_hook.py"),
                                          ("gemini", "adapters/gemini_hook.py"),
                                          ("antigravity", "adapters/antigravity_hook.py")])
def test_agent_writes_a_filled_config_to_the_documented_place(tmp_path, agent, script):
    ad = app_with_runtime(tmp_path, "Org Apps/OrgAISecureAppSec")    # a space in the path
    msg = G.install_agent(agent, ad, G.HOME)
    target = G.agent_config_path(agent, G.HOME)
    assert str(target) in msg and "(new file)" in msg
    assert str(target).startswith(str(tmp_path / "home"))
    raw = target.read_text(encoding="utf-8")
    assert "<PYTHON>" not in raw and "<APP>" not in raw
    cmds = commands(json.loads(raw))
    assert cmds
    for c in cmds:
        argv = shlex.split(c[2:] if c.startswith("& ") else c)   # the way the shell splits it (minus PowerShell's &)
        assert argv[1] == "-I" and Path(argv[0]) == Path(G.console_python())
        assert argv[2].startswith(G.cmd_path(ad)) and Path(argv[2]).is_file()
    assert any(c.endswith(script + '"') for c in cmds)
    assert G.adapter_status(G.HOME)[agent] == str(target)
    assert agent in G.read_agent_record(ad)


PWSH = shutil.which("pwsh") or shutil.which("powershell")
PARSE = ("$e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput($env:NFSC_HOOK_CMD,[ref]$null,[ref]$e); "
         "exit $e.Count")


def pwsh_parse_errors(cmd: str) -> int:
    env = dict(os.environ, NFSC_HOOK_CMD=cmd)
    return subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", PARSE], env=env, capture_output=True,
                          text=True, timeout=60).returncode


def test_windows_templates_are_chosen_on_windows_and_fill_command_windows(tmp_path):
    assert G.agent_template_file("gemini", system="windows").name == "settings.hooks.windows.json"
    assert G.agent_template_file("gemini", system="linux").name == "settings.hooks.json"
    pkg = tmp_path / "pkg"
    (pkg / "templates" / "codex").mkdir(parents=True)
    (pkg / "templates" / "codex" / "hooks.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": '"<PYTHON>" -I "<APP>/scripts/adapters/codex_hook.py"',
         "commandWindows": '& "<PYTHON>" -I "<APP>/scripts/adapters/codex_hook.py"'}]}]}}), encoding="utf-8")
    filled = G.agent_template("codex", tmp_path / "OrgAISecureAppSec", pkg=pkg)
    h = filled["hooks"]["PreToolUse"][0]["hooks"][0]
    assert "<PYTHON>" not in json.dumps(filled) and "<APP>" not in json.dumps(filled)
    assert h["commandWindows"].startswith('& "') and G._is_ours(h["commandWindows"])


@pytest.mark.skipif(not PWSH, reason="PowerShell not installed")
def test_windows_gemini_command_parses_in_powershell(tmp_path, monkeypatch):
    # V7L-01: Gemini CLI runs hooks in PowerShell on Windows; '"python" -I ...' is a parse error there.
    monkeypatch.setattr(G, "SYSTEM", "windows")
    ad = app_with_runtime(tmp_path, "Org Apps/OrgAISecureAppSec")
    cmds = commands(G.agent_template("gemini", ad))
    assert cmds and all(c.startswith('& "') for c in cmds)
    for c in cmds:
        assert pwsh_parse_errors(c) == 0, c
    assert pwsh_parse_errors(cmds[0][2:]) > 0      # the old form really is a parse error (the test can fail)


@pytest.mark.parametrize("agent", G.AGENT_NAMES)
def test_agent_is_idempotent(tmp_path, agent):
    ad = app_with_runtime(tmp_path)
    G.install_agent(agent, ad, G.HOME)
    target = G.agent_config_path(agent, G.HOME)
    first = target.read_bytes()
    assert "already up to date" in G.install_agent(agent, ad, G.HOME)
    assert target.read_bytes() == first
    assert not (ad / "backups").exists() or not any((ad / "backups").rglob(f"{agent}-*"))


def test_agent_merges_into_existing_settings_and_backs_them_up(tmp_path):
    ad = app_with_runtime(tmp_path)
    gem = G.agent_config_path("gemini", G.HOME)
    gem.parent.mkdir(parents=True)
    mine = {"theme": "dark", "context": {"fileName": ["AGENTS.md"]},
            "hooks": {"BeforeTool": [{"matcher": "run_shell", "hooks": [{"type": "command", "command": "my-check"}]}],
                      "AfterTool": [{"matcher": "*", "hooks": [{"type": "command", "command": "log"}]}]}}
    gem.write_text(json.dumps(mine), encoding="utf-8")
    msg = G.install_agent("gemini", ad, G.HOME)
    assert "backup:" in msg
    got = json.loads(gem.read_text(encoding="utf-8"))
    assert got["theme"] == "dark" and got["context"] == mine["context"]
    assert got["hooks"]["AfterTool"] == mine["hooks"]["AfterTool"]
    assert got["hooks"]["BeforeTool"][0] == mine["hooks"]["BeforeTool"][0]
    assert len(got["hooks"]["BeforeTool"]) == 2
    backups = list((ad / "backups").rglob("gemini-settings.json"))
    assert backups and json.loads(backups[0].read_text(encoding="utf-8")) == mine

    cur = G.agent_config_path("cursor", G.HOME)
    cur.parent.mkdir(parents=True)
    cur.write_text(json.dumps({"version": 7, "hooks": {"afterFileEdit": [{"command": "fmt"}],
                                                       "beforeShellExecution": [{"command": "mine.sh"}]}}), encoding="utf-8")
    G.install_agent("cursor", ad, G.HOME)
    c = json.loads(cur.read_text(encoding="utf-8"))
    assert c["version"] == 7 and c["hooks"]["afterFileEdit"] == [{"command": "fmt"}]
    assert c["hooks"]["beforeShellExecution"][0] == {"command": "mine.sh"} and len(c["hooks"]["beforeShellExecution"]) == 2


def test_agent_replaces_its_old_entry_instead_of_adding_a_second(tmp_path):
    old_app = app_with_runtime(tmp_path / "old")
    new_app = app_with_runtime(tmp_path / "new")
    G.install_agent("codex", old_app, G.HOME)
    G.install_agent("codex", new_app, G.HOME)
    data = json.loads(G.agent_config_path("codex", G.HOME).read_text(encoding="utf-8"))
    cmds = commands(data)
    assert len(cmds) == 2 and all(G.cmd_path(new_app) in c for c in cmds)
    assert "description" not in data     # the fill-in note from the template is not copied


def test_two_agents_in_the_same_second_keep_separate_backups(tmp_path):
    ad = app_with_runtime(tmp_path)
    for a in ("cursor", "antigravity"):
        p = G.agent_config_path(a, G.HOME); p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"mine": a}), encoding="utf-8")
        G.install_agent(a, ad, G.HOME)
    names = sorted(p.name for p in (ad / "backups").rglob("*-hooks.json"))
    assert names == ["antigravity-hooks.json", "cursor-hooks.json"]


@pytest.mark.parametrize("bad", ["{not json", '{"a": 1,}', "// comment\n{}", "[1, 2]", '{"hooks": []}',
                                 '{"hooks": {"beforeShellExecution": {"command": "x"}}}'])
def test_agent_refuses_a_file_it_cannot_merge_and_leaves_it_untouched(tmp_path, bad):
    ad = app_with_runtime(tmp_path)
    cur = G.agent_config_path("cursor", G.HOME)
    cur.parent.mkdir(parents=True)
    cur.write_text(bad, encoding="utf-8")
    with pytest.raises(RuntimeError, match="Nothing was changed|nothing was changed"):
        G.install_agent("cursor", ad, G.HOME)
    assert cur.read_text(encoding="utf-8") == bad
    res = G.install_agents(ad, ["cursor"], G.HOME)
    assert res[0].startswith("FAILED cursor")


def test_agent_refuses_to_write_through_a_link(tmp_path):
    ad = app_with_runtime(tmp_path)
    real = tmp_path / "dotfiles" / "hooks.json"; real.parent.mkdir()
    real.write_text("{}", encoding="utf-8")
    link = G.agent_config_path("cursor", G.HOME); link.parent.mkdir(parents=True)
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not allowed here")
    with pytest.raises(RuntimeError, match="link"):
        G.install_agent("cursor", ad, G.HOME)
    assert real.read_text(encoding="utf-8") == "{}"


def test_codex_home_is_honoured(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "ch"))
    assert G.agent_config_path("codex", G.HOME) == tmp_path / "ch" / "hooks.json"
    monkeypatch.setenv("CODEX_HOME", "relative/dir")       # not absolute: ignored
    assert G.agent_config_path("codex", G.HOME) == G.HOME / ".codex" / "hooks.json"


def test_later_runs_refresh_recorded_agents_but_respect_a_removed_hook(tmp_path):
    ad = app_with_runtime(tmp_path)
    G.install_agents(ad, ["cursor", "antigravity"], G.HOME)
    assert G.read_agent_record(ad) == ["cursor", "antigravity"]
    out = G.install_agents(ad, None, G.HOME)                # an update: no --agent flags
    assert all("already up to date" in x for x in out), out
    ag = G.agent_config_path("antigravity", G.HOME)
    ag.write_text(json.dumps({"other": {}}), encoding="utf-8")   # the user removed our hook
    out = G.install_agents(ad, None, G.HOME)
    assert any("left as it is" in x for x in out)
    assert json.loads(ag.read_text(encoding="utf-8")) == {"other": {}}
    assert G.adapter_status(G.HOME) == {"cursor": str(G.agent_config_path("cursor", G.HOME)), "codex": None,
                                        "gemini": None, "antigravity": None}


def test_agent_option_is_parsed_and_rejects_unknown_tools():
    with pytest.raises(SystemExit):
        G.main(["--agent", "vscode"])
    with pytest.raises(SystemExit):
        G.main(["--verify-only", "--agent", "cursor"])


def test_verify_global_lists_installed_adapters(tmp_path):
    local = tmp_path / "local"
    home = tmp_path / "vhome"
    hooks = home / ".cursor" / "hooks.json"; hooks.parent.mkdir(parents=True)
    hooks.write_text(json.dumps({"version": 1, "hooks": {"beforeShellExecution": [
        {"command": '"py" -I "C:/x/OrgAISecureAppSec/scripts/adapters/cursor_hook.py"'}]}}), encoding="utf-8")
    env = dict(os.environ, PATH="", LOCALAPPDATA=str(local), XDG_DATA_HOME=str(local), XDG_CONFIG_HOME=str(tmp_path / "cfg"),
               CLAUDE_CONFIG_DIR=str(tmp_path / "claude"), HOME=str(home), USERPROFILE=str(home))
    env.pop("CODEX_HOME", None)
    v = subprocess.run([sys.executable, "-I", str(ROOT / "verify-global.py")], env=env,
                       capture_output=True, text=True, timeout=120, encoding="utf-8")
    out = json.loads(v.stdout[:v.stdout.rindex("}") + 1])
    assert out["adapters"]["cursor"] == str(hooks)
    assert out["adapters"]["codex"] is None and out["adapters"]["gemini"] is None


# ---------- V7GAP-E: install_file says "created" on a fresh install ----------

def test_install_file_reports_created_then_updated_then_exists(tmp_path):
    src = tmp_path / "s.md"; src.write_text("x", encoding="utf-8")
    dst = tmp_path / "out" / "s.md"
    assert G.install_file(src, dst) == "created"
    assert G.install_file(src, dst) == "updated"
    assert G.install_file(src, dst, overwrite=False) == "exists"


# ---------- V7GAP-F and V7GAP-G: failed update task, --no-update-task ----------

class Recorder:
    def __init__(self, rc=0):
        self.calls, self.rc = [], rc

    def __call__(self, args, **kw):
        self.calls.append(list(args))
        if "/Query" in args:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")
        return types.SimpleNamespace(returncode=self.rc, stdout="", stderr="Access is denied." if self.rc else "")


def update_ready(tmp_path):
    app = tmp_path / "app"
    (app / "config").mkdir(parents=True)
    (app / "config" / "update.json").write_text(json.dumps({"repo": "org/x", "asset": "a.zip"}), encoding="utf-8")
    (app / "config" / "allowed_signers").write_text("org ssh-ed25519 AAAAtest\n", encoding="utf-8")
    return app


def test_a_failed_task_is_a_failed_check(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    app = update_ready(tmp_path)
    res = G.register_updates(app, run=Recorder(rc=1))
    assert res.startswith("schedule failed")
    assert G.verify(app, res)["auto_update"] is False
    assert G.verify(app, "scheduled daily (Task Scheduler: X Update)")["auto_update"] is True
    assert G.verify(app, "skipped: no update config")["auto_update"] is True
    assert "auto_update" not in G.verify(app)            # --verify-only has no result to judge
    for bad in ("schedule skipped: Python path is empty", "systemd user timer written but systemctl --user enable failed: x",
                "launchd agent written to p but launchctl was not found; add to crontab"):
        assert G.auto_update_ok(bad) is False, bad
    assert G.auto_update_ok("scheduled daily (Task Scheduler: failed was not found Update)")   # a name is not a result
    assert G.auto_update_ok("add to crontab: 0 11 * * * python updater.py (or re-run with --update-timer ...)")


def test_no_update_task_never_calls_schtasks_and_is_remembered(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    app = update_ready(tmp_path)
    G.set_update_task_off(app, True)
    rec = Recorder()
    res = G.register_updates(app, run=rec)
    assert rec.calls == [] and res.startswith("skipped: update task turned off")
    assert G.auto_update_ok(res)
    assert G.register_updates(app, run=rec).startswith("skipped") and rec.calls == []   # a later run keeps it off
    G.set_update_task_off(app, False)                                                  # --update-task
    G.register_updates(app, run=rec)
    assert rec.calls and "/Create" in rec.calls[0]


def test_no_update_task_and_update_task_are_exclusive_flags():
    with pytest.raises(SystemExit):
        G.main(["--no-update-task", "--update-task"])


def test_exit_code_is_4_only_when_the_schedule_alone_failed():
    good = {"runtime": True, "agent_guard": True}
    assert G.exit_code(dict(good, auto_update=True)) == 0
    assert G.exit_code(dict(good)) == 0
    assert G.exit_code(dict(good, auto_update=False)) == G.EXIT_SCHEDULE_ONLY == 4
    assert G.exit_code(dict(good, runtime=False, auto_update=False)) == 1
    assert G.exit_code(dict(good, auto_update=False), ["FAILED cursor: x"]) == 1
    upd = load(ROOT / "scripts" / "updater.py", "upd_gapfix_code")
    assert upd.INSTALL_SCHEDULE_ONLY == G.EXIT_SCHEDULE_ONLY


KEYGEN = shutil.which("ssh-keygen")


@pytest.mark.skipif(not KEYGEN, reason="ssh-keygen not installed")
@pytest.mark.parametrize("rc,want", [(4, "updated-schedule-warning"), (0, "updated"), (1, "install-failed rc=1")])
def test_updater_reports_a_schedule_only_failure_as_updated_with_a_warning(tmp_path, rc, want):
    import zipfile
    app = tmp_path / "app"
    (app / "scripts").mkdir(parents=True); (app / "config").mkdir()
    shutil.copy2(ROOT / "scripts" / "updater.py", app / "scripts" / "updater.py")
    (app / "install-report.json").write_text(json.dumps({"version": "7.0.0"}), encoding="utf-8")
    key = tmp_path / "k"
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "t", "-f", str(key)], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    (app / "config" / "allowed_signers").write_text("security@org " + (tmp_path / "k.pub").read_text(), encoding="utf-8")
    z = tmp_path / "Org_AI.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("aisec/install-global.py", f'VERSION="7.9.0"\nimport sys\nsys.exit({rc})\n')
    subprocess.run([KEYGEN, "-Y", "sign", "-f", str(key), "-n", "org-appsec-update", str(z)], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    sig = Path(str(z) + ".sig")

    def fetch(kind, url, dest):
        if kind == "release":
            return {"tag_name": "v7.9.0", "assets": [{"name": "Org_AI.zip", "url": "zip", "size": z.stat().st_size},
                                                    {"name": "Org_AI.zip.sig", "url": "sig", "size": sig.stat().st_size}]}
        shutil.copy2(z if url == "zip" else sig, dest)
    upd = load(app / "scripts" / "updater.py", f"upd_gapfix_{rc}")
    cfg = {"repo": "org/x", "asset": "Org_AI.zip", "signer_identity": "security@org"}
    assert upd.check_and_update(cfg, None, fetch=fetch, workdir=tmp_path / "w") == want
    if rc == 4:
        assert "schedule warning" in upd.result_line(want) and "updated to" in upd.result_line(want)


# ---------- V7GAP-H: unquoted, space-free Python in Windows hook lines (Codex commandWindows, Antigravity) ----------

def test_bare_python_shortens_a_path_with_spaces():
    calls = []

    def short(p):
        calls.append(p)
        return r"C:\PROGRA~1\PYTHON~1\python.exe"
    assert G.bare_python(r"C:\Program Files\Python 3\python.exe", short) == "C:/PROGRA~1/PYTHON~1/python.exe"
    assert calls == [r"C:\Program Files\Python 3\python.exe"]
    assert G.bare_python(r"C:\Python312\python.exe", lambda p: pytest.fail("no short name needed")) == "C:/Python312/python.exe"


@pytest.mark.parametrize("short", ["", r"C:\Program Files\Python 3\python.exe", r"C:\A&B\python.exe", r"C:\a^b\py.exe",
                                   r"C:\a%b%\py.exe", 'C:\\a"b\\py.exe', r"C:\a;b\py.exe"])
def test_bare_python_refuses_when_no_safe_short_form_exists(short):
    with pytest.raises(RuntimeError, match="without spaces"):
        G.bare_python(r"C:\Program Files\Python 3\python.exe", lambda p: short)


@pytest.mark.parametrize("agent", ["codex", "antigravity"])
def test_windows_lines_get_the_short_path_and_quoted_lines_the_full_one(tmp_path, monkeypatch, agent):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    exe = r"C:\Program Files\Python 3\python.exe"
    filled = G.agent_template(agent, tmp_path / "OrgAISecureAppSec", exe=exe,
                              get_short=lambda p: r"C:\PROGRA~1\PYTHON~1\python.exe")
    raw = json.dumps(filled)
    assert "<PYTHON>" not in raw and "<APP>" not in raw
    if agent == "codex":
        entries = [h for ev in filled["hooks"].values() for g in ev for h in g["hooks"]]
        assert all(h["commandWindows"].startswith('C:/PROGRA~1/PYTHON~1/python.exe -I "') for h in entries)
        assert all(h["command"].startswith('"C:/Program Files/Python 3/python.exe" -I') for h in entries)
    else:
        cmds = commands(filled)
        assert cmds and all(c.startswith('C:/PROGRA~1/PYTHON~1/python.exe -I "') for c in cmds)


@pytest.mark.parametrize("agent", ["codex", "antigravity"])
def test_windows_adapter_is_refused_and_nothing_written_without_a_short_path(tmp_path, monkeypatch, agent):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    monkeypatch.setattr(G, "_get_short_path_name", lambda p: "")
    monkeypatch.setattr(G, "console_python", lambda exe=None: r"C:\Program Files\Python 3\python.exe")
    ad = app_with_runtime(tmp_path)
    res = G.install_agents(ad, [agent], G.HOME)
    assert res[0].startswith(f"FAILED {agent}") and "without spaces" in res[0]
    assert not G.agent_config_path(agent, G.HOME).exists()
    # Gemini has no unquoted line, so it still installs with the same Python.
    assert not G.install_agents(ad, ["gemini"], G.HOME)[0].startswith("FAILED")


@pytest.mark.skipif(os.name != "nt", reason="Windows hook lines")
def test_installer_filled_windows_lines_really_deny_in_every_shell(tmp_path, monkeypatch):
    """The lines --agent writes (not hand-filled ones) run in pwsh, Windows PowerShell and cmd, and deny."""
    V = load(ROOT / "tests" / "test_v7_guard.py", "v7guard_for_gapfix")
    if V._plain_python() is None:
        pytest.skip("no space-free path to this Python")
    shells = V._hook_shells()
    project, app, env = V._runtime_with_space(tmp_path)
    monkeypatch.setattr(G, "SYSTEM", "windows")
    codex = G.agent_template("codex", app)["hooks"]["PreToolUse"][0]["hooks"][0]["commandWindows"]
    anti = commands(G.agent_template("antigravity", app))[0]
    assert not codex.startswith(('"', "&")) and not anti.startswith(('"', "&"))
    ev = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git reset --hard"},
                     "cwd": str(project)})
    a = json.dumps({"workspacePaths": [str(project)], "toolCall": {"name": "run_command", "args": {"CommandLine": "cat .env"}}})
    assert shells
    for name, wrap in shells.items():
        p = subprocess.run(wrap(codex), input=ev, text=True, capture_output=True, env=env, cwd=project, timeout=60,
                           encoding="utf-8")
        assert V._codex_verdict(p) == "deny", (name, p.returncode, p.stderr[-300:])
        p = subprocess.run(wrap(anti), input=a, text=True, capture_output=True, env=env, cwd=project, timeout=60,
                           encoding="utf-8")
        assert p.returncode == 0 and json.loads(p.stdout)["decision"] == "deny", (name, p.returncode, p.stderr[-300:])


def test_windows_installer_passes_its_arguments_on():
    ps = text("install-windows.ps1")
    assert '"$Root\\install-global.py" @args' in ps
    assert "--no-update-task" in text("ENTERPRISE_DEPLOYMENT.md")
