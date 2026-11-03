"""R2-M5 and R2-L1: git run by the stop gate and by the scanners must not run programs named in the scanned repo's
own .git/config (core.fsmonitor, hooks, filter and textconv drivers, external diff), and must see non-ASCII names."""
import importlib.util, json, os, shutil, subprocess, sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(not GIT, reason="git not installed")


def load(name):
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(name + "_sg_t", SCRIPTS / f"{name}.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        sys.path.pop(0)


def git(d, *a, env=None):
    return subprocess.run([GIT, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *a],
                          cwd=d, capture_output=True, env=env)


def hostile_repo(tmp_path):
    """A repo whose .git/config names programs for fsmonitor, a clean filter, a textconv driver, external diff and
    hooks. Each program only creates a marker file, so the test can see whether git ran it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "app.py").write_text("print(1)\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "init")
    marks = tmp_path / "marks"
    marks.mkdir()
    scripts = {}
    for name, body in (("fsmonitor", "printf '\\0'"), ("clean", "cat"), ("textconv", "cat \"$1\""), ("extdiff", "true"),
                       ("hook", "true")):
        f = tmp_path / f"{name}.sh"
        f.write_text(f"#!/bin/sh\necho ran > '{(marks / name).as_posix()}'\n{body}\n", newline="\n")
        f.chmod(0o755)
        scripts[name] = f.as_posix()
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    for h in ("post-checkout", "pre-commit", "post-index-change", "reference-transaction"):
        (hooks / h).write_text(f"#!/bin/sh\necho ran > '{(marks / ('hook-' + h)).as_posix()}'\n", newline="\n")
        (hooks / h).chmod(0o755)
    cfg = (repo / ".git" / "config").read_text()
    cfg += (f"[core]\n\tfsmonitor = sh '{scripts['fsmonitor']}'\n\thooksPath = {hooks.as_posix()}\n"
            f"[filter \"evil\"]\n\tclean = sh '{scripts['clean']}'\n\trequired = true\n"
            f"[diff \"evil\"]\n\ttextconv = sh '{scripts['textconv']}'\n"
            f"[diff]\n\texternal = sh '{scripts['extdiff']}'\n")
    (repo / ".git" / "config").write_text(cfg)
    (repo / ".gitattributes").write_text("*.py filter=evil diff=evil\n")
    (repo / "app.py").write_text("print(2)\n")
    return repo, marks


def test_fixture_really_runs_code_without_protection(tmp_path):
    repo, marks = hostile_repo(tmp_path)
    git(repo, "status")
    git(repo, "diff", "HEAD")
    assert list(marks.iterdir()), "the hostile fixture did not run anything; the test below would prove nothing"


def test_stop_gate_git_runs_nothing_from_repo_config(tmp_path):
    repo, marks = hostile_repo(tmp_path)
    sg = load("stop_gate")
    files = sg.changed_files(repo)
    sg.line_counts(repo)
    assert {p.name for p in files} >= {"app.py", ".gitattributes"}, files
    assert not list(marks.iterdir()), [p.name for p in marks.iterdir()]
    # and the whole hook process
    p = subprocess.run([sys.executable, "-I", str(SCRIPTS / "stop_gate.py")], input=json.dumps({"cwd": str(repo)}),
                       text=True, capture_output=True, timeout=120, encoding="utf-8")
    assert p.returncode == 0, p.stderr
    assert not list(marks.iterdir()), [p.name for p in marks.iterdir()]


def test_scanner_runs_get_the_safe_git_environment(tmp_path):
    repo, marks = hostile_repo(tmp_path)
    g = load("secgate")
    rc, out, err = g.run(["git", "diff", "--no-ext-diff", "HEAD"], repo)
    assert rc == 0 and "print(2)" in out, err
    rc, out, err = g.run(["git", "log", "-p", "-1"], repo)
    assert rc == 0, err
    rc, out, err = g.run(["git", "status"], repo)
    assert rc == 0, err
    assert not list(marks.iterdir()), [p.name for p in marks.iterdir()]
    sgit = load("safe_git")
    env = sgit.safe_git_env(GIT, repo, str(tmp_path / "nohooks"))
    keys = {env[f"GIT_CONFIG_KEY_{i}"].lower(): env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert keys["core.fsmonitor"] == "false" and keys["filter.evil.clean"] == "cat" and keys["diff.evil.textconv"] == "cat"
    assert keys["core.hookspath"] == str(tmp_path / "nohooks") and keys["filter.evil.required"] == "false"


def test_engine_env_keeps_its_values_but_gets_the_safe_git_settings(tmp_path):
    # Merge of v7 (engines pass their own env, e.g. GOTOOLCHAIN=local) and v7-guard (safe git): an engine run must
    # keep its own variables, lose any GIT_* it carries and still run nothing from the repo's .git/config.
    repo, marks = hostile_repo(tmp_path)
    g = load("secgate")
    base = dict(os.environ, NFSC_ENGINE_MARK="kept", GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.fsmonitor",
                GIT_CONFIG_VALUE_0="sh evil", GIT_DIR=str(tmp_path / "elsewhere"))
    env = g.scanner_env(repo, str(tmp_path / "nohooks"), base)
    assert env["NFSC_ENGINE_MARK"] == "kept" and "GIT_DIR" not in env
    keys = {env[f"GIT_CONFIG_KEY_{i}"].lower(): env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert keys["core.fsmonitor"] == "false" and keys["filter.evil.clean"] == "cat"
    rc, out, err = g.run(["git", "status"], repo, env=base)
    assert rc == 0, err
    rc, out, err = g.run(["git", "diff", "--no-ext-diff", "HEAD"], repo, env=base)
    assert rc == 0 and "print(2)" in out, err
    assert not list(marks.iterdir()), [p.name for p in marks.iterdir()]


def test_inherited_git_variables_are_dropped(monkeypatch, tmp_path):
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor=evil'")
    sgit = load("safe_git")
    env = sgit.safe_git_env(None, tmp_path, str(tmp_path / "h"))
    assert "GIT_DIR" not in env and "GIT_CONFIG_PARAMETERS" not in env


def test_stop_gate_sees_non_ascii_and_quoted_names(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    git(repo, "init", "-q")
    bad = "import os\nprint(os.getcwd())\n"
    names = ["plain.py", "ünsafe.py", "مثال.py"] + ([] if os.name == "nt" else ['a b"q.py'])
    for n in names:
        (repo / n).write_text(bad, encoding="utf-8")
    sg = load("stop_gate")
    found = {p.name for p in sg.changed_files(repo)}
    assert set(names) <= found, found
