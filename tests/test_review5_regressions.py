"""Regressions from the fifth (pre-release) independent review."""
import importlib.util, json, subprocess, sys, tempfile, types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    m = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        spec.loader.exec_module(m)
    finally:
        sys.path.pop(0)
    return m


def write(d, rel, text):
    f = Path(d, rel)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")
    return f


def test_no_organization_names_in_tracked_text():
    bad = ()      # last one is the Urdu word
    hits = []
    for f in ROOT.rglob("*"):
        if f.is_file() and not {".git", ".ai-media", "__pycache__", ".pytest_cache"} & set(f.parts) and f.suffix in (
                ".py", ".md", ".json", ".yml", ".yaml", ".txt", ".php", ".ps1", ".sh", ".toml", ".cff", ""):
            low = f.read_text(encoding="utf-8", errors="ignore").lower()
            hits += [(f.name, b) for b in bad if b in low and f.name != "test_review5_regressions.py"]
    assert not hits, hits


def test_psalm_runs_only_with_run_tests(tmp_path):
    g = load("scripts/secgate.py", "sg_r5a")
    write(tmp_path, "composer.json", "{}")
    write(tmp_path, "vendor/bin/psalm", "<?php")
    called = []
    real_run, real_find = g.run, g.find_tool
    try:
        g.find_tool = lambda name: None if name in ("semgrep", "trivy", "gitleaks", "retire") else name
        g.run = lambda cmd, cwd, timeout=600: (called.append(cmd), (0, "[]", ""))[1]
        import os
        old = os.getcwd(); os.chdir(tmp_path)
        try:
            sys.argv = ["secgate", ".", "--mode", "full", "--fail-on", "never"]
            g.main()
            assert not any("psalm" in " ".join(map(str, c)) for c in called), called
            sys.argv = ["secgate", ".", "--mode", "full", "--fail-on", "never", "--run-tests"]
            g.main()
            assert any("psalm" in " ".join(map(str, c)) for c in called), called
        finally:
            os.chdir(old)
    finally:
        g.run, g.find_tool = real_run, real_find


def test_malformed_optional_reports_are_notes_not_crashes(tmp_path):
    g = load("scripts/secgate.py", "sg_r5b")
    report = {"data": [{"file": "a.js", "results": [{"component": "x", "version": "1",
                                                     "vulnerabilities": [{"severity": "high", "identifiers": ["bad"]}]}]}]}

    def fake_run(cmd, cwd, timeout=600):
        if "--outputpath" in cmd:
            Path(cmd[cmd.index("--outputpath") + 1]).write_text(json.dumps(report), encoding="utf-8")
        return 0, "[]", ""
    real_run, real_find = g.run, g.find_tool
    import os
    old = os.getcwd(); os.chdir(tmp_path)
    try:
        g.find_tool = lambda name: None if name in ("semgrep", "trivy", "gitleaks") else name
        g.run = fake_run
        sys.argv = ["secgate", ".", "--mode", "full", "--fail-on", "never"]
        assert g.main() in (0, 2)
    finally:
        os.chdir(old)
        g.run, g.find_tool = real_run, real_find


def test_test_paths_are_judged_inside_the_project(tmp_path):
    g = load("scripts/secgate.py", "sg_r5c")
    proj = tmp_path / "spec" / "shop"                           # "spec" above the project must not count
    write(proj, "app/ids.py", "import hashlib\nx = hashlib.md5(b'id').hexdigest()\n")
    write(proj, "tests/test_ids.py", "import hashlib\nx = hashlib.md5(b'id').hexdigest()\n")
    sev = {Path(f["file"]).parent.name: f["severity"] for f in g.local_scan(proj) if f["rule"] == "INSECURE_CRYPTO"}
    assert sev == {"app": "HIGH", "tests": "MEDIUM"}, sev
    cookie = tmp_path / "app-latest"
    write(cookie, "config/session.php", "<?php return ['secure' => false, 'http_only' => false];\n")
    assert [f for f in g.config_scan(cookie) if f["rule"] == "INSECURE_COOKIE_FLAG"]


def test_recorded_task_name_must_be_valid_before_schtasks(tmp_path):
    G = load("install-global.py", "ig_r5")
    calls = []

    def run(args, **kw):
        calls.append(args)
        return types.SimpleNamespace(returncode=0, stdout=b'<Exec><Command>py</Command><Arguments>"C:\\U\\updater.py"</Arguments></Exec>', stderr="")
    for bad in ("x\" /TN evil", "Evil", "a&b Update", "-x Update"):
        (tmp_path / G.TASK_RECORD).write_text(json.dumps({"task_name": bad}), encoding="utf-8")
        calls.clear()
        G.retire_old_task(tmp_path, "Acme SecureCode Update", "C:\\U\\updater.py", run)
        assert not any(bad in a for c in calls for a in c), (bad, calls)


def test_task_xml_in_utf16_or_ansi_still_matches():
    G = load("install-global.py", "ig_r5b")
    path = "C:\\Users\\Jos\u00e9 & Co\\AppData\\updater.py"
    xml = f"<Arguments>&quot;{path.replace('&', '&amp;')}&quot;</Arguments>"
    for raw in (("\ufeff" + xml).encode("utf-16-le"), xml.encode("utf-8")):
        assert path.lower() in G._xml_text(raw).lower()
