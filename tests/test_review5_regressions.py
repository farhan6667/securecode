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


# Names that must never appear in public text. Only their SHA-256 hashes are stored here, so this guard
# does not publish the very names it protects. Every substring of a word with one of these lengths is hashed
# and compared, so the names are also caught inside longer words.
_BLOCKED_SHA256 = {
    "34f01161e6d553bad21aa46e5162c7deae536434632760b9ce840d80c65ef948",
    "cc5d93e2859817ef766e3715ea3e37b40e99e5ef7bc3e178dd925d798cdca1eb",
    "a084a7e06dee42b19858e7407800275db2465f301922e49b6e462d5b514a1193",
    "56b14f835e40e007bacef2b50777ac1eec3f2119006747c1a40bfa1a2c4868e2",
    "2be6d1ec07641b6f004938912f89876a153c963a53cba7fed04ed0c818690f0f",
}
_BLOCKED_LENGTHS = (4, 5, 6, 7)


def _blocked_hits(text):
    import hashlib
    import re
    found = set()
    for word in set(re.findall(r"\w+", text.lower())):
        for n in _BLOCKED_LENGTHS:
            for i in range(len(word) - n + 1):
                part = word[i:i + n]
                if hashlib.sha256(part.encode("utf-8")).hexdigest() in _BLOCKED_SHA256:
                    found.add(hashlib.sha256(part.encode("utf-8")).hexdigest()[:12])
    return found


def test_blocked_name_check_catches_a_planted_name():
    # A word whose hash is listed must be reported, also inside a longer word; ordinary words must not be.
    assert not _blocked_hits("ordinary security text about the gate")
    planted = "x" + "fai" + "zan" + "y"
    assert _blocked_hits(planted)


def test_no_organization_names_in_tracked_text():
    hits = []
    for f in ROOT.rglob("*"):
        if f.is_file() and not {".git", ".ai-media", "__pycache__", ".pytest_cache", ".hypothesis"} & set(f.parts) \
                and f.suffix in (".py", ".md", ".json", ".yml", ".yaml", ".txt", ".php", ".ps1", ".sh", ".toml",
                                 ".cff", ""):
            found = _blocked_hits(f.read_text(encoding="utf-8", errors="ignore"))
            if found and f.name != "test_review5_regressions.py":
                hits.append((str(f.relative_to(ROOT)), sorted(found)))
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
