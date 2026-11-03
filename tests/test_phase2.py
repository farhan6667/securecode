"""Phase 2: optional Retire.js and Psalm taint scanners, the package age check and the nuclei wrapper."""
import datetime as dt, importlib.util, json, os, subprocess, sys, urllib.error
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


def test_retire_and_psalm_are_skipped_when_missing():
    g = load("scripts/secgate.py", "sg_p2a")
    real = g.find_tool
    try:
        g.find_tool = lambda name: None
        assert g.collect_retire(Path("."), []) == (None, "")
        assert g.collect_psalm(Path("."), []) == (None, "")
    finally:
        g.find_tool = real


def test_retire_report_becomes_library_findings(tmp_path):
    g = load("scripts/secgate.py", "sg_p2b")
    report = {"data": [{"file": "public/js/jquery.min.js", "results": [
        {"component": "jquery", "version": "2.2.4", "vulnerabilities": [
            {"severity": "medium", "identifiers": {"CVE": ["CVE-2020-11022"]}},
            {"severity": "medium", "identifiers": {"CVE": ["CVE-2019-11358"]}}]},
        {"component": "lodash", "version": "4.17.21", "vulnerabilities": []}]}]}

    def fake_run(cmd, cwd, timeout=600):
        out = Path(cmd[cmd.index("--outputpath") + 1])
        out.write_text(json.dumps(report), encoding="utf-8")
        return 13, "", ""
    real_run, real_find = g.run, g.find_tool
    try:
        g.find_tool, g.run = (lambda name: name), fake_run
        findings = []
        ok, msg = g.collect_retire(tmp_path, findings)
    finally:
        g.run, g.find_tool = real_run, real_find
    assert ok and "1 vulnerable" in msg
    assert [(f["rule"], f["severity"]) for f in findings] == [("VULNERABLE_LIBRARY", "HIGH")]
    assert "CVE-2019-11358" in findings[0]["message"] and "jquery 2.2.4" in findings[0]["message"]


def test_psalm_taint_issues_are_high(tmp_path):
    g = load("scripts/secgate.py", "sg_p2c")
    (tmp_path / "composer.json").write_text("{}")
    (tmp_path / "vendor" / "bin").mkdir(parents=True)
    (tmp_path / "vendor" / "bin" / "psalm").write_text("<?php")
    issues = [{"type": "TaintedSql", "file_path": "app/Repo.php", "line_from": 12, "message": "sql", "snippet": "DB::select($q)"},
              {"type": "UnusedVariable", "file_path": "app/A.php", "line_from": 3, "message": "x"}]
    real_run, real_find = g.run, g.find_tool
    try:
        g.find_tool = lambda name: "php"
        g.run = lambda cmd, cwd, timeout=600: (2, json.dumps(issues), "")
        findings = []
        assert g.collect_psalm(tmp_path, findings)[0]
    finally:
        g.run, g.find_tool = real_run, real_find
    assert [(f["rule"], f["severity"], f["line"]) for f in findings] == [("PSALM_TaintedSql", "HIGH", 12)]


NOW = dt.datetime(2026, 11, 3, tzinfo=dt.timezone.utc)


def fake_registry(url):
    if url == "https://registry.npmjs.org/express":
        return {"time": {"4.21.2": "2024-12-05T10:00:00.000Z", "5.9.0": "2026-11-01T10:00:00.000Z"}}
    if url == "https://registry.npmjs.org/@scope%2Fpkg":        # the registry's own form for scoped names
        return {"time": {"1.0.0": "2025-01-01T00:00:00Z"}}
    if url.startswith("https://pypi.org/pypi/requests/2.32.3/json"):
        return {"urls": [{"upload_time_iso_8601": "2024-05-29T15:37:47.613Z"}]}
    if url == "https://repo.packagist.org/p2/laravel/framework.json":
        return {"packages": {"laravel/framework": [{"version": "v12.3.0", "time": "2025-03-18T15:00:00+00:00"}]}}
    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


def test_package_age_rules():
    m = load("scripts/package_age.py", "pkg_age")
    run = lambda *a: m.main(list(a), fetch=fake_registry, now=NOW)
    assert run("npm", "express", "4.21.2") == 0
    assert run("npm", "@scope/pkg", "1.0.0") == 0
    assert run("npm", "express", "5.9.0") == 1                    # two days old
    assert run("npm", "expresss", "1.0.0") == 2                   # does not exist
    assert run("npm", "express", "9.9.9") == 2                    # version not published
    assert run("pypi", "requests", "2.32.3", "--min-days", "30") == 0
    assert run("packagist", "laravel/framework", "v12.3.0") == 0
    for bad in (("npm", "../etc/passwd", "1.0.0"), ("npm", "x", "v-1/../"), ("pypi", "a b", "1"), ("npm", "Express", "1.0.0")):
        assert run(*bad) == 2, bad


def test_package_age_name_check_is_fast():
    import time
    m = load("scripts/package_age.py", "pkg_age3")
    t = time.perf_counter()
    for name in ("a" * 40 + "/a!", "a" * 28 + "!", "a-" * 300 + "/x"):
        assert m.main(["packagist", name, "1.0.0"], fetch=fake_registry, now=NOW) == 2
    assert time.perf_counter() - t < 1


def test_package_age_refuses_other_hosts():
    m = load("scripts/package_age.py", "pkg_age2")
    for url in ("http://registry.npmjs.org/x", "https://evil.example/x", "file:///etc/passwd"):
        try:
            m.fetch_json(url)
            assert False, url
        except ValueError:
            pass


def test_nuclei_wrapper_refuses_without_permission_and_bad_targets():
    m = load("scripts/run-nuclei-authorized.py", "nuclei_wrap")
    assert m.check_url("https://staging.example.com/app") is None
    for bad in ("http://169.254.169.254/latest", "https://metadata.google.internal/", "ftp://x", "https://a b",
                "https://shop.prod.example.com", "-u http://x", "http://[fe80::1]/", "http://metadata.google.internal./",
                "http://169.254.169.254.nip.io/", "http://instance-data/latest", "https://api-prod.example.com"):
        assert m.check_url(bad), bad
    env = {k: v for k, v in os.environ.items() if not k.startswith("SECURITY_DAST")}
    p = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "run-nuclei-authorized.py")], env=env,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 4 and "not run" in p.stdout
