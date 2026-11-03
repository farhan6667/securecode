"""scripts/ci/check_skips.py: a skipped test that is not on tests/skip-allowlist.json fails CI."""
import importlib.util, json, subprocess, sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_skips_t", ROOT / "scripts" / "ci" / "check_skips.py")
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def junit(tmp: Path, cases) -> Path:
    body = "".join(
        f'<testcase classname="{c}" name="{n}">' + (f'<skipped type="pytest.skip" message="{m}"/>' if m else "") + "</testcase>"
        for c, n, m in cases)
    f = tmp / "junit.xml"
    f.write_text(f'<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest">{body}</testsuite></testsuites>',
                 encoding="utf-8")
    return f


def allowlist(tmp: Path, entries) -> Path:
    f = tmp / "allow.json"
    f.write_text(json.dumps({"allowed": entries}), encoding="utf-8")
    return f


def test_node_ids_match_pytest():
    assert C.node_id("tests.test_x", "test_a[p-1]") == "tests/test_x.py::test_a[p-1]"
    assert C.node_id("tests.test_x.TestThing", "test_a") == "tests/test_x.py::TestThing::test_a"
    assert C.node_id("", "tests.test_fuzz_guard") == "tests/test_fuzz_guard.py"


def test_unlisted_skip_fails_and_listed_skip_passes(tmp_path, capsys):
    j = junit(tmp_path, [("tests.test_laravel_authz", "test_rules", "semgrep is not on PATH"),
                         ("tests.test_v7_engines", "test_real[bandit]", "bandit is not installed"),
                         ("tests.test_ok", "test_ran", "")])
    a = allowlist(tmp_path, [{"test": "tests/test_v7_engines.py::test_real[[]bandit[]]", "reason": "optional engine"}])
    assert C.main([str(j), str(a)]) == 1
    out = capsys.readouterr().out
    assert "NOT ALLOWED: tests/test_laravel_authz.py::test_rules" in out and "allowed: tests/test_v7_engines.py::test_real[bandit]" in out
    j2 = junit(tmp_path, [("tests.test_v7_engines", "test_real[bandit]", "bandit is not installed")])
    assert C.main([str(j2), str(a)]) == 0


def test_os_and_python_conditions_narrow_an_entry(tmp_path, monkeypatch):
    j = junit(tmp_path, [("", "tests.test_fuzz_guard", "could not import hypothesis")])
    a = allowlist(tmp_path, [{"test": "tests/test_fuzz_guard.py*", "python": ["3.10"], "reason": "hypothesis needs 3.11"}])
    monkeypatch.setattr(C.platform, "python_version_tuple", lambda: ("3", "10", "4"))
    assert C.main([str(j), str(a)]) == 0
    monkeypatch.setattr(C.platform, "python_version_tuple", lambda: ("3", "12", "1"))
    assert C.main([str(j), str(a)]) == 1
    j2 = junit(tmp_path, [("tests.test_v7_guard", "test_links", "symlinks not available")])
    a2 = allowlist(tmp_path, [{"test": "tests/test_v7_guard.py::test_links", "os": ["windows"], "reason": "runner rights"}])
    monkeypatch.setattr(C, "current_os", lambda: "linux")
    assert C.main([str(j2), str(a2)]) == 1
    monkeypatch.setattr(C, "current_os", lambda: "windows")
    assert C.main([str(j2), str(a2)]) == 0


@pytest.mark.parametrize("bad", [
    '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><testsuites>&a;</testsuites>',
    "<testsuites><testcase",
])
def test_unreadable_or_hostile_junit_fails_closed(tmp_path, bad):
    j = tmp_path / "j.xml"; j.write_text(bad, encoding="utf-8")
    assert C.main([str(j), str(allowlist(tmp_path, []))]) == 1


@pytest.mark.parametrize("entries", [{"allowed": [{"test": "x"}]}, {"allowed": [{"test": "", "reason": "r"}]}, [1],
                                     {"allowed": [{"test": "x", "reason": "r", "os": "windows"}]}])
def test_allowlist_entries_need_a_pattern_and_a_reason(tmp_path, entries):
    a = tmp_path / "a.json"; a.write_text(json.dumps(entries), encoding="utf-8")
    assert C.main([str(junit(tmp_path, [])), str(a)]) == 1


def test_repo_allowlist_is_valid_and_has_no_scanner_or_keygen_tests():
    entries = C.load_allowlist(ROOT / "tests" / "skip-allowlist.json")
    text = json.dumps([e["test"] for e in entries]).lower()
    for tool_test in ("laravel_authz", "java_spring", "benchmark_lab", "test_updater", "brand_overlay", "review6", "safe_git"):
        assert tool_test not in text, tool_test
    for e in entries:
        assert "*" not in e["test"] or e.get("python") or e.get("os"), e["test"]   # a wildcard must be narrowed


def test_linux_and_windows_ci_installers_pin_the_same_versions_and_hashes_as_the_lock():
    import re
    lock = json.loads((ROOT / "scripts" / "engines" / "engines.lock.json").read_text(encoding="utf-8"))["engines"]
    sh = (ROOT / "scripts" / "install-ci-scanners.sh").read_text(encoding="utf-8")
    val = lambda k: re.search(rf'^{k}="([^"]+)"', sh, re.M).group(1)
    assert val("SEMGREP_VERSION") == lock["semgrep"]["version"]
    for name in ("trivy", "gitleaks"):
        assert val(f"{name.upper()}_VERSION") == lock[name]["version"]
        assert val(f"{name.upper()}_SHA256") == lock[name]["artifacts"]["linux-amd64"]["sha256"]
        assert re.fullmatch(r"[0-9a-f]{64}", lock[name]["artifacts"]["windows-amd64"]["sha256"])
    ps = (ROOT / "scripts" / "install-ci-scanners.ps1").read_text(encoding="utf-8")
    assert "engines.lock.json" in ps and "Get-FileHash -Algorithm SHA256" in ps and "SHA-256 mismatch" in ps


def test_ci_workflow_runs_the_skip_check_and_installs_the_scanners():
    wf = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "scripts/ci/check_skips.py" in wf and "--junitxml" in wf
    assert "install-ci-scanners.sh" in wf and "install-ci-scanners.ps1" in wf
    for line in wf.splitlines():
        if "uses:" in line:
            ref = line.split("@", 1)[1].split()[0]
            assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), line
