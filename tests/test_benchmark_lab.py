"""The benchmark labs must keep finding what the checks found when RESULTS.md was written, and the
clean files in each lab must stay clean. A drop means a rule got weaker; a new hit on a clean file means
a rule got noisier."""
import importlib.util, io, re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from test_laravel_authz import find_semgrep

ROOT = Path(__file__).resolve().parents[1]


def run_lab_module(name="run_lab"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "benchmark" / "run_lab.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run(lab, mode="quick"):
    buf = io.StringIO()
    with redirect_stdout(buf):
        run_lab_module().main(["--mode", mode, "--lab", lab])
    out = buf.getvalue()
    m = re.search(r"found: (\d+) of (\d+)\. Clean files reported: (\d+) of (\d+)", out)
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), out


def test_quick_mode_lab_floor():
    found, _, _, out = run("laravel")
    assert found >= 11, out
    assert re.search(r"\| L16 \|[^\n]*\| found \|", out), out          # Blade {!! !!}


def test_legacy_lab_all_found_and_clean_framework_quiet():
    found, total, noisy, out = run("legacy")
    assert (found, noisy) == (total, 0), out
    assert total >= 17


def test_web_lab_all_found_and_clean_files_quiet():
    found, total, noisy, out = run("web")
    assert (found, noisy) == (total, 0), out
    assert total >= 22
    # the deny-list "fix" must not make the query count as fixed
    assert re.search(r"\| W10 \|[^\n]*\| found \| SQL_CONCAT", out), out


def test_spring_lab_quick_floor():
    # Without Semgrep only the built-in checks run: SQL_CONCAT, the database config and default-value checks.
    found, _, noisy, out = run("spring")
    assert found >= 6, out
    # Known false positive of the line-based SQL_CONCAT heuristic on the clean controller (a "%" + x
    # parameter on the same line as a parameterized query). Documented in RESULTS.md; it must not grow.
    assert noisy <= 1, out


@pytest.mark.skipif(find_semgrep() is None, reason="semgrep is not on PATH")
def test_spring_lab_full_floor():
    found, total, noisy, out = run("spring", "full")
    assert found == total == 20, out
    assert noisy <= 1, out


def test_lab_paths_cannot_escape(tmp_path):
    m = run_lab_module("run_lab2")
    for bad in ("../x.php", "/etc/x", "a/../../x", "C:/x", "c:\\x"):
        with pytest.raises(ValueError):
            m.materialize({"files": {bad: "x"}}, tmp_path)


def test_clean_file_matching_is_exact():
    m = run_lab_module("run_lab3")
    findings = [{"file": "public/index.php", "rule": "X"}, {"file": "./index.php", "rule": "Y"}]
    assert [f["rule"] for f in m.on_file(findings, "index.php")] == ["Y"]
    assert m.hint_match("xyz|SQL_CONCAT", "SQL_CONCAT") and not m.hint_match("xyz|qq", "SQL_CONCAT") and m.hint_match("", "Z")
