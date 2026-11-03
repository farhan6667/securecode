"""Runs semgrep/java-spring.yml on the Java, properties and YAML fixtures and checks every finding.

Each fixture line marked "// expect: <rule id>" (or "# expect: <rule id>") must be reported on the next
line, and nothing else may be reported. Every rule needs at least one positive and one negative case
in the fixtures. The test is skipped when semgrep is not installed.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from test_laravel_authz import find_semgrep

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "semgrep" / "java-spring.yml"
FIXTURES = ROOT / "tests" / "fixtures" / "java-spring"
SEMGREP = find_semgrep()
needs_semgrep = pytest.mark.skipif(SEMGREP is None, reason="semgrep is not on PATH")


def expected_markers():
    out = set()
    for f in FIXTURES.rglob("*"):
        if not f.is_file():
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            m = re.search(r"(?://|#)\s*expect:\s*([\w-]+)", line)
            if m:
                out.add((f.relative_to(FIXTURES).as_posix(), m.group(1), n + 1))
    return out


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    # Semgrep's default ignore list skips any "tests/" folder, so scan a copy outside it.
    work = tmp_path_factory.mktemp("java_spring") / "app_copy"
    shutil.copytree(FIXTURES, work)
    cmd = [SEMGREP, "scan", "--metrics", "off", "--disable-version-check", "--quiet",
           "--json", "--config", str(RULES), "."]
    proc = subprocess.run(cmd, cwd=str(work), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)
    assert proc.returncode in (0, 1), proc.stderr[-800:]
    data = json.loads(proc.stdout)
    assert data.get("errors") == [], data.get("errors")
    found = set()
    for r in data.get("results", []):
        rel = Path(r["path"]).as_posix()
        rel = rel[2:] if rel.startswith("./") else rel
        found.add((rel, r["check_id"].split(".")[-1], r["start"]["line"]))
    return found


def test_rules_have_metadata():
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    assert len(rules) >= 20
    for r in rules:
        assert r["severity"] in ("ERROR", "WARNING"), r["id"]
        assert r["metadata"]["cwe"].startswith("CWE-"), r["id"]
        assert "—" not in r["message"] and "–" not in r["message"], r["id"]


def test_every_rule_has_a_positive_fixture():
    rules = {r["id"] for r in yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]}
    marked = {rule for _, rule, _ in expected_markers()}
    assert rules == marked, rules ^ marked


@needs_semgrep
def test_semgrep_validates_rule_file():
    proc = subprocess.run([SEMGREP, "--validate", "--metrics", "off", "--disable-version-check",
                           "--config", str(RULES)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-800:]


@needs_semgrep
def test_findings_match_markers_exactly(results):
    exp = expected_markers()
    assert not (exp - results), f"missed: {sorted(exp - results)}"
    assert not (results - exp), f"false positives: {sorted(results - exp)}"

