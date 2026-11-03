"""Runs semgrep/laravel-authz.yml on the PHP fixtures and checks every finding.

Each fixture line marked "// expect: <rule id>" must be reported on the next line, and nothing else
may be reported. The test is skipped when semgrep is not installed.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "semgrep" / "laravel-authz.yml"
FIXTURES = ROOT / "tests" / "fixtures" / "laravel-authz"

# Rule ids per fixture file, one entry per expected finding.
EXPECTED = {
    "app/Http/Controllers/OrderIdorController.php": ["laravel-idor-unscoped-lookup"] * 7,
    "app/Http/Controllers/SafeOrderController.php": [],
    "app/Http/Controllers/ProfileMassAssignController.php": ["laravel-mass-assignment"] * 7,
    "app/Models/Models.php": ["laravel-mass-assignment"],
    "routes/api.php": ["laravel-api-route-without-auth"] * 11,
    "routes/web.php": ["laravel-web-group-without-auth"] * 2,
}


def find_semgrep():
    # Absolute PATH entries only. The current folder and relative entries are never searched, so a
    # planted semgrep script in the working tree cannot stand in for the real one.
    blocked = {os.path.normcase(os.path.realpath(p)) for p in (os.getcwd(), ROOT)}
    exts = [""]
    if os.name == "nt":
        exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        d = d.strip('"')
        if not d or not os.path.isabs(d):
            continue
        rd = os.path.normcase(os.path.realpath(d))
        if any(rd == b or rd.startswith(b.rstrip(os.sep) + os.sep) for b in blocked):
            continue
        for e in exts:
            c = os.path.join(d, "semgrep" + e)
            if os.path.isfile(c) and (os.name == "nt" or os.access(c, os.X_OK)):
                return c
    return None


SEMGREP = find_semgrep()
pytestmark = pytest.mark.skipif(SEMGREP is None, reason="semgrep is not on PATH")


def expected_from_markers(path):
    out = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for n, line in enumerate(lines, 1):
        m = re.search(r"//\s*expect:\s*([\w-]+)", line)
        if m:
            out.append((m.group(1), n + 1))
    return sorted(out)


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    # Semgrep's default ignore list skips any "tests/" folder, so scan a copy outside it.
    work = tmp_path_factory.mktemp("laravel_authz") / "app_copy"
    shutil.copytree(FIXTURES, work)
    cmd = [SEMGREP, "scan", "--metrics", "off", "--disable-version-check", "--quiet",
           "--json", "--config", str(RULES), "."]
    proc = subprocess.run(cmd, cwd=str(work), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)
    assert proc.returncode in (0, 1), proc.stderr[-800:]
    data = json.loads(proc.stdout)
    assert data.get("errors") == [], data.get("errors")
    found = {}
    for r in data.get("results", []):
        rel = Path(r["path"]).as_posix()
        rel = rel[2:] if rel.startswith("./") else rel
        found.setdefault(rel, []).append((r["check_id"].split(".")[-1], r["start"]["line"]))
    return found


def test_rule_file_has_four_rules_with_verify_messages():
    import yaml
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    assert sorted(r["id"] for r in rules) == sorted({i for v in EXPECTED.values() for i in v})
    for r in rules:
        assert r["severity"] == "ERROR"
        assert r["message"].startswith("Verify:")


def test_every_fixture_is_listed():
    on_disk = {p.relative_to(FIXTURES).as_posix() for p in FIXTURES.rglob("*.php")}
    assert on_disk == set(EXPECTED)


@pytest.mark.parametrize("rel", sorted(EXPECTED))
def test_rule_ids_per_file(results, rel):
    got = sorted(rule for rule, _ in results.get(rel, []))
    assert got == sorted(EXPECTED[rel])


@pytest.mark.parametrize("rel", sorted(EXPECTED))
def test_findings_on_marked_lines(results, rel):
    assert sorted(results.get(rel, [])) == expected_from_markers(FIXTURES / rel)
