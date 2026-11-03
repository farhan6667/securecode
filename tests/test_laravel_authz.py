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
    "app/Http/Controllers/BindingIdorController.php": ["laravel-idor-route-model-binding"] * 12,
    "app/Http/Controllers/BindingResourceController.php": ["laravel-idor-route-model-binding"] * 8,
    "app/Http/Controllers/SafeBindingController.php": [],
    # Semgrep alone reports all 19; secgate's route context then drops 8 (test_gate_route_context).
    "binding-app/app/Http/Controllers/RouteContextControllers.php": ["laravel-idor-route-model-binding"] * 19,
    "binding-app/app/Http/Requests/UpdateOrderRequest.php": [],
    "binding-app/app/Http/Requests/NoteOrderRequest.php": [],
    "binding-app/routes/web.php": [],
    # A realistic, clean app (false positive check): Semgrep alone reports 8 bindings whose check sits
    # in routes or a FormRequest; secgate's route context must drop all of them.
    "realistic-app/app/Http/Controllers/Admin/UserController.php": ["laravel-idor-route-model-binding"] * 5,
    "realistic-app/app/Http/Controllers/Api/ProjectController.php": ["laravel-idor-route-model-binding"],
    "realistic-app/app/Http/Controllers/Api/TaskController.php": [],
    "realistic-app/app/Http/Controllers/BlogController.php": [],
    "realistic-app/app/Http/Controllers/CommentController.php": ["laravel-idor-route-model-binding"] * 2,
    "realistic-app/app/Http/Controllers/PostController.php": [],
    "realistic-app/app/Http/Requests/StoreCommentRequest.php": [],
    "realistic-app/routes/api.php": [],
    "realistic-app/routes/web.php": [],
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
def scan(tmp_path_factory):
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
    return work, data


@pytest.fixture(scope="module")
def results(scan):
    _, data = scan
    found = {}
    for r in data.get("results", []):
        rel = Path(r["path"]).as_posix()
        rel = rel[2:] if rel.startswith("./") else rel
        found.setdefault(rel, []).append((r["check_id"].split(".")[-1], r["start"]["line"]))
    return found


def test_rule_file_has_five_rules_with_verify_messages():
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


# --- secgate.py route context for laravel-idor-route-model-binding (OPEN-01) -------------------------
BINDING_APP = "binding-app"
CONTEXT_FILE = "app/Http/Controllers/RouteContextControllers.php"


def load_secgate(name="secgate_l18"):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "secgate.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def gate_markers(path):
    keeps, drops = [], []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = re.search(r"//\s*expect:\s*laravel-idor-route-model-binding\s+(gate-keeps|gate-drops)", line)
        if m:
            (keeps if m.group(1) == "gate-keeps" else drops).append(n + 1)
    return sorted(keeps), sorted(drops)


def gate_findings(data, app=BINDING_APP):
    # The same shape collect_semgrep() builds, for the files of one app only.
    out = []
    for r in data.get("results", []):
        rel = Path(r["path"]).as_posix()
        rel = rel[2:] if rel.startswith("./") else rel
        if rel.startswith(app + "/"):
            out.append({"rule": r["check_id"], "severity": "HIGH", "file": rel[len(app) + 1:],
                        "line": r["start"]["line"], "message": r["extra"]["message"], "engine": "semgrep"})
    return out


def test_gate_route_context(scan):
    work, data = scan
    sg = load_secgate()
    found = gate_findings(data)
    kept = sg.laravel_binding_context(work / BINDING_APP, found)
    keeps, drops = gate_markers(FIXTURES / BINDING_APP / CONTEXT_FILE)
    assert sorted(f["line"] for f in found) == sorted(keeps + drops)
    assert sorted(f["line"] for f in kept) == keeps
    assert len(drops) == 8 and len(keeps) == 11


def test_gate_realistic_app_has_no_findings_left(scan):
    work, data = scan
    sg = load_secgate("secgate_l18r")
    found = gate_findings(data, "realistic-app")
    assert len(found) == 8 and {f["rule"].split(".")[-1] for f in found} == {"laravel-idor-route-model-binding"}
    assert sg.laravel_binding_context(work / "realistic-app", found) == []


def test_gate_context_keeps_everything_without_routes_or_a_readable_file(scan, tmp_path):
    work, data = scan
    sg = load_secgate("secgate_l18b")
    found = gate_findings(data)
    # No routes/ folder and no requests: nothing can be tied to a route, so nothing is dropped.
    assert sg.laravel_binding_context(tmp_path, found) == found
    # A finding path that leaves the root is never read.
    outside = [dict(f, file="../" + BINDING_APP + "/" + f["file"]) for f in found]
    assert sg.laravel_binding_context(work / BINDING_APP / "app", outside) == outside


def test_gate_context_leaves_other_rules_alone(tmp_path):
    sg = load_secgate("secgate_l18c")
    other = [{"rule": "laravel-idor-unscoped-lookup", "file": "x.php", "line": 3, "message": "m"}]
    assert sg.laravel_binding_context(tmp_path, other) == other


def test_gate_routes_parser_is_linear_and_ignores_comments(tmp_path):
    import time
    sg = load_secgate("secgate_l18d")
    (tmp_path / "routes").mkdir()
    hostile = ("Route::middleware('auth')->group(function () {" * 3000 + "/* ->can('x') */ "
               "Route::get('/a/{a}', [AController::class, 'show']);" + "});" * 3000 + "{" * 20000 + "'" + "x" * 200000)
    (tmp_path / "routes" / "web.php").write_text("<?php\n" + hostile, encoding="utf-8")
    t = time.perf_counter()
    table = sg.laravel_routes(tmp_path)
    assert time.perf_counter() - t < 5
    assert table[("AController", "show")] == [{"authz": False, "scoped": False, "params": ["a"]}]


def _binding_finding(rel, line, var, meth):
    return {"rule": "laravel-idor-route-model-binding", "file": rel, "line": line,
            "message": f"Verify: ... (binding: ${var} in {meth}())"}


def test_gate_ignores_route_files_laravel_does_not_load(tmp_path):
    sg = load_secgate("secgate_l18f")
    (tmp_path / "routes").mkdir()
    (tmp_path / "app").mkdir()
    ctl = "<?php\nuse App\\Models\\Order;\nclass OController extends Controller\n{\n    public function show(Order $order)\n    {\n        return $order;\n    }\n}\n"
    (tmp_path / "app" / "OController.php").write_text(ctl, encoding="utf-8")
    stray = "<?php Route::get('/o/{order}', [OController::class, 'show'])->can('view', 'order');\n"
    (tmp_path / "routes" / "unused.php").write_text(stray, encoding="utf-8")
    f = [_binding_finding("app/OController.php", 5, "order", "show")]
    assert sg.laravel_binding_context(tmp_path, f) == f
    # Once web.php loads it, the route counts.
    (tmp_path / "routes" / "web.php").write_text("<?php\nrequire __DIR__.'/unused.php';\n", encoding="utf-8")
    assert sg.laravel_binding_context(tmp_path, f) == []


def test_gate_scoped_child_needs_a_model_parent_the_rule_checked(tmp_path):
    sg = load_secgate("secgate_l18g")
    (tmp_path / "routes").mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "routes" / "web.php").write_text(
        "<?php\nRoute::get('/t/{team}/p/{project}', [PController::class, 'show'])->scopeBindings();\n", encoding="utf-8")
    # The parent type is not imported from a Models namespace, so the rule never looked at it: keep the child.
    ctl = ("<?php\nuse Acme\\Team;\nuse App\\Models\\Project;\nclass PController extends Controller\n{\n"
           "    public function show(Team $team, Project $project)\n    {\n        return $project;\n    }\n}\n")
    (tmp_path / "app" / "PController.php").write_text(ctl, encoding="utf-8")
    f = [_binding_finding("app/PController.php", 6, "project", "show")]
    assert sg.laravel_binding_context(tmp_path, f) == f
    # With a model parent that the rule did not report (it was checked), the scoped child is covered.
    (tmp_path / "app" / "PController.php").write_text(ctl.replace("use Acme\\Team;", "use App\\Models\\Team;"), encoding="utf-8")
    assert sg.laravel_binding_context(tmp_path, f) == []
    # If the parent was reported too, nothing checks it: keep both.
    both = f + [_binding_finding("app/PController.php", 6, "team", "show")]
    assert sg.laravel_binding_context(tmp_path, both) == both


def test_gate_routes_skip_symlinked_files(tmp_path):
    sg = load_secgate("secgate_l18e")
    outside = tmp_path / "outside.php"
    outside.write_text("<?php Route::get('/a/{a}', [AController::class, 'show'])->can('view', 'a');", encoding="utf-8")
    proj = tmp_path / "proj"
    (proj / "routes").mkdir(parents=True)
    try:
        os.symlink(outside, proj / "routes" / "web.php")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    assert sg.laravel_routes(proj) == {}
