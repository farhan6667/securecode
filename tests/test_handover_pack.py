"""7.2 handover: review coverage, review findings, handover readiness, the report lint and the handover pack.

The point of these tests: a project can not be reported as ready for the security team while review classes were never
looked at, a finding the reviewer found by reading code counts like a scanner finding, and a pack that was edited
after it was built fails its own check.
"""
import importlib.util, json, os, sys, zipfile
from pathlib import Path

import pytest

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


R = load("scripts/report.py", "report_h72")
L = load("scripts/report_lint.py", "report_lint_h72")
H = load("scripts/handover_pack.py", "handover_pack_h72")

GH_TOKEN = "".join(["gh", "p_", "a1B2" * 9])


def gate(findings, **status):
    ts = {"semgrep": True, "trivy": True, "gitleaks": True, "errors": {}, "notes": [], "project_tests": []}
    ts.update(status)
    return {"mode": "ci", "tool_status": ts, "counts": {}, "findings": findings}


def write(p: Path, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return p


def full_coverage(**override):
    classes = {k: {"status": "examined", "evidence": f"app/{k}.py:10 and tests/Security/{k}_test.py"} for k, _ in R.COVERAGE_CLASSES}
    classes["mobile"] = {"status": "not applicable", "reason": "no mobile client in this repository"}
    classes.update(override)
    return {"classes": classes, "surface": {"entry_points_found": 12, "entry_points_reviewed": 12}}


def project(tmp_path, findings=(), coverage="full", review=None, retest=None, dast=True, matrix=True, **status):
    sec = tmp_path / ".security"
    write(sec / "findings.json", gate(list(findings), **status))
    if coverage == "full":
        coverage = full_coverage()
    if coverage is not None:
        write(sec / "coverage.json", coverage)
    if review is not None:
        write(sec / "review-findings.json", {"findings": review})
    if retest is not None:
        write(sec / "retest.json", retest)
    if dast:
        write(sec / "dast-findings.json", {"status": "ran", "scan": "baseline", "target": "http://127.0.0.1:8000", "tool": "zap", "findings": []})
    if matrix:
        write(sec / "authz-matrix.md", "| route | verb |\n|---|---|\n| /a | GET |\n")
    assert R.main(["--root", str(tmp_path)]) == 0
    return (sec / "REPORT.md").read_text(encoding="utf-8"), json.loads((sec / "report-state.json").read_text(encoding="utf-8"))


def lint_errors(text):
    return L.lint(text)[0]


# --- coverage and readiness -----------------------------------------------------------------------------------

def test_a_clean_scan_with_no_recorded_review_is_not_ready(tmp_path):
    # By default no coverage file is written (it costs tokens on every test): the report is the plain one and makes
    # no readiness claim at all. A team that keeps the file gets the table and the line.
    md, state = project(tmp_path, coverage=None)
    assert state["verdict"] == "PASSED" and state["readiness"] == "NOT READY"
    assert "## Coverage" not in md and "Handover readiness" not in md and lint_errors(md) == []
    md, state = project(tmp_path, coverage={"classes": {}})
    assert state["readiness"] == "NOT READY" and "no review coverage was recorded" in " ".join(state["readiness_why"])
    assert "## Coverage" in md and md.count("| not examined |") == len(R.COVERAGE_CLASSES) and "Handover readiness: NOT READY" in md.replace("*", "")


def test_full_coverage_and_no_open_finding_is_ready_for_review(tmp_path):
    md, state = project(tmp_path)
    assert state["readiness"] == "READY FOR PENTEST REVIEW" and state["not_examined"] == []
    assert "Handover readiness: READY FOR PENTEST REVIEW" in md and lint_errors(md) == []
    assert "The security team's own test decides approval" in md


@pytest.mark.parametrize("entry,why", [
    ({"status": "examined"}, "examined needs evidence"),
    ({"status": "not applicable"}, "not applicable needs a reason"),
    ({"status": "done"}, "no valid status"),
    ({"status": "not examined", "reason": "ran out of time"}, "ran out of time"),
    ("examined", "not recorded"),
])
def test_a_class_without_evidence_or_reason_counts_as_not_examined(tmp_path, entry, why):
    md, state = project(tmp_path, coverage=full_coverage(idor=entry))
    assert state["readiness"] == "NOT READY" and len(state["not_examined"]) == 1 and "IDOR" in state["not_examined"][0]
    assert why in md


def test_a_class_missing_from_the_file_counts_as_not_examined(tmp_path):
    cov = full_coverage()
    del cov["classes"]["ssrf"]
    _, state = project(tmp_path, coverage=cov)
    assert state["readiness"] == "NOT READY" and state["not_examined"] == ["Server-side request forgery"]


def test_fewer_entry_points_reviewed_than_found_is_not_ready(tmp_path):
    cov = full_coverage()
    cov["surface"] = {"entry_points_found": 30, "entry_points_reviewed": 11}
    _, state = project(tmp_path, coverage=cov)
    assert state["readiness"] == "NOT READY" and "only 11 of 30 entry points" in " ".join(state["readiness_why"])


@pytest.mark.parametrize("surface,want", [({"entry_points_found": -1}, "NOT READY"), ({"entry_points_found": True}, "NOT READY"),
                                          ({"entry_points_found": "12"}, "NOT READY"), ("x", "CONDITIONALLY READY"),
                                          (None, "CONDITIONALLY READY"), ({}, "CONDITIONALLY READY")])
def test_a_count_that_is_not_a_plain_number_blocks_and_a_missing_one_is_a_condition(tmp_path, surface, want):
    cov = full_coverage()
    cov["surface"] = surface
    _, state = project(tmp_path, coverage=cov)
    assert state["readiness"] == want


def test_no_dast_or_no_matrix_is_conditional_not_ready(tmp_path):
    _, state = project(tmp_path, dast=False, matrix=False)
    why = " ".join(state["readiness_why"])
    assert state["readiness"] == "CONDITIONALLY READY" and "running application" in why and "authorization matrix" in why


def test_a_blocked_gate_is_never_ready_even_with_full_coverage(tmp_path):
    _, state = project(tmp_path, semgrep=False)
    assert state["verdict"] == "BLOCKED" and state["readiness"] == "NOT READY"


def test_an_open_medium_blocks_readiness_and_an_accepted_one_makes_it_conditional(tmp_path):
    f = [{"rule": "X_MEDIUM", "severity": "MEDIUM", "file": "a.py", "line": 3, "message": "m", "code": "c", "engine": "local"}]
    _, state = project(tmp_path, findings=f, retest={"results": []})
    assert state["verdict"] == "PASSED" and state["readiness"] == "NOT READY"
    accepted = {"results": [{"id": "F-01", "fingerprint": state["fingerprints"]["F-01"], "outcome": "Risk accepted",
                             "accepted_by": "Head of Security", "date": "2026-11-20"}]}
    _, state = project(tmp_path, findings=f, retest=accepted)
    assert state["readiness"] == "CONDITIONALLY READY" and "security team has to confirm" in " ".join(state["readiness_why"])


def test_coverage_text_from_the_reviewer_is_escaped_and_redacted(tmp_path):
    cov = full_coverage(xss={"status": "examined", "evidence": f"<script>alert(1)</script> | token={GH_TOKEN} " + chr(0x202E) + ""})
    md, _ = project(tmp_path, coverage=cov)
    html = (tmp_path / ".security" / "REPORT.html").read_text(encoding="utf-8")
    assert GH_TOKEN not in md and GH_TOKEN not in html and "<script>alert" not in html and "" + chr(0x202E) + "" not in md
    assert lint_errors(md) == []


# --- findings from the code review ------------------------------------------------------------------------------

REVIEW = [{"id": "R-07", "title": "Order export has no owner check", "class": "idor", "severity": "HIGH", "file": "app/orders.py",
           "line": 88, "route": "GET /api/orders/{id}/export", "message": "any signed-in user can export any order",
           "evidence": "Order.objects.get(pk=id)"}]


def test_a_review_finding_counts_for_the_verdict_like_a_scanner_finding(tmp_path):
    md, state = project(tmp_path, review=REVIEW)
    assert state["verdict"] == "FAILED" and state["readiness"] == "NOT READY" and state["counts"]["HIGH"] == 1
    assert "| R-07 |" in md and "app/orders.py:88" in md and "export" in md
    assert lint_errors(md) == []


def test_a_review_finding_closes_only_with_retest_evidence(tmp_path):
    _, state = project(tmp_path, review=REVIEW, retest={"results": [{"id": "R-07", "outcome": "Pass"}]})
    assert state["verdict"] == "FAILED"                                    # a Pass with no evidence is Not retested
    ok = {"results": [{"id": "R-07", "outcome": "Pass", "evidence": "tests/Security/test_orders.py::test_other_user_export_403",
                       "variant": "also tried POST"}]}
    md, state = project(tmp_path, review=REVIEW, retest=ok)
    assert state["verdict"] == "PASSED" and state["readiness"] == "READY FOR PENTEST REVIEW" and "| R-07 | Pass |" in md


def test_review_ids_are_kept_when_valid_and_assigned_when_missing_or_repeated(tmp_path):
    review = [dict(REVIEW[0]), dict(REVIEW[0], title="second", line=90), dict(REVIEW[0], id="../x", title="third", line=91),
              "not a finding", {"severity": "LOW"}]
    md, _ = project(tmp_path, review=review)
    ids = sorted(set(x for x in __import__("re").findall(r"\| (R-\d+) \|", md)))
    assert ids == ["R-01", "R-02", "R-03", "R-07"]


def test_a_garbage_review_or_coverage_file_does_not_crash_the_report(tmp_path):
    sec = tmp_path / ".security"
    write(sec / "findings.json", gate([]))
    write(sec / "review-findings.json", "[[[")
    write(sec / "coverage.json", '{"classes": [1, 2]}')
    assert R.main(["--root", str(tmp_path)]) == 0
    assert json.loads((sec / "report-state.json").read_text())["readiness"] == "NOT READY"


# --- the lint ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("claim", ["The penetration test was passed.", "This app passed the pentest.", "It is production-ready.",
                                   "No security issues were found.", "No vulnerabilities found."])
def test_the_lint_refuses_the_new_overclaims(tmp_path, claim):
    md, _ = project(tmp_path)
    assert any("overclaim" in e for e in lint_errors(md + "\n" + claim + "\n"))


def test_the_lint_refuses_a_ready_claim_over_an_unexamined_class(tmp_path):
    md, _ = project(tmp_path)
    forged = md.replace("| Server-side request forgery | examined |", "| Server-side request forgery | not examined |")
    assert forged != md and any("READY FOR PENTEST REVIEW while" in e for e in lint_errors(forged))


def test_the_lint_refuses_a_missing_or_short_coverage_table(tmp_path):
    md, _ = project(tmp_path)
    assert any("READY FOR PENTEST REVIEW while" in e for e in lint_errors(md.replace("## Coverage", "## Something else")))
    short = "\n".join(ln for ln in md.splitlines() if not ln.startswith("| Cryptography"))
    assert any("coverage table has" in e for e in lint_errors(short))
    blank = __import__("re").sub(r"(?m)^(\| Cross-site scripting [^|]*\| examined \|)[^|]*\|$", r"\1 - |", md)
    assert blank != md and any("no evidence or reason" in e for e in lint_errors(blank))


# --- the pack -----------------------------------------------------------------------------------------------------

def build_pack(tmp_path, **kw):
    project(tmp_path, **kw)
    code, msg = H.build(tmp_path)
    zips = sorted((tmp_path / ".security" / "handover").glob("*.zip")) if (tmp_path / ".security" / "handover").is_dir() else []
    return code, msg, (zips[-1] if zips else None)


def test_a_ready_project_builds_a_pack_that_verifies(tmp_path):
    code, msg, z = build_pack(tmp_path, review=REVIEW, retest={"results": [{"id": "R-07", "outcome": "Pass", "evidence": "tests/t.py::t"}]})
    assert code == 0 and z is not None and "NOT-READY" not in z.name and "Pack SHA-256:" in msg
    names = set(zipfile.ZipFile(z).namelist())
    assert {"MANIFEST.json", "MANIFEST.sha256", "REPORT.md", "REPORT.html", "findings.json", "coverage.json", "review-findings.json",
            "retest.json", "authz-matrix.md", "NOT-TESTED.md", "report-state.json"} <= names
    man = json.loads(zipfile.ZipFile(z).read("MANIFEST.json"))
    assert man["readiness"] == "READY FOR PENTEST REVIEW" and man["verdict"] == "PASSED" and man["git"]["commit"]
    assert {f["name"] for f in man["files"]} == names - {"MANIFEST.json", "MANIFEST.sha256"}
    vcode, vmsg = H.verify(z)
    assert vcode == 0 and "CONSISTENT" in vmsg and "PASS" not in vmsg and "--expect-sha256" in vmsg
    digest = __import__("hashlib").sha256(z.read_bytes()).hexdigest()
    assert digest in msg
    assert H.verify(z, digest)[0] == 0 and "PASS" in H.verify(z, digest)[1]
    assert H.verify(z, "0" * 64)[0] == 1 and "not the pack that was built" in H.verify(z, "0" * 64)[1]
    assert H.verify(z, "nonsense")[0] == 2


def test_a_not_ready_project_still_builds_a_pack_that_says_so(tmp_path):
    code, msg, z = build_pack(tmp_path, coverage=None)
    assert code == 1 and "NOT-READY" in z.name and "Handover readiness: NOT READY" in msg
    nt = zipfile.ZipFile(z).read("NOT-TESTED.md").decode()
    assert "Review classes that were not examined" in nt and "Server-side request forgery" in nt and "Limits of the automated review" in nt


def rezip(z: Path, change):
    with zipfile.ZipFile(z) as src:
        members = {n: src.read(n) for n in src.namelist()}
    change(members)
    out = z.with_name("edited.zip")
    with zipfile.ZipFile(out, "w") as dst:
        for n, b in members.items():
            dst.writestr(n, b)
    return out


def test_an_edited_removed_or_added_file_fails_the_check(tmp_path):
    _, _, z = build_pack(tmp_path)
    edited = rezip(z, lambda m: m.__setitem__("REPORT.md", m["REPORT.md"].replace(b"CONDITIONALLY", b"").replace(b"NOT READY", b"READY") + b"x"))
    assert H.verify(edited)[0] == 1 and "REPORT.md does not match the manifest" in H.verify(edited)[1]
    removed = rezip(z, lambda m: m.pop("coverage.json"))
    assert "coverage.json is listed but missing" in H.verify(removed)[1]
    added = rezip(z, lambda m: m.__setitem__("extra.txt", b"hi"))
    assert "extra.txt is in the pack but not in the manifest" in H.verify(added)[1]

    def forge(m):
        man = json.loads(m["MANIFEST.json"])
        man["readiness"] = "READY FOR PENTEST REVIEW"
        m["MANIFEST.json"] = json.dumps(man).encode()
    assert "MANIFEST.sha256 does not match" in H.verify(rezip(z, forge))[1]


def test_a_hostile_zip_is_refused_without_writing_anything(tmp_path):
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("../../evil.txt", b"x")
        zf.writestr("MANIFEST.json", b"{}")
    assert H.verify(bad)[0] == 2 and not (tmp_path.parent / "evil.txt").exists()
    assert H.verify(tmp_path / "nothing.zip")[0] == 2
    notzip = tmp_path / "n.zip"
    notzip.write_bytes(b"hello")
    assert H.verify(notzip)[0] == 2


def test_secrets_in_the_raw_findings_do_not_reach_the_pack(tmp_path):
    f = [{"rule": "generic-api-key", "severity": "LOW", "file": "a.py", "line": 1, "message": f"token {GH_TOKEN}",
          "code": "api" + f'_key = "{GH_TOKEN}"', "engine": "gitleaks"}]
    write(tmp_path / ".security" / "RUNBOOK.md", "Start with: make run\nadmin pass" + f"word={GH_TOKEN}\n")
    _, _, z = build_pack(tmp_path, findings=f, retest={"results": [{"id": "F-01", "outcome": "Risk accepted", "accepted_by": "CISO", "date": "2026-11-20"}]})
    with zipfile.ZipFile(z) as zf:
        blob = b"".join(zf.read(n) for n in zf.namelist())
    assert GH_TOKEN.encode() not in blob and b"RUNBOOK.md" in zipfile.ZipFile(z).read("MANIFEST.json")


def test_the_pack_builds_its_own_report_and_ignores_an_edited_one(tmp_path):
    # Review round 1: readiness came from report-state.json and REPORT.md on disk, which anyone can edit, and results
    # changed after the report was written still gave a READY pack.
    _, state = project(tmp_path, coverage={"classes": {}})
    assert state["readiness"] == "NOT READY"
    sec = tmp_path / ".security"
    forged = dict(state, readiness="READY FOR PENTEST REVIEW", verdict="PASSED", not_examined=[], readiness_why=["all good"])
    write(sec / "report-state.json", forged)
    md = sec / "REPORT.md"
    md.write_text(md.read_text(encoding="utf-8").replace("NOT READY", "READY FOR PENTEST REVIEW"), encoding="utf-8")
    code, msg = H.build(tmp_path)
    z = sorted((sec / "handover").glob("*.zip"))[-1]
    man = json.loads(zipfile.ZipFile(z).read("MANIFEST.json"))
    assert code == 1 and "NOT-READY" in z.name and man["readiness"] == "NOT READY"
    assert b"Handover readiness: NOT READY" in zipfile.ZipFile(z).read("REPORT.md").replace(b"*", b"")
    assert json.loads((sec / "report-state.json").read_text())["readiness"] == "NOT READY"      # the folder is put right too


def test_results_changed_after_the_report_change_the_pack(tmp_path):
    _, state = project(tmp_path)
    assert state["readiness"] == "READY FOR PENTEST REVIEW"
    sec = tmp_path / ".security"
    write(sec / "review-findings.json", {"findings": [dict(REVIEW[0], severity="CRITICAL")]})
    write(sec / "coverage.json", {"classes": {}})
    code, msg = H.build(tmp_path)
    man = json.loads(zipfile.ZipFile(sorted((sec / "handover").glob("*.zip"))[-1]).read("MANIFEST.json"))
    assert code == 1 and man["verdict"] == "FAILED" and man["readiness"] == "NOT READY"


def test_a_planted_html_report_is_never_copied(tmp_path):
    project(tmp_path)
    sec = tmp_path / ".security"
    (sec / "REPORT.html").write_text("<script>alert(1)</script> Penetration test passed " + GH_TOKEN, encoding="utf-8")
    _, _, z = build_pack(tmp_path)
    page = zipfile.ZipFile(z).read("REPORT.html")
    assert b"<script>" not in page and GH_TOKEN.encode() not in page and b"Content-Security-Policy" in page


def test_a_pack_with_only_a_manifest_or_a_forged_readiness_fails_the_check(tmp_path):
    _, _, z = build_pack(tmp_path, coverage=None)

    def only_manifest(m):
        man = json.loads(m["MANIFEST.json"])
        man["files"], man["readiness"] = [], "READY FOR PENTEST REVIEW"
        mb = json.dumps(man).encode()
        m.clear()
        m["MANIFEST.json"] = mb
        m["MANIFEST.sha256"] = (__import__("hashlib").sha256(mb).hexdigest() + "  MANIFEST.json\n").encode()
    code, msg = H.verify(rezip(z, only_manifest))
    assert code == 1 and "not a complete handover pack" in msg

    def forged_ready(m):
        man = json.loads(m["MANIFEST.json"])
        man["readiness"] = "READY FOR PENTEST REVIEW"
        mb = json.dumps(man).encode()
        m["MANIFEST.json"] = mb
        m["MANIFEST.sha256"] = (__import__("hashlib").sha256(mb).hexdigest() + "  MANIFEST.json\n").encode()
    code, msg = H.verify(rezip(z, forged_ready))
    assert code == 1 and "different readiness" in msg

    def odd_git(m):
        man = json.loads(m["MANIFEST.json"])
        man["git"] = "x"
        mb = json.dumps(man).encode()
        m["MANIFEST.json"] = mb
        m["MANIFEST.sha256"] = (__import__("hashlib").sha256(mb).hexdigest() + "  MANIFEST.json\n").encode()
    assert H.verify(rezip(z, odd_git))[0] in (0, 1)                 # a message, never a traceback


def test_secrets_under_secret_named_keys_and_other_token_shapes_are_redacted(tmp_path):
    slack = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "x" * 24
    sendgrid = "SG." + "a" * 22 + "." + "b" * 43
    npm = "npm_" + "Ab1" * 12
    google = "ya29." + "a1B2" * 10
    plain = "".join(["hunter", "2-is-the-pass"])
    basic = "dXNlcjpwYXNzd29yZDEyMzQ="
    hdr = {"".join(["Author", "ization"]): "Basic " + basic, "".join(["X-Api", "-Key"]): plain}
    user = {"item": "test user", "purpose": f"hook {slack} mail {sendgrid} {npm} {google}", "headers": hdr}
    user["".join(["pass", "word"])] = plain
    user[GH_TOKEN] = "a key that is a token"
    art = {"artifacts": [user]}
    project(tmp_path)
    write(tmp_path / ".security" / "artifacts.json", art)
    _, _, z = build_pack(tmp_path)
    with zipfile.ZipFile(z) as zf:
        blob = b"".join(zf.read(n) for n in zf.namelist())
    for s in (slack, sendgrid, npm, google, plain, basic, GH_TOKEN):
        assert s.encode() not in blob, s


def test_the_pack_does_not_read_through_a_link(tmp_path):
    project(tmp_path)
    secret = tmp_path / "outside.txt"
    secret.write_text("OUTSIDE-CONTENT")
    link = tmp_path / ".security" / "RUNBOOK.md"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("no symlink rights here")
    _, _, z = build_pack(tmp_path)
    assert "RUNBOOK.md" not in zipfile.ZipFile(z).namelist()


def test_without_results_the_pack_says_what_to_run(tmp_path):
    assert H.build(tmp_path)[0] == 3
    (tmp_path / ".security").mkdir()
    code, msg = H.build(tmp_path)
    assert code == 3 and "Run the gate first" in msg


@pytest.mark.parametrize("content", ['{"findings": 5, "tool_status": []}', '{"findings": [{"severity": {"a": 1}, "line": []}]}', "[]", "null"])
def test_hostile_result_files_give_a_message_not_a_traceback(tmp_path, content):
    write(tmp_path / ".security" / "findings.json", content)
    write(tmp_path / ".security" / "coverage.json", '{"classes": {"idor": 5}, "surface": []}')
    write(tmp_path / ".security" / "retest.json", '{"results": [5, {"id": []}]}')
    code, msg = H.build(tmp_path)
    assert code in (1, 3) and "Traceback" not in msg


# --- review round 1: readiness that was too generous ----------------------------------------------------------------

CRIT = {"rule": "SQL_INJECTION", "severity": "CRITICAL", "file": "app/db.py", "line": 9, "message": "m", "code": "q = 'x' + y", "engine": "local"}


def test_an_emptied_before_file_can_not_hide_what_the_scanners_report_now(tmp_path):
    sec = tmp_path / ".security"
    write(sec / "findings-before.json", gate([]))
    _, state = project(tmp_path, findings=[CRIT])
    assert state["verdict"] == "FAILED" and state["readiness"] == "NOT READY" and state["counts"]["CRITICAL"] == 1


def test_a_pass_for_a_finding_the_latest_run_still_reports_is_a_fail_with_or_without_a_before_file(tmp_path):
    ok = {"results": [{"id": "F-01", "outcome": "Pass", "evidence": "tests/Security/test_db.py::test_injection_refused"}]}
    md, state = project(tmp_path, findings=[CRIT], retest=ok)
    assert state["verdict"] == "FAILED" and "| F-01 | Pass |" not in md       # by number only, with no first-run file: not used
    ok["results"][0]["fingerprint"] = state["fingerprints"]["F-01"]
    md, state = project(tmp_path, findings=[CRIT], retest=ok)
    assert state["verdict"] == "FAILED" and "| F-01 | Fail |" in md           # named exactly: still reported, so a Fail
    write(tmp_path / ".security" / "findings-before.json", gate([CRIT]))
    md, state = project(tmp_path, findings=[CRIT], retest=ok)
    assert state["verdict"] == "FAILED" and "| F-01 | Fail |" in md


def test_a_made_up_id_does_not_close_a_review_finding_that_gave_none(tmp_path):
    review = [dict(REVIEW[0], severity="CRITICAL")]
    del review[0]["id"]
    guess = {"results": [{"id": "R-01", "outcome": "Pass", "evidence": "tests/Security/test_orders.py::test_x"}]}
    _, state = project(tmp_path, review=review, retest=guess)
    assert state["verdict"] == "FAILED"


@pytest.mark.parametrize("sev", ["high ", " CRITICAL", "Critical.", "P1", "severe", ["HIGH"], None, 5])
def test_a_review_finding_with_an_odd_severity_is_taken_as_high_not_as_informational(tmp_path, sev):
    _, state = project(tmp_path, review=[dict(REVIEW[0], severity=sev)])
    assert state["verdict"] == "FAILED" and state["readiness"] == "NOT READY"


@pytest.mark.parametrize("outcome", ["Compensating control", "Risk accepted"])
def test_an_unfixed_critical_is_never_ready_on_the_developers_own_say(tmp_path, outcome):
    bare = {"results": [{"id": "R-07", "outcome": outcome}]}
    _, state = project(tmp_path, review=[dict(REVIEW[0], severity="CRITICAL")], retest=bare)
    assert state["verdict"] == "FAILED"                              # no name, date or evidence: not retested
    full = {"results": [{"id": "R-07", "outcome": outcome, "accepted_by": "Team lead", "date": "2026-11-20",
                         "evidence": "nginx rule in deploy/nginx.conf:40 and tests/test_waf.py::test_blocked"}]}
    _, state = project(tmp_path, review=[dict(REVIEW[0], severity="CRITICAL")], retest=full)
    assert state["readiness"] == "NOT READY" and "belongs to the security team" in " ".join(state["readiness_why"])


def test_two_thousand_informational_entries_can_not_push_a_critical_out(tmp_path):
    noise = [{"rule": f"N{i}", "severity": "INFO", "file": "a.py", "line": i, "message": "m", "code": str(i), "engine": "x"} for i in range(2100)]
    _, state = project(tmp_path, findings=noise + [CRIT], retest={"results": []})
    assert state["counts"]["CRITICAL"] == 1 and state["verdict"] == "FAILED"
    assert "did not fit in the report" in " ".join(state["readiness_why"])


@pytest.mark.parametrize("surface", [{"entry_points_found": 500}, {"entry_points_found": 500, "entry_points_reviewed": "all"},
                                     {"entry_points_found": 500, "entry_points_reviewed": 3.0}, {"entry_points_found": 0, "entry_points_reviewed": 0}])
def test_loose_entry_point_counts_are_not_ready(tmp_path, surface):
    cov = full_coverage()
    cov["surface"] = surface
    _, state = project(tmp_path, coverage=cov)
    assert state["readiness"] == "NOT READY"


@pytest.mark.parametrize("ev", [1, True, "x", "ok", ["tests"], {"a": 1}])
def test_evidence_that_is_not_real_text_does_not_count(tmp_path, ev):
    cov = {"classes": {k: {"status": "examined", "evidence": ev} for k, _ in R.COVERAGE_CLASSES}}
    _, state = project(tmp_path, coverage=cov)
    assert state["readiness"] == "NOT READY" and len(state["not_examined"]) == len(R.COVERAGE_CLASSES)


def test_a_dast_file_that_only_says_ran_and_an_empty_matrix_do_not_count(tmp_path):
    project(tmp_path)
    sec = tmp_path / ".security"
    write(sec / "dast-findings.json", {"status": "ran", "findings": []})      # ran, but against nothing
    write(sec / "authz-matrix.md", "")
    assert R.main(["--root", str(tmp_path)]) == 0
    state = json.loads((sec / "report-state.json").read_text())
    why = " ".join(state["readiness_why"])
    assert state["readiness"] == "CONDITIONALLY READY" and "running application" in why and "authorization matrix" in why
    write(sec / "dast-findings.json", {"status": "ran"})                      # ran, with no list of findings at all
    assert R.main(["--root", str(tmp_path)]) == 0
    assert json.loads((sec / "report-state.json").read_text())["verdict"] == "BLOCKED"


# --- review round 2 ----------------------------------------------------------------------------------------------------

def raw_write(p: Path, data: bytes):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


CRIT_REVIEW = json.dumps({"findings": [dict(REVIEW[0], severity="CRITICAL")]})


@pytest.mark.parametrize("data", [b"\xef\xbb\xbf" + CRIT_REVIEW.encode(), CRIT_REVIEW.encode("utf-16")])
def test_a_review_file_saved_with_a_byte_order_mark_or_as_utf16_is_still_read(tmp_path, data):
    project(tmp_path)
    raw_write(tmp_path / ".security" / "review-findings.json", data)
    assert R.main(["--root", str(tmp_path)]) == 0
    state = json.loads((tmp_path / ".security" / "report-state.json").read_text())
    assert state["verdict"] == "FAILED" and state["counts"]["CRITICAL"] == 1


@pytest.mark.parametrize("name,data", [("review-findings.json", CRIT_REVIEW[:-1] + ",}"), ("review-findings.json", "[" + CRIT_REVIEW + "]"),
                                       ("review-findings.json", CRIT_REVIEW.replace('"findings"', '"Findings"')),
                                       ("dast-findings.json", "not json"), ("coverage.json", "[1]"), ("retest.json", "{{")])
def test_a_result_file_that_is_there_but_unreadable_is_never_ready(tmp_path, name, data):
    project(tmp_path)
    raw_write(tmp_path / ".security" / name, data.encode())
    assert R.main(["--root", str(tmp_path)]) == 0
    state = json.loads((tmp_path / ".security" / "report-state.json").read_text())
    assert state["verdict"] == "BLOCKED" and state["readiness"] == "NOT READY" and name in state["why"]
    code, msg = H.build(tmp_path)
    assert code in (1, 3) and ("NOT READY" in msg or name in msg)


@pytest.mark.parametrize("latest", ["[]", "null", "{{{", '{"findings": [], "tool_status": ' + "9" * 5000 + "}"])
def test_an_unreadable_latest_run_is_blocked_even_with_a_clean_older_copy(tmp_path, latest):
    sec = tmp_path / ".security"
    write(sec / "findings-before.json", gate([]))
    write(sec / "coverage.json", full_coverage())
    raw_write(sec / "findings.json", latest.encode())
    assert R.main(["--root", str(tmp_path)]) == 0
    state = json.loads((sec / "report-state.json").read_text())
    assert state["verdict"] == "BLOCKED" and state["readiness"] == "NOT READY"


def test_a_review_finding_with_no_severity_is_high_and_a_dast_label_with_a_note_keeps_its_level(tmp_path):
    review = [dict(REVIEW[0])]
    del review[0]["severity"]
    _, state = project(tmp_path, review=review, retest={"results": [{}]})
    assert state["verdict"] == "FAILED" and state["counts"]["HIGH"] == 1
    assert R.norm_finding({"severity": "High (Medium)"})["severity"] == "HIGH"
    assert R.norm_finding({"severity": "weird"})["severity"] == "HIGH" and R.norm_finding({"line": 1e999})["line"] == 0


def test_an_acceptance_given_to_one_late_finding_does_not_move_to_the_next_one(tmp_path):
    low = {"rule": "L1", "severity": "LOW", "file": "a.py", "line": 1, "message": "m", "code": "a", "engine": "x"}
    late_low = {"rule": "L2", "severity": "LOW", "file": "b.py", "line": 1, "message": "m", "code": "b", "engine": "x"}
    new_med = {"rule": "M1", "severity": "MEDIUM", "file": "c.py", "line": 1, "message": "m", "code": "c", "engine": "x"}
    sec = tmp_path / ".security"
    write(sec / "findings-before.json", gate([low]))
    accept = {"results": [{"id": "F-02", "outcome": "Risk accepted", "accepted_by": "Lead", "date": "2026-11-20"}]}
    md, state = project(tmp_path, findings=[low, late_low, new_med], retest=accept)
    assert "| F-02 | Risk accepted |" not in md and state["readiness"] == "NOT READY"


def test_one_pass_does_not_close_two_findings(tmp_path):
    a = dict(REVIEW[0], id="R-01", line=10, severity="HIGH")
    b = dict(REVIEW[0], line=90, severity="CRITICAL")
    del b["id"]
    m = R.build(tmp_path, write(tmp_path / ".security" / "findings.json", gate([])), None, None, None, None,
                write(tmp_path / ".security" / "review-findings.json", {"findings": [a, b]}), None)
    fa = [f for f in m["findings"] if f["id"] == "R-01"][0]
    assert len({f["fp"] for f in m["findings"]}) == 2                # the line tells them apart
    ok = {"results": [{"id": "R-01", "fingerprint": fa["fp"], "outcome": "Pass", "evidence": "tests/Security/test_o.py::test_x"}]}
    _, state = project(tmp_path, review=[a, b], retest=ok)
    assert state["verdict"] == "FAILED" and state["counts"]["CRITICAL"] == 1
    same = [{"rule": "zap-10", "severity": "HIGH", "url": "http://127.0.0.1/a", "message": "m"}] * 2
    dast = {"status": "ran", "target": "http://127.0.0.1", "findings": same}
    m2 = R.build(tmp_path, tmp_path / ".security" / "findings.json", None, write(tmp_path / "d.json", dast), None, None)
    fp = m2["findings"][0]["fp"]
    rt = write(tmp_path / "rt.json", {"results": [{"fingerprint": fp, "outcome": "Pass", "evidence": "curl -i http://127.0.0.1/a gives 403"}]})
    m3 = R.build(tmp_path, tmp_path / ".security" / "findings.json", None, tmp_path / "d.json", rt, None)
    assert [f["retest"]["outcome"] for f in m3["findings"]] == ["Not retested", "Not retested"]


@pytest.mark.parametrize("name", ["unhackable-shop", "bulletproof-api", "ready-for-pentest", "fully secure app"])
def test_a_project_name_or_a_quoted_code_line_does_not_fail_the_tools_own_report(tmp_path, name):
    root = tmp_path / name
    root.mkdir()
    f = [{"rule": "X_LOW", "severity": "LOW", "file": "no vulnerabilities remain.py", "line": 1, "message": "the app is 100% secure",
          "code": "# this is fully secure and bulletproof", "engine": "local"}]
    md, _ = project(root, findings=f, coverage=None, retest={"results": [{}]})
    assert lint_errors(md) == []
    code, msg = H.build(root)
    assert code == 1 and "lint" not in msg


def test_a_quoted_secret_with_a_comma_is_not_written_into_the_report(tmp_path):
    value = "".join(["Tr0ub4dor", ",3x", "ample"])
    f = [{"rule": "X", "severity": "LOW", "file": "a.py", "line": 1, "message": "m", "code": "pass" + f'word = "{value}"', "engine": "local"}]
    md, _ = project(tmp_path, findings=f, retest={"results": [{}]})
    html = (tmp_path / ".security" / "REPORT.html").read_text(encoding="utf-8")
    assert value not in md and value not in html and lint_errors(md) == []


@pytest.mark.parametrize("field", ["message", "code", "file", "rule"])
def test_odd_text_and_odd_types_give_a_report_not_a_traceback(tmp_path, field, capsys):
    f = {"rule": "X", "severity": "LOW", "file": "a.py", "line": 1, "message": "m", "code": "c", "engine": "local"}
    f[field] = "x" + chr(0xD800) + "y"
    sec = tmp_path / ".security"
    write(sec / "findings.json", {"mode": "ci", "tool_status": {"semgrep": True, "trivy": True, "gitleaks": True, "errors": ["boom"], "notes": 5},
                                  "findings": [f, {"line": 1e999}]})
    assert R.main(["--root", str(tmp_path)]) == 0
    assert "BLOCKED" in (sec / "REPORT.md").read_text(encoding="utf-8")
    code, msg = H.build(tmp_path)
    assert code in (1, 3) and "Traceback" not in msg


def test_a_finding_path_on_another_host_is_never_resolved(tmp_path, monkeypatch):
    def no_resolve(self, *a, **k):
        raise AssertionError("resolve() was called on a path from a result file")
    monkeypatch.setattr(Path, "resolve", no_resolve)
    unc = "\\\\198.51.100.7\\share\\x.py"
    assert R.rel_path(unc, tmp_path) == "//198.51.100.7/share/x.py"
    assert R.rel_path(str(tmp_path / "app" / "a.py"), tmp_path) == "app/a.py" and R.rel_path("app\\a.py", tmp_path) == "app/a.py"
    assert R.rel_path(str(tmp_path / ".." / "out.py"), tmp_path).endswith("out.py")


def test_verify_does_not_echo_a_hostile_file_name(tmp_path):
    _, _, z = build_pack(tmp_path)
    esc = chr(27)

    def forge(m):
        man = json.loads(m["MANIFEST.json"])
        man["files"].append({"name": "x" + esc + "[2J\nPASS: this is the pack", "bytes": 1, "sha256": "0" * 64})
        mb = json.dumps(man).encode()
        m["MANIFEST.json"] = mb
        m["MANIFEST.sha256"] = (__import__("hashlib").sha256(mb).hexdigest() + "  MANIFEST.json\n").encode()
    code, msg = H.verify(rezip(z, forge))
    assert code == 1 and esc not in msg and "PASS: this is the pack" not in msg

    def deep(m):
        m["MANIFEST.json"] = b"[" * 100000
    assert H.verify(rezip(z, deep))[0] == 1


def test_big_inputs_are_cut_before_they_cost_time(tmp_path):
    import time
    note = "n" * 3_000_000
    many = [dict(REVIEW[0], id=None, line=i, title=f"t{i}") for i in range(30000)]
    t = time.time()
    _, state = project(tmp_path, review=many, retest={"results": [{"id": "R-07", "outcome": "Fail", "note": note, "evidence": note}]})
    assert time.time() - t < 60 and state["readiness"] == "NOT READY" and "did not fit" in " ".join(state["readiness_why"])
    assert L.lint("x" * (L.TEXT_MAX + 1))[0] and "larger than" in L.lint("x" * (L.TEXT_MAX + 1))[0][0]


# --- review round 3 ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["review-findings.json", "dast-findings.json"])
def test_a_result_file_that_is_a_hard_link_or_a_folder_stops_the_pack(tmp_path, name):
    # The report read the file and said NOT READY; the pack skipped it as "not plain" and built a READY pack.
    project(tmp_path, review=[dict(REVIEW[0])])
    sec = tmp_path / ".security"
    target = sec / name
    if not target.exists():
        write(target, {"findings": [dict(REVIEW[0])]})
    try:
        os.link(target, tmp_path / "second-name.json")
    except (OSError, NotImplementedError):
        pytest.skip("no hard links here")
    code, msg = H.build(tmp_path)
    assert code == 3 and name in msg and not (sec / "handover").exists()
    os.unlink(tmp_path / "second-name.json")
    os.unlink(target)
    target.mkdir()
    code, msg = H.build(tmp_path)
    assert code == 3 and name in msg


def dast_file(findings):
    return {"status": "ran", "scan": "baseline", "target": "http://127.0.0.1:8000", "tool": "zap", "findings": findings}


XSS = {"rule": "zap-xss", "severity": "HIGH", "url": "http://127.0.0.1:8000/search", "message": "reflected XSS", "cwe": "79"}
SQLI = {"rule": "zap-sqli", "severity": "HIGH", "url": "http://127.0.0.1:8000/orders", "message": "SQL injection", "cwe": "89"}


def test_a_dast_pass_does_not_move_to_the_next_finding_when_the_scan_is_run_again(tmp_path):
    sec = tmp_path / ".security"
    project(tmp_path)
    write(sec / "dast-findings.json", dast_file([XSS, SQLI]))
    assert R.main(["--root", str(tmp_path)]) == 0
    prints = json.loads((sec / "report-state.json").read_text())["fingerprints"]
    md = (sec / "REPORT.md").read_text(encoding="utf-8")
    m = R.build(tmp_path, sec / "findings.json", None, sec / "dast-findings.json", None, None)
    xss_id = [f["id"] for f in m["findings"] if f["rule"] == "zap-xss"][0]
    assert f"fingerprint `{prints[xss_id]}`" in md
    # by id only: not used, and the report says why and what to add
    write(sec / "retest.json", {"results": [{"id": xss_id, "outcome": "Pass", "evidence": "tests/test_search.py::test_escaped"}]})
    assert R.main(["--root", str(tmp_path)]) == 0
    md = (sec / "REPORT.md").read_text(encoding="utf-8")
    assert json.loads((sec / "report-state.json").read_text())["verdict"] == "FAILED" and "matched by its fingerprint" in md
    # the fixed one is gone after the rerun; the Pass that named it closes nothing else
    write(sec / "retest.json", {"results": [{"id": "D-01", "fingerprint": prints[xss_id], "outcome": "Pass",
                                             "evidence": "tests/test_search.py::test_escaped"}]})
    write(sec / "dast-findings.json", dast_file([SQLI]))
    assert R.main(["--root", str(tmp_path)]) == 0
    state = json.loads((sec / "report-state.json").read_text())
    assert state["verdict"] == "FAILED" and state["counts"]["HIGH"] == 1
    # and an honest Pass by fingerprint does close its own finding
    write(sec / "dast-findings.json", dast_file([XSS, SQLI]))
    both = [{"fingerprint": prints[i], "outcome": "Pass", "evidence": "tests/test_dast.py::test_refused_" + i} for i in ("D-01", "D-02")]
    write(sec / "retest.json", {"results": both})
    assert R.main(["--root", str(tmp_path)]) == 0
    assert json.loads((sec / "report-state.json").read_text())["verdict"] == "PASSED"


def test_a_finding_matched_by_fingerprint_can_be_closed_and_an_ignored_entry_is_explained(tmp_path):
    review = [dict(REVIEW[0])]
    del review[0]["id"]
    _, state = project(tmp_path, review=review, retest={"results": [{"id": "R-01", "outcome": "Pass", "evidence": "tests/t.py::test_x"}]})
    md = (tmp_path / ".security" / "REPORT.md").read_text(encoding="utf-8")
    fp = state["fingerprints"]["R-01"]
    assert state["verdict"] == "FAILED" and f'add "fingerprint": "{fp}"' in md.replace("\\", "")
    _, state = project(tmp_path, review=review, retest={"results": [{"fingerprint": fp, "outcome": "Pass", "evidence": "tests/t.py::test_x"}]})
    assert state["verdict"] == "PASSED" and state["readiness"] == "READY FOR PENTEST REVIEW"


@pytest.mark.parametrize("text", ["curl -H 'Author" + "ization: Bearer {s}' http://x", "Author" + "ization: Basic {s}", "curl -" + "u admin:{s} http://x",
                                  "Cookie: laravel_session={s}", "curl -b PHPSESSID={s} http://x", "redis://:{s}@cache:6379/0",
                                  "mysql -uroot -p{s} shop", "tool --pass" + "word {s}", "docker login -u me -p {s}", "APP_KEY={s}",
                                  "ENCRYPTION_KEY = {s}"])
def test_secrets_in_commands_and_headers_do_not_reach_the_report_or_the_pack(tmp_path, text):
    s = "".join(["abcDEF", "1234567890", "xyzABCDEF"])
    line = text.replace("{s}", s)
    assert s not in R.redact(line), R.redact(line)
    project(tmp_path, retest={"results": []})
    sec = tmp_path / ".security"
    write(sec / "RUNBOOK.md", "Start the app:\n" + line + "\n")
    write(sec / "artifacts.json", {"artifacts": [{"item": "probe", "purpose": line}]})
    _, _, z = build_pack(tmp_path)
    with zipfile.ZipFile(z) as zf:
        assert s.encode() not in b"".join(zf.read(n) for n in zf.namelist())
    assert R.redact("mkdir -p build && tar -xzf a.tgz") == "mkdir -p build && tar -xzf a.tgz"      # ordinary options stay readable


def test_a_whole_key_block_is_removed_from_text_members(tmp_path):
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "A" * 40
    project(tmp_path)
    write(tmp_path / ".security" / "RUNBOOK.md", "key:\n-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n" + body[::-1] + "\n-----END " + "PRIVATE KEY-----\nrest\n")
    _, _, z = build_pack(tmp_path)
    book = zipfile.ZipFile(z).read("RUNBOOK.md").decode()
    assert body not in book and body[::-1] not in book and "rest" in book


def test_text_from_a_result_file_can_not_borrow_the_detail_line_exemption(tmp_path):
    # Text from a result file is always shown as quoted (a table cell, a numbered line, a code span), so it neither
    # fails the tool's own report nor can pose as the report's words. A line that merely starts like a detail line,
    # written into the report by hand, is prose and is checked.
    project(tmp_path)
    sec = tmp_path / ".security"
    write(sec / "dast-findings.json", {"status": "skipped", "note": "**F-01** (x) the app is fully secure ` and unhackable"})
    assert R.main(["--root", str(tmp_path)]) == 0
    md = (sec / "REPORT.md").read_text(encoding="utf-8")
    assert lint_errors(md) == [] and "did not run: `" in md
    assert any("overclaim" in e for e in lint_errors(md + "\n- \\*\\*F-01\\*\\* (x) the app is fully secure\n"))
    assert any("overclaim" in e for e in lint_errors(md + "\n- **note** the app is unhackable\n"))


def test_an_observation_is_quoted_text_and_honest_wording_in_it_passes(tmp_path):
    # Round 4: "no issues found there after the fix" in an observation failed the lint and stopped an honest pack.
    obs = {"results": [], "observations": [{"title": "Reset form", "location": "app/reset.py:9",
                                            "note": "no issues found there after the fix; production-ready settings file"}]}
    md, _ = project(tmp_path, retest=obs)
    assert "- **O-01** (" in md and lint_errors(md) == []
    assert H.build(tmp_path)[0] == 0


def test_a_finding_the_latest_run_rates_higher_is_listed_at_the_higher_level(tmp_path):
    low = {"rule": "BANDIT_B404", "severity": "LOW", "file": "app/views.py", "line": 1, "message": "m", "code": "1 import subprocess", "engine": "bandit"}
    sec = tmp_path / ".security"
    write(sec / "findings-before.json", gate([low]))
    md, state = project(tmp_path, findings=[dict(low, severity="CRITICAL")], retest={"results": [{}]})
    assert state["verdict"] == "FAILED" and state["counts"]["CRITICAL"] == 1 and state["counts"]["LOW"] == 0
    assert "the higher one is used" in md


@pytest.mark.parametrize("name,data", [("review-findings.json", {"findings": [dict(REVIEW[0], id="R-01"), "R-03: HIGH IDOR in /api/admin/users"]}),
                                       ("findings.json", {"mode": "ci", "tool_status": {"semgrep": True, "trivy": True, "gitleaks": True, "errors": {}},
                                                          "findings": [[dict(CRIT)]]}),
                                       ("dast-findings.json", {"status": "ran", "target": "http://127.0.0.1", "findings": [5]}),
                                       ("retest.json", {"results": ["F-01 pass"]})])
def test_an_entry_that_is_not_an_object_makes_the_file_unreadable_not_shorter(tmp_path, name, data):
    project(tmp_path)
    write(tmp_path / ".security" / name, data)
    assert R.main(["--root", str(tmp_path)]) == 0
    state = json.loads((tmp_path / ".security" / "report-state.json").read_text())
    assert state["verdict"] in ("BLOCKED", "FAILED") and state["readiness"] == "NOT READY"
    assert name in (tmp_path / ".security" / "REPORT.md").read_text(encoding="utf-8").replace("\\", "")


@pytest.mark.parametrize("sev", [None, ["HIGH"], 4, "Severe", "HIGH1", "CRITICAL_", "BLOCKER", "9.8", "ERROR"])
def test_a_scanner_or_dast_finding_with_an_unknown_severity_is_not_informational(tmp_path, sev):
    f = dict(CRIT, severity=sev)
    if sev is None:
        del f["severity"]
    _, state = project(tmp_path, findings=[f], retest={"results": [{}]})
    assert state["verdict"] == "FAILED" and state["counts"]["HIGH"] == 1
    assert R.norm_finding({"severity": "Informational"})["severity"] == "INFO" and R.norm_finding({"severity": "warning"})["severity"] == "MEDIUM"


@pytest.mark.parametrize("enc", ["utf-8-sig", "utf-16"])
def test_the_pack_carries_every_file_the_report_read_whatever_its_encoding(tmp_path, enc):
    project(tmp_path, review=[dict(REVIEW[0])], retest={"results": [{"id": "R-07", "outcome": "Pass", "evidence": "tests/t.py::test_x"}]})
    sec = tmp_path / ".security"
    for n in ("coverage.json", "retest.json", "review-findings.json"):
        raw_write(sec / n, (sec / n).read_text(encoding="utf-8").encode(enc))
    code, msg = H.build(tmp_path)
    z = sorted((sec / "handover").glob("*.zip"))[-1]
    names = zipfile.ZipFile(z).namelist()
    assert code == 0 and {"coverage.json", "retest.json", "review-findings.json"} <= set(names) and "left out" not in msg
    raw_write(sec / "retest.json", b"{broken")
    code, msg = H.build(tmp_path)
    assert code == 3 and "retest.json" in msg


def test_two_findings_that_share_a_fingerprint_say_why_an_entry_was_not_used(tmp_path):
    twin = {"rule": "zap-x", "severity": "MEDIUM", "url": "http://127.0.0.1:8000/a", "message": "m"}
    sec = tmp_path / ".security"
    project(tmp_path)
    write(sec / "dast-findings.json", dast_file([twin, dict(twin)]))
    m = R.build(tmp_path, sec / "findings.json", None, sec / "dast-findings.json", None, None)
    fp = m["findings"][0]["fp"]
    write(sec / "retest.json", {"results": [{"id": "D-01", "fingerprint": fp, "outcome": "Risk accepted", "accepted_by": "Lead", "date": "2026-11-20"}]})
    assert R.main(["--root", str(tmp_path)]) == 0
    md = (sec / "REPORT.md").read_text(encoding="utf-8")
    assert "share this fingerprint" in md and json.loads((sec / "report-state.json").read_text())["readiness"] == "NOT READY"


@pytest.mark.parametrize("data", ['{"status": "ran", "target": "http://127.0.0.1", "findings": {"a": 1}}', '{"status": "ran", "findings": "none"}'])
def test_a_dast_file_whose_findings_are_not_a_list_is_unreadable_not_empty(tmp_path, data):
    project(tmp_path)
    raw_write(tmp_path / ".security" / "dast-findings.json", data.encode())
    assert R.main(["--root", str(tmp_path)]) == 0
    assert json.loads((tmp_path / ".security" / "report-state.json").read_text())["verdict"] == "BLOCKED"


# --- review round 5 ----------------------------------------------------------------------------------------------------

def test_a_long_string_that_looks_like_the_start_of_a_token_does_not_stall_anything(tmp_path):
    import time
    bad = "eyJ-" * 50000
    project(tmp_path)
    sec = tmp_path / ".security"
    write(sec / "artifacts.json", {"artifacts": [{"item": bad, "purpose": bad}]})
    write(sec / "RUNBOOK.md", bad + "\n" + ("-----BEGIN X-----\n" * 20000))
    t = time.time()
    assert R.redact(bad) and R.main(["--root", str(tmp_path)]) == 0
    code, msg = H.build(tmp_path)
    assert code == 0 and time.time() - t < 20
    jwt = "".join(["ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "JzdWIiOiIxMjM0NTYifQ", ".", "c2lnbmF0dXJlX3ZhbHVl"])
    assert jwt not in R.redact("token " + jwt) and jwt not in R.redact("x=" + jwt)


@pytest.mark.parametrize("name", ["RUNBOOK.md", "authz-matrix.md", "findings-summary.txt"])
def test_a_utf16_text_file_is_decoded_before_it_is_checked_for_secrets(tmp_path, name):
    s = "".join(["abcDEF", "1234567890", "xyzABCDEF"])
    project(tmp_path)
    sec = tmp_path / ".security"
    raw_write(sec / name, ("| route | verb |\n|---|---|\n| /a | GET |\nAuthor" + f"ization: Bearer {s}\nAPP_KEY={s}\n").encode("utf-16"))
    _, _, z = build_pack(tmp_path)
    member = zipfile.ZipFile(z).read(name)
    assert s.encode() not in member and b"\x00" not in member and s.encode("utf-16-le") not in member and b"route" in member
    raw_write(sec / name, b"a\x00b\x00 plain bytes with NULs")
    code, msg = H.build(tmp_path)
    assert code == 3 and name in msg


@pytest.mark.parametrize("text", ['curl -' + 'u "admin:{s}" http://x', "curl --us" + "er 'u:{s}' http://x", 'curl -b "PHPSESSID={s}" http://x',
                                  "curl --cookie SID={s} http://x", "sshpass -p '{s}' ssh host", 'tool --pass' + 'word "{s}"',
                                  "redis-cli -a {s} ping", "sqlcmd -S db -U sa -P {s}"])
def test_quoted_option_values_are_redacted(text):
    s = "".join(["abcDEF", "1234567890", "xyzABCDEF"])
    assert s not in R.redact(text.replace("{s}", s)), R.redact(text.replace("{s}", s))


def test_a_long_name_on_an_accepted_risk_passes_the_lint(tmp_path):
    low = {"rule": "L1", "severity": "LOW", "file": "a.py", "line": 1, "message": "m", "code": "a", "engine": "x"}
    sec = tmp_path / ".security"
    write(sec / "findings-before.json", gate([low]))
    who = "  Dr. Ayesha Khan, Head of Application Security, Cyber Security Department, change ticket SEC-2026-11-0042, approved in the weekly review  "
    md, state = project(tmp_path, findings=[low], retest={"results": [{"id": "F-01", "outcome": "Risk accepted", "accepted_by": who, "date": "2026-11-20"}]})
    assert "| F-01 | Risk accepted |" in md and lint_errors(md) == [] and H.build(tmp_path)[0] == 0


@pytest.mark.parametrize("key", ["Findings", "alerts", "site"])
def test_a_dast_file_that_ran_must_hold_its_findings_under_the_known_name(tmp_path, key):
    project(tmp_path)
    write(tmp_path / ".security" / "dast-findings.json", {"status": "ran", "target": "http://127.0.0.1:8000", key: [dict(XSS)]})
    assert R.main(["--root", str(tmp_path)]) == 0
    assert json.loads((tmp_path / ".security" / "report-state.json").read_text())["verdict"] == "BLOCKED"


@pytest.mark.parametrize("name", ["findings.json", "review-findings.json", "dast-findings.json"])
def test_a_repeated_key_does_not_hide_the_findings_before_it(tmp_path, name):
    project(tmp_path)
    one = json.dumps([dict(CRIT)] if name == "findings.json" else [dict(REVIEW[0], severity="CRITICAL")] if name.startswith("review") else [dict(XSS)])
    head = '"mode": "ci", "tool_status": {"semgrep": true, "trivy": true, "gitleaks": true, "errors": {}}, ' if name == "findings.json" else \
        ('"status": "ran", "target": "http://127.0.0.1:8000", ' if name.startswith("dast") else "")
    raw_write(tmp_path / ".security" / name, ("{" + head + '"findings": ' + one + ', "findings": []}').encode())
    assert R.main(["--root", str(tmp_path)]) == 0
    assert json.loads((tmp_path / ".security" / "report-state.json").read_text())["verdict"] == "BLOCKED"
    assert H.build(tmp_path)[0] == 3


def test_without_a_first_run_file_an_acceptance_by_number_does_not_pass_to_the_next_finding(tmp_path):
    old = {"rule": "M0", "severity": "MEDIUM", "file": "a.py", "line": 1, "message": "m", "code": "a", "engine": "x"}
    new = {"rule": "M9", "severity": "MEDIUM", "file": "z.py", "line": 1, "message": "m", "code": "z", "engine": "x"}
    accept = {"results": [{"id": "F-01", "outcome": "Risk accepted", "accepted_by": "Ayesha Khan", "date": "2026-11-20"}]}
    md, state = project(tmp_path, findings=[old], retest=accept)
    assert "matched by its fingerprint" in md and state["readiness"] == "NOT READY"
    fp = state["fingerprints"]["F-01"]
    accept["results"][0]["fingerprint"] = fp
    _, state = project(tmp_path, findings=[old], retest=accept)
    assert state["readiness"] == "CONDITIONALLY READY"
    md, state = project(tmp_path, findings=[new], retest=accept)          # the accepted one is gone, a new one is F-01
    assert "Ayesha" not in md and state["readiness"] == "NOT READY"


@pytest.mark.parametrize("name", ["REPORT.md", "report-state.json"])
def test_a_folder_where_a_report_file_goes_gives_a_message(tmp_path, name, capsys):
    write(tmp_path / ".security" / "findings.json", gate([]))
    (tmp_path / ".security" / name).mkdir()
    assert R.main(["--root", str(tmp_path)]) == 3 and "could not be written" in capsys.readouterr().out


def test_a_finding_that_says_ready_does_not_fail_an_honest_not_ready_report(tmp_path):
    f = [{"rule": "X_LOW", "severity": "LOW", "file": "a.py", "line": 1, "message": "status: ready for pentest", "code": "status: ready", "engine": "x"}]
    obs = {"results": [{}], "observations": [{"title": "t", "location": "x", "note": "ready for pentest after the next release"}]}
    (tmp_path / ".security").mkdir()
    (tmp_path / ".security" / "fully secure.txt").write_text("x")
    md, state = project(tmp_path, findings=f, coverage=None, retest=obs)
    assert state["readiness"] == "NOT READY" and lint_errors(md) == []


# --- review round 1: the lint ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("dress", ["Handover readiness: <b>READY FOR PENTEST REVIEW</b>", "Handover readiness: - READY",
                                   "Handover readiness: _READY FOR PENTEST REVIEW_", "Result: ready for PEN-TEST review",
                                   "Handover status: READY", "**Readiness:** READY"])
def test_the_lint_sees_a_ready_claim_however_it_is_dressed(tmp_path, dress):
    md, _ = project(tmp_path, coverage=None)
    assert lint_errors(md) == []
    assert any("READY FOR PENTEST REVIEW while" in e for e in lint_errors(md + "\n" + dress + "\n"))


def test_the_lint_matches_coverage_rows_to_the_review_classes(tmp_path):
    md, _ = project(tmp_path)
    lines = md.splitlines()
    idx = [i for i, ln in enumerate(lines) if ln.startswith("| Server-side request forgery")][0]
    same = lines[:idx] + [lines[idx - 1]] + lines[idx + 1:]         # one class twice, one missing: still 24 rows
    errs = lint_errors("\n".join(same))
    assert any("appears more than once" in e for e in errs) and any("23 of the 24" in e for e in errs)
    odd = lines[:idx] + ["| Everything | examined | trust me, all of it |"] + lines[idx + 1:]
    assert any("not one of the review classes" in e for e in lint_errors("\n".join(odd)))


@pytest.mark.parametrize("honest", ["No issues found is never claimed by this report.",
                                    "The scanner said no issues found but the bug is still there.",
                                    "A scanner reporting no vulnerabilities found does not prove safety.",
                                    "This report does not say the pentest passed.",
                                    "| F-01 | x | HIGH | C | a.py:1 | # TODO use a production-ready server | fix | Fail |"])
def test_the_lint_lets_honest_sentences_and_quoted_code_through(tmp_path, honest):
    md, _ = project(tmp_path)
    assert not any("overclaim" in e for e in lint_errors(md + "\n" + honest + "\n"))


def test_one_very_long_line_does_not_stall_the_lint(tmp_path):
    import time
    md, _ = project(tmp_path)
    t = time.time()
    L.lint(md + "\n" + "unhackable not " * 8000 + "\n")
    assert time.time() - t < 5
