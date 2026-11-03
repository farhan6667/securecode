"""7.0 integration fixes (V7I-*): suppression expiry, unreadable scanner output, stray control characters,
staging target checks for nuclei and ZAP, and SQL_CONCAT on bound parameters. Each test failed on the code
before its fix."""
import datetime as dt, importlib.util, io, ipaddress, json, os, re, subprocess, sys
from contextlib import redirect_stdout
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


G = load("scripts/secgate.py", "sg_v7i")


# --- V7I-01 suppression expiry ------------------------------------------------------------------------------

def _suppress(tmp_path, monkeypatch, expires_lines):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    body = "suppressions:\n" + "".join(
        f"  - {{rule: R1, file: a.py, reason: test, owner: sec@example.test, expires: {e}}}\n" for e in expires_lines)
    sup = tmp_path / "sup.yaml"
    sup.write_text(body, encoding="utf-8")
    monkeypatch.setenv("SECGATE_SUPPRESSIONS", str(sup))
    notes = []
    out = G.apply_suppressions([{"rule": "R1", "severity": "HIGH", "file": str(tmp_path / "a.py"), "line": 1, "message": "m"}],
                               tmp_path.resolve(), "ci", notes)
    return out, notes


@pytest.mark.parametrize("expires", ['"20260115"', '"2026-W01"', '"2026W01"', '"2026-W01-1"', '"2026-001"',
                                     '"20261231"', '"2026-1-5"', '"2026-01-15T00:00:00"', '"next year"', "20261231", "[]"])
def test_non_iso_expiry_is_expired_and_named(tmp_path, monkeypatch, expires):
    out, notes = _suppress(tmp_path, monkeypatch, [expires])
    assert len(out) == 1, (expires, notes)                        # still reported: fail closed
    assert any("a.py" in n and ("expired" in n or "incomplete" in n) for n in notes), notes


def test_iso_expiry_still_works(tmp_path, monkeypatch):
    soon = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    out, notes = _suppress(tmp_path, monkeypatch, [f'"{soon}"'])
    assert out == [], notes
    out, notes = _suppress(tmp_path, monkeypatch, [soon])           # unquoted: YAML reads a date object
    assert out == [], notes
    past = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    out, _ = _suppress(tmp_path, monkeypatch, [f'"{past}"'])
    assert len(out) == 1


def test_parse_expiry_is_strict():
    p = G.parse_expiry
    assert p("2026-12-31") == dt.date(2026, 12, 31) and p(dt.date(2026, 1, 2)) == dt.date(2026, 1, 2)
    for bad in ("20261231", "2026-W01", "2026-12-31 ", " 2026-12-31", "2026-02-30", "２０２６-01-01", "2026-12-31\n",
                dt.datetime(2026, 1, 1), 20261231, None, ""):
        assert p(bad) is None, bad


# --- V7I-02 unreadable scanner output -----------------------------------------------------------------------

DEEP = "[" * 200_000 + "]" * 200_000
HUGE = "9" * 5000

SEMGREP_BAD = ['{"results":[1]}', '{"results":{"a":1}}', DEEP, '{"results":' + DEEP + '}',
               '{"results":[{"start":{"line":' + HUGE + '}}]}', '{"results":[{"extra":"x"}]}',
               '{"results":[{"extra":{"message":{"a":1}}}]}', '{"results":[{"start":[1]}]}', "null", '"text"', "[]",
               '{"results":[{"check_id":["x"]}]}', '{"results":[{"extra":{"severity":{"x":1}}}]}', "{not json"]
TRIVY_BAD = ['{"Results":"x"}', '{"Results":[1]}', '{"Results":[{"Vulnerabilities":[{"Severity":["x"]}]}]}',
             '{"Results":[{"Secrets":[{"StartLine":{"a":1}}]}]}', '{"Results":[{"Misconfigurations":{"a":1}}]}', DEEP,
             '{"Results":[{"Target":' + HUGE + '}]}', "[]", '{"Results":[{"Vulnerabilities":[{"Title":[1]}]}]}']
GITLEAKS_BAD = ["[1]", '{"a":1}', DEEP, '[{"StartLine":"abc"}]', '[{"File":{"x":1}}]', '[{"StartLine":' + HUGE + '}]']


def _with_fake(monkeypatch, out_text, report_text=None):
    def fake_run(cmd, cwd, timeout=600, env=None):
        if "--report-path" in cmd:
            Path(cmd[cmd.index("--report-path") + 1]).write_text(report_text if report_text is not None else "[]", encoding="utf-8")
            return 0, "", ""
        return 0, out_text, ""
    monkeypatch.setattr(G, "find_tool", lambda name: name if name in ("semgrep", "trivy", "gitleaks") else None)
    monkeypatch.setattr(G, "run", fake_run)


@pytest.mark.parametrize("out", SEMGREP_BAD, ids=[f"s{i}" for i in range(len(SEMGREP_BAD))])
def test_malformed_semgrep_is_unreadable_not_a_crash(tmp_path, monkeypatch, out):
    _with_fake(monkeypatch, out)
    findings = []
    ok, msg = G.collect_semgrep(tmp_path, findings, mode="ci")
    assert not ok and "scanner output unreadable" in msg or (not ok and out == "{not json"), msg
    assert findings == []


@pytest.mark.parametrize("out", TRIVY_BAD, ids=[f"t{i}" for i in range(len(TRIVY_BAD))])
def test_malformed_trivy_is_unreadable_not_a_crash(tmp_path, monkeypatch, out):
    _with_fake(monkeypatch, out)
    findings = []
    ok, msg = G.collect_trivy(tmp_path, findings, mode="ci")
    assert not ok and "scanner output unreadable" in msg, msg
    assert findings == []


@pytest.mark.parametrize("report", GITLEAKS_BAD, ids=[f"g{i}" for i in range(len(GITLEAKS_BAD))])
def test_malformed_gitleaks_is_unreadable_not_a_crash(tmp_path, monkeypatch, report):
    _with_fake(monkeypatch, "", report)
    findings = []
    ok, msg = G.collect_gitleaks(tmp_path, findings, mode="full")
    assert not ok and "scanner output unreadable" in msg, msg
    assert findings == []


def test_good_scanner_output_still_parses(tmp_path, monkeypatch):
    _with_fake(monkeypatch, json.dumps({"results": [{"check_id": "x.sqli", "path": "a.py", "start": {"line": "7"},
                                                     "extra": {"severity": "ERROR", "message": "m", "lines": "l",
                                                               "metadata": {"confidence": "HIGH"}}}]}))
    f = []
    assert G.collect_semgrep(tmp_path, f)[0] and f[0]["line"] == 7 and f[0]["severity"] == "HIGH"
    _with_fake(monkeypatch, json.dumps({"Results": [{"Target": "req.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "PkgName": "p", "InstalledVersion": 1.0}]}]}))
    f = []
    assert G.collect_trivy(tmp_path, f)[0] and f[0]["rule"] == "CVE-1"


def _main(monkeypatch, tmp_path, mode):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["secgate", ".", "--mode", mode, "--fail-on", "never"])
    monkeypatch.setattr(G, "_engines", lambda: None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = G.main()
    return rc, buf.getvalue()


def test_unreadable_required_scanner_blocks_ci_and_is_a_note(tmp_path, monkeypatch):
    _with_fake(monkeypatch, '{"results":[1]}')
    rc, out = _main(monkeypatch, tmp_path, "ci")
    assert rc == 3 and "BLOCKED" in out, out
    assert re.search(r"NOTE: semgrep: scanner output unreadable", out), out
    rc, out = _main(monkeypatch, tmp_path, "full")
    assert rc == 0 and "PARTIAL" in out and "Traceback" not in out, out


def test_a_collector_that_raises_still_fails_closed(tmp_path, monkeypatch):
    _with_fake(monkeypatch, '{"results":[]}')

    def boom(root, findings, mode="full"):
        raise RecursionError("deep")
    monkeypatch.setattr(G, "collect_trivy", boom)
    rc, out = _main(monkeypatch, tmp_path, "ci")
    assert rc == 3 and "trivy: scanner output unreadable" in out, out


def test_engine_readers_survive_hostile_reports(tmp_path):
    eng = G._engines()
    if eng is None:
        pytest.skip("engines package not loaded")
    for e in eng.RUNNABLE:
        for bad in (DEEP, "[1,2]", '{"results":"x","runs":7,"vulnerabilities":[1]}', HUGE, "null", '{"a":' + DEEP + "}"):
            try:
                r = e.normalize(bad, tmp_path)
            except Exception:
                continue                          # run_engines turns this into a NOTE (tested in test_v7_engines)
            assert isinstance(r, list), e.name


# --- V7I-03 stray control characters and duplicate v-html ---------------------------------------------------

HIDDEN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")


def test_rule_patterns_hold_no_control_characters():
    for rid, _, rx in G.RULES:
        assert not HIDDEN.search(rx), rid


def test_tracked_source_files_hold_no_hidden_characters():
    try:
        files = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, timeout=60).stdout.decode("utf-8").split("\0")
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git not available")
    files = [f for f in files if f.endswith((".py", ".yml", ".yaml", ".md", ".json", ".toml"))]
    if not files:
        pytest.skip("not a git checkout")
    bad = []
    for f in files:
        p = ROOT / f
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            m = HIDDEN.search(line)
            if m:
                bad.append(f"{f}:{n} U+{ord(m.group()):04X}")
    assert not bad, "write hidden characters as escapes (\\u202e), never literally: " + ", ".join(bad[:20])


def test_v_html_is_reported_once(tmp_path):
    (tmp_path / "C.vue").write_text('<template><div v-html="msg"></div><p v-html = "x"></p></template>\n', encoding="utf-8")
    rules = [f["rule"] for f in G.local_scan(str(tmp_path))]
    assert rules == ["VUE_RAW_HTML"], rules
    (tmp_path / "C.vue").write_text("<div>{!! $x !!}</div>\n", encoding="utf-8")
    assert [f["rule"] for f in G.local_scan(str(tmp_path))] == ["XSS_RAW_TEMPLATE"]


def test_deny_list_fix_still_sees_v_html_sinks():
    assert any(rx.search('<div v-html="userInput"></div>') for rx in G._DENY_SINKS)


# --- V7I-04 staging target checks (nuclei and ZAP) ----------------------------------------------------------

N = load("scripts/run-nuclei-authorized.py", "nuclei_v7i")


def zap():
    # loaded per test: the old script ran (and exited) on import
    return load("scripts/run-zap-authorized.py", "zap_v7i")


def res(*ips):
    calls = []

    def r(host):
        calls.append(host)
        return list(ips)
    r.calls = calls
    return r


PUBLIC = res("203.0.113.10")

REFUSED = [
    "http://[fd00:ec2:0::254]/", "http://[fd00:ec2::254]/latest", "http://[::ffff:100.100.100.200]/",
    "http://[::ffff:169.254.169.254]/", "http://[64:ff9b::a9fe:a9fe]/", "http://[::169.254.169.254]/",
    "http://[2002:a9fe:a9fe::]/",                               # 6to4 around 169.254.169.254
    "http://metadata.goog/", "http://metadata.goog./computeMetadata/v1/", "http://metadata.google.internal/",
    "http://metadata.azure.com/", "http://metadata.azure/", "http://metadata/", "http://instance-data.ec2.internal/",
    "http://2852039166/", "http://0xa9fea9fe/", "http://0251.0376.0251.0376/", "http://0xa9.0xfe.0xa9.0xfe/",
    "http://169.254.43518/", "http://1684301000/",              # 169.254.169.254 and 100.100.100.200 in short forms
    "http://0x64646464/",                                       # 100.100.100.100 (carrier-grade NAT, private)
    "http://100.100.100.200/", "http://169.254.170.2/v2/credentials",
    "http://10.0.0.5/", "http://0xa000005/", "http://012.0.0.5/", "http://192.168.1.10/", "http://3232235777/",
    "http://172.16.0.1/", "http://127.0.0.1/", "http://127.1/", "http://2130706433/", "http://[::1]/",
    "http://[::ffff:127.0.0.1]/", "http://[fc00::1]/", "http://0.0.0.0/", "http://[::]/", "http://224.0.0.1/",
    "http://[fe80::1]/", "http://240.0.0.1/", "http://169.254.169.254.nip.io/", "http://a.b.c.d.e.1/",
]


@pytest.mark.parametrize("url", REFUSED)
def test_nuclei_refuses_metadata_private_and_odd_ip_forms(url):
    assert N.check_url(url, resolver=PUBLIC, env={}), url


@pytest.mark.parametrize("answers", [["169.254.169.254"], ["10.1.2.3"], ["203.0.113.5", "127.0.0.1"], ["fd00:ec2::254"],
                                     ["::ffff:169.254.169.254"], [], ["not-an-ip"]])
def test_nuclei_refuses_names_that_resolve_badly(answers):
    assert N.check_url("https://staging.example.test/", resolver=res(*answers), env={})


def test_nuclei_resolves_once_and_accepts_public_staging():
    r = res("203.0.113.10")
    assert N.check_url("https://staging.example.test/app", resolver=r, env={}) is None
    assert r.calls == ["staging.example.test"]


def test_private_staging_needs_the_exact_host_allowlisted():
    url = "http://staging.internal.test:8080/"
    assert N.check_url(url, resolver=res("10.0.0.7"), env={})
    assert N.check_url(url, resolver=res("10.0.0.7"), env={"SECURITY_DAST_PRIVATE_HOSTS": "other.test"})
    assert N.check_url(url, resolver=res("10.0.0.7"), env={"SECURITY_DAST_PRIVATE_HOSTS": "x, staging.internal.test"}) is None
    assert N.check_url("http://10.0.0.7/", resolver=PUBLIC, env={"SECURITY_DAST_PRIVATE_HOSTS": "10.0.0.7"}) is None
    # metadata and link-local are never allowed, even when named
    for host, ip in (("metadata.goog", "169.254.169.254"), ("169.254.169.254", "169.254.169.254"),
                     ("staging.internal.test", "169.254.169.254"), ("staging.internal.test", "100.100.100.200"),
                     ("0.1.2.3", "0.1.2.3"), ("[fe80::1]", "fe80::1")):
        assert N.check_url(f"http://{host}/", resolver=res(ip), env={"SECURITY_DAST_PRIVATE_HOSTS": host}), host


ZENV = {"SECURITY_DAST_ALLOW": "true", "SECURITY_DAST_URL": "https://staging.example.test/"}
DOCKER = str(Path(sys.executable).resolve())          # any absolute path stands in for docker


def test_zap_wrapper_checks_the_target_and_pins_it(tmp_path):
    Z = zap()
    cmd, err = Z.build_cmd(ZENV, tmp_path, res("203.0.113.10"), find=lambda n: DOCKER if n == "docker" else None)
    assert err is None and cmd[0] == DOCKER and os.path.isabs(cmd[0]), err
    assert "--add-host=staging.example.test:203.0.113.10" in cmd
    for url, ip in (("http://metadata.goog/", "169.254.169.254"), ("http://169.254.169.254/", "169.254.169.254"),
                    ("http://staging.example.test/", "169.254.169.254"), ("http://staging.example.test/", "10.0.0.1"),
                    ("http://2852039166/", "203.0.113.1")):
        cmd, err = Z.build_cmd({**ZENV, "SECURITY_DAST_URL": url}, tmp_path, res(ip), find=lambda n: DOCKER)
        assert cmd is None and "not run" in err, url


def test_zap_wrapper_needs_an_absolute_docker(tmp_path):
    Z = zap()
    for found in (None, "docker", "docker.exe"):
        cmd, err = Z.build_cmd(ZENV, tmp_path, PUBLIC, find=lambda n, f=found: f)
        assert cmd is None and "docker" in err


def test_zap_wrapper_does_nothing_on_import_or_without_permission(tmp_path):
    Z = zap()
    assert Z.main(env={}, resolver=PUBLIC, runner=lambda c: pytest.fail("ran"), find=lambda n: DOCKER) == 4
    ran = []
    assert Z.main(env=ZENV, resolver=PUBLIC, runner=lambda c: ran.append(c) or 0, find=lambda n: DOCKER) == 0 and ran


# --- V7I-05 SQL_CONCAT and bound parameters -----------------------------------------------------------------

def _sql_hits(tmp_path, line):
    (tmp_path / "Q.java").write_text("class Q {\n  void f() {\n    " + line + "\n  }\n}\n", encoding="utf-8")
    return [f for f in G.local_scan(str(tmp_path)) if f["rule"] == "SQL_CONCAT"]


@pytest.mark.parametrize("line", [
    'return em.createQuery("select i from Invoice i where i.note like :n").setParameter("n", "%" + note + "%").getResultList();',
    'q = em.createQuery("SELECT u FROM User u WHERE u.a = :a AND u.b = :b").setParameter("a", "x" + a).setParameter("b", b + "%");',
    'rows = db.prepare("SELECT * FROM t WHERE n LIKE :n").bind("n", "%" + n + "%").all();',
    'jdbc.query("SELECT * FROM t WHERE n = :n", new MapSqlParameterSource().addValue("n", "%" + n + "%"), rm);',
])
def test_concat_inside_bound_parameters_is_not_sql_concat(tmp_path, line):
    assert _sql_hits(tmp_path, line) == []


@pytest.mark.parametrize("line", [
    'return em.createQuery("select o from Order o where o.note like \'%" + note + "%\'").getResultList();',
    'em.createQuery("SELECT u FROM User u WHERE u.n = \'" + n + "\'").setParameter("a", a);',
    'em.createQuery("SELECT u FROM User u WHERE u.n = :n").setParameter("n", x); String q2 = "SELECT a FROM t WHERE b=\'" + z + "\'";',
    'em.createQuery("SELECT u FROM User u WHERE u.n = \'" + n + "\'").setParameter("a", unbalanced(;',
])
def test_concat_outside_bound_parameters_is_still_found(tmp_path, line):
    assert _sql_hits(tmp_path, line), line


def test_strip_bound_args_is_linear():
    import time
    t = time.perf_counter()
    G.strip_bound_args(".bind(" * 20000)
    G.strip_bound_args(".setParameter(\"" * 20000)
    G.strip_bound_args("(" * 50000 + ".bind(" + ")" * 50000)
    assert time.perf_counter() - t < 2
