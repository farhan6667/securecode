"""7.0 per-language engines: detection, pinned install plans, checksum refusal, argv safety, normalizers on
recorded sample output, and the 'not run' notes in the gate."""
import hashlib, importlib.util, io, json, os, re, subprocess, sys, tarfile, zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "engines"


def load_engines():
    here = ROOT / "scripts" / "engines"
    spec = importlib.util.spec_from_file_location("nfsc_engines", here / "__init__.py", submodule_search_locations=[str(here)])
    m = importlib.util.module_from_spec(spec)
    sys.modules["nfsc_engines"] = m
    spec.loader.exec_module(m)
    return m


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


E = load_engines()
from nfsc_engines import _base, _install  # noqa: E402


@pytest.fixture(autouse=True)
def private_tools_dir(tmp_path_factory, monkeypatch):
    # Never look at (or write to) the real tools folder of the machine running the tests.
    monkeypatch.setenv("NEXAFORGE_TOOLS_DIR", str(tmp_path_factory.mktemp("tools")))


def write(root, rel, text=""):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def fixture(name, project):
    text = (FIX / name).read_text(encoding="utf-8")
    return text.replace("PROJECT", json.dumps(str(project).replace("\\", "/"))[1:-1])


def polyglot(root):
    write(root, "requirements.txt", "jinja2==2.11.2\n")
    write(root, "svc/go.mod", "module example.com/svc\n\ngo 1.22\n")
    write(root, "web/package.json", '{"name":"web"}')
    write(root, "web/package-lock.json", '{"lockfileVersion":3}')
    write(root, "api/pom.xml", "<project/>")
    write(root, "legacy/App.csproj", "<Project/>")
    write(root, "site/composer.json", "{}")
    return root


# ------------------------------------------------------------------ detection

def test_polyglot_detection_and_engine_list(tmp_path):
    polyglot(tmp_path)
    assert E.detect_languages(tmp_path) == {"python", "go", "node", "java", "dotnet", "php"}
    names = {e.name for e in E.relevant(tmp_path)}
    assert {"bandit", "pip-audit", "gosec", "govulncheck", "npm-audit", "eslint-security", "dependency-check",
            "spotbugs", "security-code-scan", "psalm", "osv-scanner", "semgrep", "trivy", "gitleaks"} <= names


def test_detection_ignores_dependency_folders_and_single_language_repos(tmp_path):
    write(tmp_path, "app/main.py", "print(1)\n")
    write(tmp_path, "node_modules/left-pad/package.json", "{}")
    write(tmp_path, "vendor/x/go.mod", "module x\n")
    write(tmp_path, ".venv/lib/pom.xml", "<project/>")
    assert E.detect_languages(tmp_path) == {"python"}
    names = {e.name for e in E.relevant(tmp_path)}
    assert "bandit" in names and not names & {"gosec", "govulncheck", "npm-audit", "eslint-security", "spotbugs", "psalm"}


def test_detection_does_not_follow_linked_folders(tmp_path):
    outside = tmp_path / "outside"
    write(outside, "go.mod", "module x\n")
    proj = tmp_path / "proj"
    write(proj, "a.py", "")
    try:
        os.symlink(outside, proj / "linked", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create a directory symlink here")
    assert "go" not in E.detect_languages(proj)


# ------------------------------------------------------------------ install plans and pins

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def test_every_automatic_plan_is_pinned_and_hashed():
    for e in E.ENGINES:
        p = e.pin()
        v = str(p.get("version", ""))
        assert "latest" not in v.lower(), e.name
        if p["kind"] == "download":
            for key, art in p["artifacts"].items():
                assert art["url"].startswith("https://github.com/"), (e.name, key)
                assert HEX64.match(art["sha256"]), (e.name, key)
                assert v.lstrip("v") in art["url"], (e.name, key)
        elif p["kind"] == "pip":
            assert re.match(r"^\d+\.\d+\.\d+$", v) and p["wheel_sha256"], e.name
            assert all(HEX64.match(h) for h in p["wheel_sha256"]), e.name
        elif p["kind"] == "go":
            assert re.match(r"^v\d+\.\d+\.\d+$", v) and p["h1"].startswith("h1:") and p["h1"].endswith("="), e.name
        elif p["kind"] == "npm":
            for n, pk in p["packages"].items():
                assert re.match(r"^\d+\.\d+\.\d+$", pk["version"]) and pk["integrity"].startswith("sha512-"), (e.name, n)
        else:
            assert p["kind"] in ("manual", "builtin") and p.get("manual"), e.name


def test_plan_shows_source_version_checksum_and_never_auto_installs_codeql_or_scs():
    plans = {e.name: e.install_plan() for e in E.ENGINES}
    osv = plans["osv-scanner"]
    if osv["auto"]:
        assert HEX64.match(osv["sha256"]) and osv["url"].startswith("https://") and osv["version"] == "2.7.0"
        assert any("SHA-256" in s for s in osv["steps"])
    for name in ("codeql", "security-code-scan", "psalm", "npm-audit"):
        assert plans[name]["auto"] is False, name
    assert "licence" in plans["codeql"]["note"].lower() and "commercial" in plans["codeql"]["note"]
    for name in ("bandit", "pip-audit"):
        assert plans[name]["auto"] and plans[name]["sha256"], name


def test_lock_matches_ci_installer_pins():
    # The laptop installer and the CI installer must agree on the Linux archives.
    ci = (ROOT / "scripts" / "install-ci-scanners.sh").read_text(encoding="utf-8")
    for name in ("trivy", "gitleaks"):
        art = E.BY_NAME[name].pin()["artifacts"]["linux-amd64"]
        assert art["sha256"] in ci and E.BY_NAME[name].pin()["version"] in ci, name


# ------------------------------------------------------------------ checksum refusal

class FakeEngine(_base.Engine):
    name, command = "fake-tool", "fake-tool"

    def __init__(self, pin):
        self._pin = pin

    def pin(self):
        return self._pin


def raw_pin(sha, exe="fake-tool.exe", archive="raw", member=None):
    art = {"url": "https://github.com/x/y/releases/download/v1.0.0/fake", "sha256": sha, "archive": archive, "exe": exe}
    if member:
        art["member"] = member
    return {"version": "1.0.0", "kind": "download", "licence": "MIT", "artifacts": {"any": art}}


def copier(src):
    def fetch(url, dest):
        Path(dest).write_bytes(Path(src).read_bytes())
    return fetch


def test_tampered_download_is_refused_and_nothing_is_installed(tmp_path):
    payload = write(tmp_path, "payload.bin", "pretend binary")
    eng = FakeEngine(raw_pin("0" * 64))
    with pytest.raises(_install.ChecksumMismatch) as ei:
        _install.install_download(eng, fetch=copier(payload), log=lambda *_: None)
    assert "mismatch" in str(ei.value).lower()
    assert not eng.install_dir().exists()
    assert not (eng.installed_path() and eng.installed_path().exists())


def test_matching_download_installs_into_the_tools_folder(tmp_path):
    payload = write(tmp_path, "payload.bin", "pretend binary")
    sha = hashlib.sha256(payload.read_bytes()).hexdigest()
    eng = FakeEngine(raw_pin(sha))
    path = _install.install_download(eng, fetch=copier(payload), log=lambda *_: None)
    assert path.is_file() and path.read_text() == "pretend binary"
    assert _base.inside(path, _base.tools_root())


def test_verify_sha256_deletes_the_bad_file_and_refuses_an_empty_pin(tmp_path):
    f = write(tmp_path, "x.whl", "data")
    with pytest.raises(_install.ChecksumMismatch):
        _install.verify_sha256(f, ["1" * 64])
    assert not f.exists()
    g = write(tmp_path, "y.whl", "data")
    with pytest.raises(_install.ChecksumMismatch):
        _install.verify_sha256(g, [])
    assert _install.verify_sha256(g, hashlib.sha256(b"data").hexdigest())


def test_archive_with_traversal_or_link_is_refused(tmp_path):
    bad_zip = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad_zip, "w") as z:
        z.writestr("../evil.exe", "x")
    with pytest.raises(_install.InstallError):
        _install.extract(bad_zip, "zip", "*", tmp_path / "out1")
    assert not (tmp_path / "evil.exe").exists()
    link_tar = tmp_path / "bad.tar.gz"
    with tarfile.open(link_tar, "w:gz") as t:
        ti = tarfile.TarInfo("trivy")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        t.addfile(ti)
    with pytest.raises(_install.InstallError):
        _install.extract(link_tar, "tar.gz", "trivy", tmp_path / "out2")
    ok_zip = tmp_path / "ok.zip"
    with zipfile.ZipFile(ok_zip, "w") as z:
        z.writestr("trivy.exe", "bin")
        z.writestr("README.md", "doc")
    _install.extract(ok_zip, "zip", "trivy.exe", tmp_path / "out3")
    assert (tmp_path / "out3" / "trivy.exe").read_text() == "bin" and not (tmp_path / "out3" / "README.md").exists()


def test_download_urls_must_be_https_on_github():
    for bad in ("http://github.com/a", "https://evil.example/a", "file:///etc/passwd", "https://github.com.evil.example/x"):
        with pytest.raises(_install.InstallError):
            _install.check_url(bad)
    assert _install.check_url("https://objects.githubusercontent.com/x")


def test_pip_route_refuses_a_wheel_with_the_wrong_hash(tmp_path):
    eng = E.BY_NAME["bandit"]

    def runner(argv, cwd, timeout, env=None):
        if "download" in argv:
            dest = Path(argv[argv.index("-d") + 1])
            (dest / "bandit-1.9.4-py3-none-any.whl").write_bytes(b"not the real wheel")
        return 0, "", ""
    with pytest.raises(_install.ChecksumMismatch):
        _install.install_pip(eng, runner=runner, log=lambda *_: None)
    assert not eng.install_dir().exists()


def test_go_and_npm_post_install_checks():
    info = "path\tgithub.com/securego/gosec/v2/cmd/gosec\nmod\tgithub.com/securego/gosec/v2\tv2.30.0\th1:abc=\n"
    assert _install.check_go_build_info(info, "github.com/securego/gosec/v2", "v2.30.0", "h1:abc=")
    assert not _install.check_go_build_info(info, "github.com/securego/gosec/v2", "v2.30.0", "h1:other=")
    assert not _install.check_go_build_info("mod\tgithub.com/evil/gosec\tv2.30.0\th1:abc=", "github.com/securego/gosec/v2", "v2.30.0", "h1:abc=")
    want = E.BY_NAME["retire"].pin()["packages"]
    good = {"packages": {"node_modules/retire": {"version": "6.1.0", "integrity": want["retire"]["integrity"]}}}
    bad = {"packages": {"node_modules/retire": {"version": "6.1.0", "integrity": "sha512-forged"}}}
    assert _install.check_npm_lock(json.dumps(good), want) == []
    assert _install.check_npm_lock(json.dumps(bad), want) == ["retire"]


def test_go_install_env_keeps_the_checksum_database_on(monkeypatch):
    monkeypatch.setenv("GONOSUMDB", "*")
    monkeypatch.setenv("GOFLAGS", "-insecure")
    monkeypatch.setenv("GOINSECURE", "*")
    env = _install.go_env("/tmp/bin")
    assert env["GOSUMDB"] == "sum.golang.org" and "GONOSUMDB" not in env and "GOFLAGS" not in env and "GOINSECURE" not in env


# ------------------------------------------------------------------ setup consent

def test_setup_without_yes_installs_nothing(tmp_path, monkeypatch, capsys):
    sc = load("scripts/securecode.py", "sc_v7a")
    write(tmp_path, "requirements.txt", "jinja2==2.11.2\n")
    called = []
    monkeypatch.setattr(_install, "install", lambda e, log=print: called.append(e.name))
    assert sc.main(["setup", str(tmp_path)]) == 0
    assert called == [] and "Nothing was installed" in capsys.readouterr().out
    assert sc.main(["setup", str(tmp_path), "--yes", "--engine", "bandit"]) == 0
    assert called == ["bandit"]


def test_setup_reports_a_refused_checksum(tmp_path, monkeypatch, capsys):
    sc = load("scripts/securecode.py", "sc_v7b")
    write(tmp_path, "requirements.txt", "x==1\n")

    def refuse(e, log=print):
        raise _install.ChecksumMismatch("SHA-256 mismatch")
    monkeypatch.setattr(_install, "install", refuse)
    assert sc.main(["setup", str(tmp_path), "--yes", "--engine", "bandit"]) == 1
    assert "REFUSED (checksum)" in capsys.readouterr().out


def test_doctor_lists_needed_engines(tmp_path, capsys):
    sc = load("scripts/securecode.py", "sc_v7c")
    polyglot(tmp_path)
    assert sc.main(["doctor", str(tmp_path), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    needed = {e["engine"] for e in data["engines"] if e["needed"]}
    assert {"gosec", "bandit", "npm-audit", "spotbugs"} <= needed and set(data["languages"]) >= {"go", "python"}


# ------------------------------------------------------------------ argv safety

def fake_ctx(mode="full", run_tests=True, calls=None):
    def find(name):
        return name if os.path.isabs(str(name)) else f"/fake/bin/{name}"

    def runner(argv, cwd, timeout, env=None):
        calls.append((argv, cwd, timeout, env)) if calls is not None else None
        return 0, "", ""
    return _base.Ctx(find, runner, mode, run_tests)


def runnable_project(tmp_path):
    polyglot(tmp_path)
    write(tmp_path, "package.json", '{"name":"root"}')
    write(tmp_path, "package-lock.json", '{"lockfileVersion":3}')
    write(tmp_path, "App.sln", "")
    (tmp_path / "api" / "target" / "classes").mkdir(parents=True)
    return tmp_path


def install_fakes():
    # Make every engine look installed without running anything.
    for e in E.RUNNABLE:
        p = e.installed_path()
        if p is not None:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("fake")
    E.BY_NAME["eslint-security"].plugin_dir().mkdir(parents=True, exist_ok=True)


@pytest.mark.parametrize("mode", ["full", "ci"])
def test_argv_is_a_list_with_a_timeout_and_no_shell(tmp_path, mode):
    proj = runnable_project(tmp_path / "p")
    install_fakes()
    out = tmp_path / "out"
    for e in E.RUNNABLE:
        if e.name == "codeql":
            continue
        d = out / e.name
        d.mkdir(parents=True)
        argv, cwd, timeout, env, report = e.argv(proj, d, fake_ctx(mode))
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv), e.name
        assert Path(argv[0]).name not in ("sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh"), e.name
        assert "-c" not in argv[:1] and isinstance(timeout, int) and 0 < timeout <= 3600, e.name


def test_ci_mode_ignores_repo_engine_settings(tmp_path):
    proj = runnable_project(tmp_path / "p")
    for f in (".bandit", "osv-scanner.toml", "eslint.config.js", "eslint-suppressions.json", ".npmrc"):
        write(proj, f, "hostile")
    install_fakes()
    out = tmp_path / "out"

    def args(name, mode):
        d = out / mode / name
        d.mkdir(parents=True, exist_ok=True)
        return E.BY_NAME[name].argv(proj, d, fake_ctx(mode))

    a = args("osv-scanner", "ci")[0]
    assert Path(a[a.index("--config") + 1]).resolve().is_relative_to(ROOT)
    assert "--config" not in args("osv-scanner", "full")[0]
    b = args("bandit", "ci")[0]
    assert "--ignore-nosec" in b and Path(b[b.index("--ini") + 1]).resolve().is_relative_to(ROOT)
    assert "--ignore-nosec" not in args("bandit", "full")[0]
    assert "-nosec" in args("gosec", "ci")[0] and "-nosec" not in args("gosec", "full")[0]
    es = args("eslint-security", "ci")[0]
    cfg = Path(es[es.index("-c") + 1])
    assert "--no-inline-config" in es and not cfg.resolve().is_relative_to(proj.resolve())
    supp = Path(es[es.index("--suppressions-location") + 1])
    assert supp.read_text() == "{}" and not supp.resolve().is_relative_to(proj.resolve())
    na, ncwd, *_ = args("npm-audit", "ci")
    assert "--registry" in na and Path(ncwd).resolve() != proj.resolve() and not (Path(ncwd) / ".npmrc").exists()
    na_full, ncwd_full, *_ = args("npm-audit", "full")
    assert Path(ncwd_full) == proj and "--registry" not in na_full
    go_env = args("govulncheck", "ci")[3]
    assert go_env["GOTOOLCHAIN"] == "local" and go_env["CGO_ENABLED"] == "0" and go_env["GOWORK"] == "off"
    dc = args("dependency-check", "ci")[0]
    assert "--disableYarnAudit" in dc and "--disablePnpmAudit" in dc and "--disableOssIndex" in dc


def test_dependency_check_key_is_not_on_the_command_line(tmp_path, monkeypatch):
    proj = runnable_project(tmp_path / "p")
    install_fakes()
    monkeypatch.setenv("NVD_API_KEY", "test-key-value-123")
    d = tmp_path / "out"
    d.mkdir()
    argv = E.BY_NAME["dependency-check"].argv(proj, d, fake_ctx())[0]
    assert not any("test-key-value-123" in a for a in argv)
    props = Path(argv[argv.index("--propertyfile") + 1])
    assert "test-key-value-123" in props.read_text()


def test_build_running_engines_need_run_tests(tmp_path):
    proj = runnable_project(tmp_path / "p")
    install_fakes()
    d = tmp_path / "o"
    d.mkdir()
    with pytest.raises(_base.NotRunnable):
        E.BY_NAME["security-code-scan"].argv(proj, d, fake_ctx(run_tests=False))


def test_codeql_is_opt_in(tmp_path, monkeypatch):
    proj = runnable_project(tmp_path / "p")
    monkeypatch.delenv("SECGATE_CODEQL", raising=False)
    calls = []
    ok, raw, msg = E.BY_NAME["codeql"].run(proj, tmp_path, fake_ctx(calls=calls))
    assert ok is None and "opt-in" in msg and calls == []


def test_execute_uses_no_shell_and_a_timeout(tmp_path, monkeypatch):
    seen = {}

    class R:
        returncode, stdout, stderr = 0, "ok", ""

    def fake_run(cmd, **kw):
        seen.update(kw, cmd=cmd)
        return R()
    monkeypatch.setattr(_base.subprocess, "run", fake_run)
    exe = write(tmp_path, "tool.exe", "")
    rc, out, _ = _base.execute([str(exe), "--version"], tmp_path, 42)
    assert rc == 0 and seen["shell"] is False and seen["timeout"] == 42 and isinstance(seen["cmd"], list)


def test_batch_files_with_cmd_metacharacters_are_refused(tmp_path, monkeypatch):
    bat = write(tmp_path, "tool.cmd", "@echo off")
    monkeypatch.setattr(_base.subprocess, "run", lambda *a, **k: pytest.fail("must not start"))
    rc, _, err = _base.execute([str(bat), "--path", "a&calc"], tmp_path, 10)
    assert rc == 126 and "refused" in err
    g = load("scripts/secgate.py", "sg_v7bat")
    monkeypatch.setattr(g.subprocess, "run", lambda *a, **k: pytest.fail("must not start"))
    rc, _, err = g.run([str(bat), "x|y"], tmp_path, 10)
    assert rc == 126


def test_engine_finder_refuses_tools_planted_in_the_project(tmp_path, monkeypatch):
    name = "osv-scanner.exe" if os.name == "nt" else "osv-scanner"
    p = write(tmp_path, name, "#!/bin/sh\n")
    p.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join([".", str(tmp_path)]))
    assert _base.find_tool("osv-scanner") is None


# ------------------------------------------------------------------ normalizers on recorded output

def norm(name, fname, project):
    return E.BY_NAME[name].normalize(fixture(fname, project), project)


def test_normalize_osv_scanner(tmp_path):
    f = norm("osv-scanner", "osv-scanner.json", tmp_path)
    by = {x["rule"]: x for x in f}
    assert by["GHSA-35jh-r3h4-6jhm"]["severity"] == "HIGH" and by["GHSA-xvch-5gv4-984h"]["severity"] == "CRITICAL"
    assert by["GHSA-35jh-r3h4-6jhm"]["file"] == "package-lock.json" and "CVE-2021-23337" in by["GHSA-35jh-r3h4-6jhm"]["aliases"]
    assert all(x["engine"] == "osv-scanner" for x in f)


def test_normalize_bandit(tmp_path):
    f = norm("bandit", "bandit.json", tmp_path)
    assert [(x["rule"], x["severity"], x["file"], x["line"]) for x in f] == [
        ("BANDIT_B506_yaml_load", "MEDIUM", "app/loader.py", 5),
        ("BANDIT_B602_subprocess_popen_with_shell_equals_true", "HIGH", "app/jobs.py", 12)]
    assert "CWE-78" in f[1]["message"]


def test_normalize_pip_audit(tmp_path):
    write(tmp_path, "requirements.txt", "jinja2==2.11.2\n")
    f = norm("pip-audit", "pip-audit.json", tmp_path)
    assert len(f) == 1 and f[0]["rule"] == "PYSEC-2021-66" and f[0]["severity"] == "MEDIUM"
    assert f[0]["file"] == "requirements.txt" and "2.11.3" in f[0]["message"] and "CVE-2020-28493" in f[0]["aliases"]


def test_normalize_gosec(tmp_path):
    f = norm("gosec", "gosec.json", tmp_path)
    assert [(x["rule"], x["severity"], x["file"], x["line"]) for x in f] == [
        ("GOSEC_G201", "HIGH", "db/query.go", 41), ("GOSEC_G304", "MEDIUM", "files.go", 18)]


def test_normalize_govulncheck_ranks_reachability(tmp_path):
    f = {x["rule"]: x for x in norm("govulncheck", "govulncheck.jsonl", tmp_path)}
    called, unreached = f["GO-2024-2687"], f["GO-2023-1840"]
    assert called["severity"] == "HIGH" and called["file"] == "main.go" and called["line"] == 14
    assert "calls the vulnerable function" in called["message"] and "CVE-2023-45288" in called["aliases"]
    assert unreached["severity"] == "LOW" and unreached["file"] == "go.mod"


def test_normalize_npm_audit(tmp_path):
    write(tmp_path, "package-lock.json", "{}")
    f = {x["rule"]: x for x in norm("npm-audit", "npm-audit.json", tmp_path)}
    assert set(f) == {"GHSA-35jh-r3h4-6jhm", "GHSA-xvch-5gv4-984h"}       # report-helper only depends on lodash
    assert f["GHSA-35jh-r3h4-6jhm"]["severity"] == "HIGH" and f["GHSA-xvch-5gv4-984h"]["severity"] == "CRITICAL"
    assert "mkdirp@1.0.4" in f["GHSA-xvch-5gv4-984h"]["message"]


def test_normalize_eslint_security(tmp_path):
    f = norm("eslint-security", "eslint.json", tmp_path)
    assert [(x["rule"], x["severity"], x["file"], x["line"]) for x in f] == [
        ("ESLINT_security/detect-eval-with-expression", "HIGH", "src/server.js", 12),
        ("ESLINT_security/detect-object-injection", "LOW", "src/server.js", 20)]


def test_normalize_dependency_check(tmp_path):
    f = {x["rule"]: x for x in norm("dependency-check", "dependency-check.json", tmp_path)}
    assert f["CVE-2021-44228"]["severity"] == "CRITICAL" and f["CVE-2021-44228"]["file"] == "lib/log4j-core-2.14.1.jar"
    assert f["CVE-2022-42889"]["severity"] == "CRITICAL"          # UNKNOWN falls back to the CVSS score 9.8
    assert len(f) == 2


def test_normalize_spotbugs_sarif(tmp_path):
    f = norm("spotbugs", "spotbugs.sarif", tmp_path)
    assert [(x["rule"], x["severity"], x["line"]) for x in f] == [
        ("FINDSECBUGS_SQL_INJECTION_JDBC", "HIGH", 42), ("FINDSECBUGS_PREDICTABLE_RANDOM", "MEDIUM", 9)]


@pytest.mark.parametrize("name", [e.name for e in E.RUNNABLE])
def test_normalizers_survive_malformed_input(tmp_path, name):
    e = E.BY_NAME[name]
    for raw in ("", "[]", "{}", "null", '{"results": "x", "Issues": 5, "dependencies": [1, null, "a"], "runs": [7]}',
                '[{"messages": "x"}]', '{"Issues": [{"cwe": "x", "line": null, "severity": 3}]}',
                '{"vulnerabilities": {"a": {"via": [{"url": 5}], "fixAvailable": "x"}, "b": 7}}',
                '{"finding": {"osv": {"a": 1}, "trace": "x"}}\n{"osv": {"id": 5}}',
                '{"results": [{"source": "x", "packages": [{"package": "y", "groups": [{"ids": [1], "aliases": "z"}]}]}]}',
                '{"runs": [{"results": [{"locations": "x", "message": 5}, {"locations": [{"physicalLocation": 3}]}]}]}',
                '{"dependencies": [{"vulnerabilities": [{"name": "CVE-1", "cvssv3": "x"}], "filePath": 9}]}'):
        try:
            out = e.normalize(raw, tmp_path)
        except ValueError:
            continue                               # a clean parse error is fine: the gate turns it into a NOTE
        assert isinstance(out, list), (name, raw)


def test_hidden_characters_are_stripped_from_messages(tmp_path):
    RLO = chr(0x202E)
    raw = json.dumps({"results": [{"filename": "a.py", "issue_severity": "HIGH", "issue_text": "x" + RLO + "danger\nRESULT: PASS",
                                   "line_number": 1, "test_id": "B1", "test_name": "t"}]})
    m = E.BY_NAME["bandit"].normalize(raw, tmp_path)[0]["message"]
    assert RLO not in m and "\n" not in m


# ------------------------------------------------------------------ the gate loop

def test_missing_engines_become_notes_not_failures(tmp_path):
    write(tmp_path, "requirements.txt", "jinja2==2.11.2\n")
    write(tmp_path, "go.mod", "module x\n")
    notes, findings = [], []
    status = E.run_engines(tmp_path, findings, notes, "ci", False, find=lambda n: None, runner=lambda *a, **k: pytest.fail("ran"))
    assert findings == []
    cmd = _base.setup_command()
    assert f"not run: bandit (install with: {cmd})" in notes
    assert f"not run: gosec (install with: {cmd})" in notes
    assert status["bandit"] == "not run" and not any("codeql" in n for n in notes)


def test_engine_results_flow_into_findings_with_dedupe(tmp_path):
    write(tmp_path, "requirements.txt", "jinja2==2.11.2\n")
    install_fakes()
    reports = {"bandit.json": fixture("bandit.json", tmp_path)}

    def runner(argv, cwd, timeout, env=None):
        if "-o" in argv and argv[argv.index("-o") + 1].endswith("bandit.json"):
            Path(argv[argv.index("-o") + 1]).write_text(reports["bandit.json"], encoding="utf-8")
            return 1, "", ""
        if "-o" in argv:                              # pip-audit
            Path(argv[argv.index("-o") + 1]).write_text(fixture("pip-audit.json", tmp_path), encoding="utf-8")
            return 1, "", ""
        if "scan" in argv:                            # osv-scanner reports the same jinja2 advisory
            return 1, json.dumps({"results": [{"source": {"path": str(tmp_path / "requirements.txt")}, "packages": [
                {"package": {"name": "jinja2", "version": "2.11.2", "ecosystem": "PyPI"},
                 "vulnerabilities": [{"id": "GHSA-g3rq-g295-4j3m", "summary": "ReDoS"}],
                 "groups": [{"ids": ["GHSA-g3rq-g295-4j3m"], "aliases": ["CVE-2020-28493", "PYSEC-2021-66"], "max_severity": "5.3"}]}]}]}), ""
        return 0, "", ""
    findings = [{"rule": "CVE-2020-28493", "severity": "MEDIUM", "file": "requirements.txt", "line": 0, "message": "", "engine": "trivy"}]
    notes = []
    E.run_engines(tmp_path, findings, notes, "full", False, find=lambda n: n if os.path.isabs(n) else None, runner=runner)
    engines = [f["engine"] for f in findings]
    assert engines.count("bandit") == 2
    assert "osv-scanner" not in engines and "pip-audit" not in engines, findings   # Trivy already had CVE-2020-28493
    assert any(n.startswith("bandit: completed") for n in notes)


def test_a_crashing_engine_is_a_note(tmp_path, monkeypatch):
    write(tmp_path, "requirements.txt", "x==1\n")
    install_fakes()

    def boom(*a, **k):
        raise RuntimeError("engine exploded")
    monkeypatch.setattr(E.BY_NAME["bandit"], "normalize", boom)
    notes, findings = [], []

    def runner(argv, cwd, timeout, env=None):
        if "-o" in argv:
            Path(argv[argv.index("-o") + 1]).write_text("{}", encoding="utf-8")
        return 0, "{}", ""
    E.run_engines(tmp_path, findings, notes, "ci", False, find=lambda n: n if os.path.isabs(n) else None, runner=runner)
    assert any(n.startswith("bandit: report could not be read") for n in notes)


def test_gate_prints_not_run_notes_and_still_passes(tmp_path, monkeypatch, capsys):
    g = load("scripts/secgate.py", "sg_v7gate")
    write(tmp_path, "requirements.txt", "jinja2==2.11.2\n")
    write(tmp_path, "app.py", "print('hello')\n")
    monkeypatch.setattr(g, "find_tool", lambda name: None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["secgate", ".", "--mode", "full", "--fail-on", "high"])
    rc = g.main()
    out = capsys.readouterr().out
    assert f"NOTE: not run: bandit (install with: {_base.setup_command()})" in out
    assert rc == 0 and "BLOCKED" not in out
    report = json.loads((tmp_path / ".security" / "findings.json").read_text(encoding="utf-8"))
    assert report["tool_status"]["engines"]["bandit"] == "not run"


def test_setup_command_is_the_full_installed_path_per_platform(monkeypatch, tmp_path):
    # V7GAP-D: a resolved path, because PowerShell does not expand %LOCALAPPDATA% and cmd does not expand $env:...
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\Some One\AppData\Local")
    assert _base.setup_command("Windows") == 'py -I "C:\\Users\\Some One\\AppData\\Local\\OrgAISecureAppSec\\scripts\\securecode.py" setup'
    assert _base.setup_command("Darwin").endswith('/Library/Application Support/OrgAISecureAppSec/scripts/securecode.py" setup')
    monkeypatch.setenv("XDG_DATA_HOME", "/home/u/.local/share")
    assert _base.setup_command("Linux") == 'python3 -I "/home/u/.local/share/OrgAISecureAppSec/scripts/securecode.py" setup'
    for system in ("Windows", "Darwin", "Linux"):
        cmd = _base.setup_command(system)
        assert "%" not in cmd and "$" not in cmd, cmd
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "install with securecode setup" not in readme


def test_gate_retire_ignores_repo_ignore_file_in_ci(tmp_path, monkeypatch):
    g = load("scripts/secgate.py", "sg_v7retire")
    write(tmp_path, ".retireignore", "**/*")
    calls = []

    def fake_run(cmd, cwd, timeout=600, env=None):
        calls.append([str(c) for c in cmd])
        if "--outputpath" in cmd:
            Path(cmd[cmd.index("--outputpath") + 1]).write_text('{"data": []}', encoding="utf-8")
        return 0, "", ""
    monkeypatch.setattr(g, "find_tool", lambda name: name if name == "retire" else None)
    monkeypatch.setattr(g, "run", fake_run)
    ok, _ = g.collect_retire(tmp_path, [], mode="ci")
    ign = calls[-1][calls[-1].index("--ignorefile") + 1]
    assert ok and Path(ign).resolve().is_relative_to(ROOT)
    g.collect_retire(tmp_path, [], mode="full")
    assert "--ignorefile" not in calls[-1]


# ------------------------------------------------------------------ real tools, only when installed

@pytest.mark.parametrize("name", ["bandit", "osv-scanner", "gosec"])
def test_real_engine_when_installed(tmp_path, name, monkeypatch):
    monkeypatch.delenv("NEXAFORGE_TOOLS_DIR", raising=False)
    e = E.BY_NAME[name]
    if not e.locate():
        pytest.skip(f"{name} is not installed")
    if name == "gosec" and not _base.find_tool("go"):
        pytest.skip("go is not installed")
    if name == "bandit":
        write(tmp_path, "app.py", "import yaml\n\ndef f(raw):\n    return yaml.load(raw)\n")
    elif name == "osv-scanner":
        write(tmp_path, "requirements.txt", "jinja2==2.11.2\n")
    else:
        write(tmp_path, "go.mod", "module example.com/x\n\ngo 1.21\n")
        write(tmp_path, "main.go", 'package main\n\nimport "os"\n\nfunc main() { _ = os.WriteFile("/tmp/x", nil, 0777) }\n')
    d = tmp_path.parent / (tmp_path.name + "-out")
    d.mkdir()
    ok, raw, msg = e.run(tmp_path, d, _base.Ctx(mode="ci"))
    assert ok, msg
    assert e.normalize(raw, tmp_path), raw[:500]


def test_setup_refuses_a_tools_folder_inside_the_project(tmp_path, monkeypatch, capsys):
    sc = load("scripts/securecode.py", "sc_v7d")
    write(tmp_path, "requirements.txt", "x==1\n")
    monkeypatch.setenv("NEXAFORGE_TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr(_install, "install", lambda e, log=print: pytest.fail("must not install"))
    assert sc.main(["setup", str(tmp_path), "--yes", "--engine", "bandit"]) == 2
    assert "inside the project" in capsys.readouterr().out


# ------------------------------------------------------------------ ZAP for local DAST (V7F-Z)

ZAP_PIN = E.BY_NAME["zap"].pin()


def test_zap_pin_is_the_official_crossplatform_zip():
    art = ZAP_PIN["artifacts"]["any"]
    assert ZAP_PIN["version"] == "2.17.0" and ZAP_PIN["licence"] == "Apache-2.0"
    assert art["url"] == "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip"
    assert art["sha256"] == "94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0" and art["size"] == 286652857
    assert E.BY_NAME["zap"] not in E.RUNNABLE                  # the gate never runs it; local_dast.py does
    plan = E.BY_NAME["zap"].install_plan()
    assert plan["auto"] and any("286,652,857 bytes" in s for s in plan["steps"])


def fake_zap_zip(tmp_path):
    z = tmp_path / "ZAP_2.17.0_Crossplatform.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("ZAP_2.17.0/zap-2.17.0.jar", "pretend jar")
        f.writestr("ZAP_2.17.0/zap.sh", "#!/bin/sh\n")
        f.writestr("ZAP_2.17.0/plugin/x.zap", "addon")
    return z


def zap_with_pin(monkeypatch, sha, size):
    eng = E.BY_NAME["zap"]
    pin = json.loads(json.dumps(ZAP_PIN))
    pin["artifacts"]["any"].update(sha256=sha, size=size)
    monkeypatch.setattr(eng, "pin", lambda: pin)
    return eng


def test_zap_installs_where_local_dast_finds_it(tmp_path, monkeypatch):
    z = fake_zap_zip(tmp_path)
    eng = zap_with_pin(monkeypatch, hashlib.sha256(z.read_bytes()).hexdigest(), z.stat().st_size)
    path = _install.install_download(eng, fetch=copier(z), log=lambda *_: None)
    assert path == _base.tools_root() / "zap" / "ZAP_2.17.0" / "zap-2.17.0.jar" and path.read_text() == "pretend jar"
    assert eng.locate() == str(path)
    sys.path.insert(0, str(ROOT / "scripts"))
    dast = load("scripts/local_dast.py", "local_dast_zap")
    assert _base.tools_root() / "zap" / "ZAP_2.17.0" in dast._zap_dirs()
    java = str(tmp_path / "java.exe")
    monkeypatch.setattr(dast, "find_tool", lambda n: java if n == "java" else None)     # no docker, a java on PATH
    kind, argv = dast.find_zap()
    assert kind == "local" and argv[0] == java and argv[-2:] == ["-jar", str(path)]


def test_zap_download_with_the_wrong_size_or_hash_is_refused(tmp_path, monkeypatch):
    z = fake_zap_zip(tmp_path)
    sha = hashlib.sha256(z.read_bytes()).hexdigest()
    eng = zap_with_pin(monkeypatch, sha, z.stat().st_size + 1)
    with pytest.raises(_install.ChecksumMismatch, match="size mismatch"):
        _install.install_download(eng, fetch=copier(z), log=lambda *_: None)
    eng = zap_with_pin(monkeypatch, "0" * 64, z.stat().st_size)
    with pytest.raises(_install.ChecksumMismatch):
        _install.install_download(eng, fetch=copier(z), log=lambda *_: None)
    assert not (_base.tools_root() / "zap").exists()


@pytest.mark.parametrize("text,major", [('openjdk version "17.0.9" 2023-10-17', 17), ('java version "1.8.0_392"', 8),
                                        ('openjdk version "21" 2023-09-19', 21), ('openjdk version "11.0.2"', 11),
                                        ("garbage", None), ("", None)])
def test_java_major_parsing(text, major):
    from nfsc_engines import zap
    assert zap.java_major(text) == major


def test_java_problem_reports_missing_or_old_java_and_never_installs_it():
    from nfsc_engines import zap
    calls = []

    def runner(argv, cwd, timeout):
        calls.append(argv)
        return 0, "", 'openjdk version "11.0.20" 2023-07-18'
    assert zap.java_problem(lambda n: None, runner) == "java 17+ (not on PATH)" and calls == []
    assert zap.java_problem(lambda n: "/usr/bin/java", runner) == "java 17+ (found 11)"
    assert calls == [["/usr/bin/java", "-version"]]                       # only asks the version, installs nothing
    ok = lambda argv, cwd, timeout: (0, "", 'openjdk version "17.0.9"')  # noqa: E731
    assert zap.java_problem(lambda n: "/usr/bin/java", ok) is None


def test_doctor_shows_zap_and_setup_names_the_java_requirement(tmp_path, monkeypatch, capsys):
    from nfsc_engines import zap
    sc = load("scripts/securecode.py", "sc_v7zap")
    monkeypatch.setattr(zap, "java_problem", lambda find=None, runner=None: "java 17+ (not on PATH)")
    write(tmp_path, "app.py", "print(1)\n")
    assert sc.main(["doctor", str(tmp_path), "--json"]) == 0
    row = next(e for e in json.loads(capsys.readouterr().out)["engines"] if e["engine"] == "zap")
    assert row["optional"] and not row["needed"] and row["missing_runtimes"] == ["java 17+ (not on PATH)"]
    called = []
    monkeypatch.setattr(_install, "install", lambda e, log=print: called.append(e.name))
    assert sc.main(["setup", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "[zap]" not in out                                    # never in the default plan
    assert sc.main(["setup", str(tmp_path), "--engine", "zap"]) == 0
    out = capsys.readouterr().out
    assert "[zap] version 2.17.0" in out and "never installs Java" in out and "Nothing was installed" in out
    assert called == []
