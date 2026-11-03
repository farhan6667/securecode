"""7.0 update mechanism: the schedule catches up missed runs on every OS, and the updater copes with rate limits,
network loss, partial downloads, overlapping runs, unsigned or older releases, and a 6.x to 7.x major update."""
import importlib.util, json, os, plistlib, shutil, subprocess, sys, time, types, urllib.error, zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KEYGEN = shutil.which("ssh-keygen")
needs_keygen = pytest.mark.skipif(not KEYGEN, reason="ssh-keygen not installed")
CFG = {"repo": "org/nexaforge-securecode", "asset": "Org_AI.zip", "signer_identity": "security@org"}
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


G = load(ROOT / "install-global.py", "inst_update_mech")


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    for k in ("LOCALAPPDATA", "XDG_DATA_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(k, str(tmp_path / "env" / k.lower()))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "envclaude"))
    monkeypatch.setattr(G, "HOME", tmp_path / "home")


def update_ready_app(tmp: Path, product="NexaForge SecureCode") -> Path:
    app = tmp / "app"
    (app / "config").mkdir(parents=True, exist_ok=True)
    (app / "config" / "update.json").write_text(json.dumps(CFG), encoding="utf-8")
    (app / "config" / "allowed_signers").write_text("security@org ssh-ed25519 AAAAtest\n", encoding="utf-8")
    (app / "config" / "brand.json").write_text(json.dumps({"product_name": product}), encoding="utf-8")
    return app


class Recorder:
    def __init__(self, rc=0, loaded=False):
        self.calls, self.rc, self.xml, self.loaded = [], rc, {}, loaded

    def __call__(self, args, **kw):
        self.calls.append(list(args))
        if "/XML" in args and "/Create" in args:
            self.xml[args[args.index("/TN") + 1]] = Path(args[args.index("/XML") + 1]).read_text(encoding="utf-16")
        if "/Query" in args or "print" in args:     # no task to query; launchd job loaded only when asked
            return types.SimpleNamespace(returncode=0 if (self.loaded and "print" in args) else 1, stdout="", stderr="")
        return types.SimpleNamespace(returncode=self.rc, stdout="", stderr="boom" if self.rc else "")


# ---------- Windows Task Scheduler definition ----------

def parsed(xml: str):
    return ET.fromstring(xml.split("?>", 1)[1])


def test_task_xml_catches_up_retries_and_needs_a_network():
    x = G.windows_task_xml("C:\\Py\\pythonw.exe", "C:\\App\\scripts\\updater.py", "PC\\dev", "NexaForge SecureCode")
    t = parsed(x)
    s = t.find("t:Settings", NS)
    assert s.find("t:StartWhenAvailable", NS).text == "true"                  # catch-up after a missed start
    assert s.find("t:RunOnlyIfNetworkAvailable", NS).text == "true"
    assert s.find("t:ExecutionTimeLimit", NS).text == "PT1H"
    assert s.find("t:MultipleInstancesPolicy", NS).text == "IgnoreNew"
    assert s.find("t:RestartOnFailure/t:Count", NS).text == "3"
    assert s.find("t:RestartOnFailure/t:Interval", NS).text == "PT30M"
    assert s.find("t:DisallowStartIfOnBatteries", NS).text == "false"
    cal = t.find("t:Triggers/t:CalendarTrigger", NS)
    assert cal.find("t:RandomDelay", NS).text == "PT30M" and cal.find("t:StartBoundary", NS).text.endswith("T11:00:00")
    logon = t.find("t:Triggers/t:LogonTrigger", NS)
    assert logon.find("t:UserId", NS).text == "PC\\dev" and logon.find("t:Delay", NS).text == "PT10M"
    p = t.find("t:Principals/t:Principal", NS)
    assert p.find("t:LogonType", NS).text == "InteractiveToken" and p.find("t:RunLevel", NS).text == "LeastPrivilege"
    ex = t.find("t:Actions/t:Exec", NS)
    assert ex.find("t:Command", NS).text == "C:\\Py\\pythonw.exe"
    assert ex.find("t:Arguments", NS).text == '-I "C:\\App\\scripts\\updater.py"'


def test_task_xml_escapes_hostile_paths_and_names():
    upd = "C:\\Users\\R&D <x>\\it's \"q\"\\]]>\\updater.py"
    t = parsed(G.windows_task_xml("C:\\P&y\\pythonw.exe", upd, "D<OM>\\a&b", "Acme & Co"))
    assert t.find("t:Actions/t:Exec/t:Arguments", NS).text == f'-I "{upd}"'
    assert t.find("t:Actions/t:Exec/t:Command", NS).text == "C:\\P&y\\pythonw.exe"
    assert t.find("t:Principals/t:Principal/t:UserId", NS).text == "D<OM>\\a&b"
    assert len(t.findall(".//t:Exec", NS)) == 1                                  # nothing injected a second action


@pytest.mark.parametrize("bad", ["C:\\a\nb\\updater.py", "C:\\a\x00\\updater.py", "C:\\a\u2028b", "x" * 1001])
def test_task_xml_refuses_control_characters_and_overlong_paths(bad):
    with pytest.raises(ValueError):
        G.windows_task_xml("C:\\py.exe", bad, "PC\\dev", "NexaForge SecureCode")


def test_without_a_user_name_there_is_no_logon_trigger():
    t = parsed(G.windows_task_xml("C:\\py.exe", "C:\\u.py", None, "NexaForge SecureCode"))
    assert t.find("t:Triggers/t:LogonTrigger", NS) is None and t.find("t:Triggers/t:CalendarTrigger", NS) is not None


def test_windows_registration_uses_the_xml_file_and_the_system_schtasks(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    app = update_ready_app(tmp_path)
    rec = Recorder()
    assert G.register_updates(app, run=rec) == "scheduled daily (Task Scheduler: NexaForge SecureCode Update)"
    create = [c for c in rec.calls if "/Create" in c][0]
    assert "/XML" in create and "/TR" not in create and "/F" in create
    if os.name == "nt":
        assert os.path.isabs(create[0]) and create[0].lower().endswith("schtasks.exe")
    assert "StartWhenAvailable>true" in rec.xml["NexaForge SecureCode Update"]
    assert not list(Path(os.environ.get("TEMP", tmp_path)).glob("nfsc-task-*"))  # the temp XML folder is removed


@pytest.mark.skipif(os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true",
                    reason="creates a real (disabled) scheduled task: only on a throwaway CI runner")
def test_task_scheduler_accepts_the_generated_xml(tmp_path):
    # FakeSchtasks only reads the file back; this asks the real Task Scheduler. The task is disabled and removed.
    upd = str(tmp_path / "R&D <x> it's" / "updater.py")
    xml = G.windows_task_xml(sys.executable, upd, G.windows_user(), "NFSC CI Check")
    xml = xml.replace("    <Enabled>true</Enabled>\n    <Hidden>", "    <Enabled>false</Enabled>\n    <Hidden>")
    f = tmp_path / "t.xml"; f.write_text(xml, encoding="utf-16")
    name, exe = "NFSC CI XML Check", G.schtasks_exe()
    try:
        p = subprocess.run([exe, "/Create", "/F", "/TN", name, "/XML", str(f)], capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
        text = G._xml_text(subprocess.run([exe, "/Query", "/TN", name, "/XML"], capture_output=True).stdout)
        for needle in ("<StartWhenAvailable>true", "<RunOnlyIfNetworkAvailable>true", "<Count>3</Count>", "<LogonTrigger>"):
            assert needle in text, needle
        assert upd.lower() in text.lower()
    finally:
        subprocess.run([exe, "/Delete", "/TN", name, "/F"], capture_output=True)


def test_windows_registration_failure_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    assert G.register_updates(update_ready_app(tmp_path), run=Recorder(rc=1)).startswith("schedule failed: boom")


# ---------- macOS and Linux ----------

def test_linux_without_the_flag_prints_cron_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "linux")
    app = update_ready_app(tmp_path)
    rec = Recorder()
    res = G.register_updates(app, run=rec)
    assert res.startswith("add to crontab: 0 11 * * * ") and "--update-timer" in res
    assert not rec.calls
    assert not list(tmp_path.rglob("*.timer")) and not list(tmp_path.rglob("*.service"))


def test_linux_timer_is_persistent_and_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "linux")
    monkeypatch.setattr(G, "_tool", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(G.sys, "executable", "/opt/py $HOME 3/bin/python%1")
    app = update_ready_app(tmp_path / "my apps", "Acme SecureCode")
    rec = Recorder()
    res = G.register_updates(app, run=rec, timer=True)
    assert res == "scheduled daily (systemd user timer acme-securecode-update.timer, Persistent=true)"
    base = Path(os.environ["XDG_CONFIG_HOME"]) / "systemd" / "user"
    timer = (base / "acme-securecode-update.timer").read_text(encoding="utf-8")
    service = (base / "acme-securecode-update.service").read_text(encoding="utf-8")
    assert "Persistent=true" in timer and "OnCalendar=*-*-* 11:00:00" in timer and "RandomizedDelaySec=30min" in timer
    assert "WantedBy=timers.target" in timer and "Type=oneshot" in service
    upd = str(app / "scripts" / "updater.py").replace("\\", "\\\\")
    assert f'ExecStart="/opt/py $$HOME 3/bin/python%%1" -I "{upd}"' in service
    assert rec.calls == [["/usr/bin/systemctl", "--user", "daemon-reload"],
                         ["/usr/bin/systemctl", "--user", "enable", "--now", "acme-securecode-update.timer"]]
    # An update re-runs the installer without the flag: the timer we wrote is refreshed, not dropped.
    rec2 = Recorder()
    assert G.register_updates(app, run=rec2).startswith("scheduled daily (systemd user timer")
    assert rec2.calls


def test_linux_timer_reports_a_missing_or_failing_systemctl(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "linux")
    app = update_ready_app(tmp_path)
    monkeypatch.setattr(G, "_tool", lambda n: None)
    assert "systemctl was not found; add to crontab" in G.register_updates(app, run=Recorder(), timer=True)
    monkeypatch.setattr(G, "_tool", lambda n: "/usr/bin/" + n)
    assert "failed: boom; add to crontab" in G.register_updates(app, run=Recorder(rc=1), timer=True)


def test_macos_launch_agent_runs_at_load_and_daily(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "darwin")
    monkeypatch.setattr(G, "_tool", lambda n: "/bin/" + n)
    monkeypatch.setattr(G.os, "getuid", lambda: 501, raising=False)
    app = update_ready_app(tmp_path / "Application Support")
    rec = Recorder()
    res = G.register_updates(app, run=rec, timer=True)
    assert res.startswith("scheduled daily (launchd agent eu.nexaforge.nexaforge-securecode.update")
    plist = tmp_path / "home" / "Library" / "LaunchAgents" / "eu.nexaforge.nexaforge-securecode.update.plist"
    d = plistlib.loads(plist.read_bytes())
    assert d["RunAtLoad"] is True and d["StartCalendarInterval"] == {"Hour": 11, "Minute": 0}
    assert d["ProgramArguments"] == [sys.executable, "-I", str(app / "scripts" / "updater.py")]
    assert rec.calls[-1] == ["/bin/launchctl", "bootstrap", "gui/501", str(plist)]
    assert not any("bootout" in c for c in rec.calls)


def test_macos_update_never_boots_out_the_running_agent(tmp_path, monkeypatch):
    # Review finding: the updater runs as a child of the launchd job; a bootout from the installer it starts would
    # kill the update half way. A loaded agent is left alone.
    monkeypatch.setattr(G, "SYSTEM", "darwin")
    monkeypatch.setattr(G, "_tool", lambda n: "/bin/" + n)
    monkeypatch.setattr(G.os, "getuid", lambda: 501, raising=False)
    app = update_ready_app(tmp_path)
    rec = Recorder(loaded=True)
    assert "already loaded" in G.register_updates(app, run=rec, timer=True)
    assert [c[1] for c in rec.calls] == ["print"]


def test_unit_names_come_only_from_safe_brand_characters(tmp_path):
    app = update_ready_app(tmp_path, "Acme (Pilot) 2")
    assert G.unit_slug(app) == "acme-pilot-2"
    (app / "config" / "brand.json").write_text(json.dumps({"product_name": "\u0633\u06cc\u06a9\u06cc\u0648\u0631"}), encoding="utf-8")
    assert G.unit_slug(app) == "nexaforge-securecode"


def test_a_linked_unit_file_is_not_written_through(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "linux")
    monkeypatch.setattr(G, "_tool", lambda n: "/usr/bin/" + n)
    app = update_ready_app(tmp_path)
    base = Path(os.environ["XDG_CONFIG_HOME"]) / "systemd" / "user"
    base.mkdir(parents=True)
    target = tmp_path / "victim.txt"; target.write_text("keep", encoding="utf-8")
    try:
        (base / "nexaforge-securecode-update.timer").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    assert "is a link" in G.register_updates(app, run=Recorder(), timer=True)
    assert target.read_text(encoding="utf-8") == "keep"


# ---------- the updater ----------

def make_app(tmp: Path, installed="6.2.0", updater=ROOT / "scripts" / "updater.py", product="Acme SecureCode"):
    app = tmp / "app"
    (app / "scripts").mkdir(parents=True)
    (app / "config").mkdir()
    (app / "docs").mkdir()
    shutil.copy2(updater, app / "scripts" / "updater.py")
    (app / "install-report.json").write_text(json.dumps({"version": installed}), encoding="utf-8")
    (app / "config" / "update.json").write_text(json.dumps(CFG), encoding="utf-8")
    (app / "config" / "brand.json").write_text(json.dumps({"product_name": product}), encoding="utf-8")
    (app / "docs" / "ORG-FINDINGS.md").write_text("# Our own pentest findings\n", encoding="utf-8")
    return app


def http_error(code, headers):
    return urllib.error.HTTPError("https://api.github.com/repos/x/y/releases/latest", code, "Forbidden", headers, None)


def run_main(app, monkeypatch, capsys, name, raise_with=None, status=None):
    upd = load(app / "scripts" / "updater.py", name)
    monkeypatch.setattr(upd, "token", lambda: None)
    calls = []

    def fake_api(url, tok, accept="x"):
        calls.append(url)
        if raise_with is not None:
            raise raise_with
        raise AssertionError("unexpected")
    monkeypatch.setattr(upd, "api", fake_api)
    if status is not None:
        monkeypatch.setattr(upd, "check_and_update", lambda cfg, tok, **kw: calls.append("check") or status)
    rc = upd.main()
    return upd, rc, capsys.readouterr().out.strip(), calls


def test_rate_limit_backs_off_logs_and_exits_cleanly(tmp_path, monkeypatch, capsys):
    app = make_app(tmp_path)
    reset = int(time.time()) + 1800
    e = http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)})
    upd, rc, out, calls = run_main(app, monkeypatch, capsys, "upd_rl", raise_with=e)
    assert rc == 0 and "GitHub rate limit reached" in out and len(calls) == 1
    st = json.loads((app / "update-state.json").read_text(encoding="utf-8"))
    assert st["result"] == "rate-limited" and st["backoff_until"] == reset and st["last_check"].endswith("Z")
    assert "update check deferred: GitHub rate limit" in (app / "update.log").read_text(encoding="utf-8")
    # The next run inside the back-off does not ask GitHub at all.
    upd2, rc2, out2, calls2 = run_main(app, monkeypatch, capsys, "upd_rl2", raise_with=AssertionError("must not call"))
    assert rc2 == 0 and "back-off" in out2 and calls2 == []
    assert not (app / "update.lock").exists()


def test_429_retry_after_and_absurd_reset_times_are_bounded():
    upd = load(ROOT / "scripts" / "updater.py", "upd_rl_unit")
    now = 1_000_000.0
    assert upd.rate_limit_until(http_error(429, {"Retry-After": "120"}), now) == now + 120
    assert upd.rate_limit_until(http_error(429, {}), now) == now + 3600
    far = upd.rate_limit_until(http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "99999999999"}), now)
    assert far == now + upd.MAX_BACKOFF
    assert upd.rate_limit_until(http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "5"}), now) == now + 60
    assert upd.rate_limit_until(http_error(403, {}), now) is None            # a plain 403 is an error, not a back-off
    assert upd.rate_limit_until(http_error(404, {"Retry-After": "5"}), now) is None


def test_a_stored_backoff_far_in_the_future_is_not_trusted(tmp_path, monkeypatch, capsys):
    app = make_app(tmp_path)
    (app / "update-state.json").write_text(json.dumps({"backoff_until": time.time() + 30 * 86400}), encoding="utf-8")
    upd, rc, out, calls = run_main(app, monkeypatch, capsys, "upd_rl_far", status="up-to-date")
    assert calls == ["check"] and rc == 0


def test_plain_403_is_a_failure_not_a_backoff(tmp_path, monkeypatch, capsys):
    app = make_app(tmp_path)
    upd, rc, out, calls = run_main(app, monkeypatch, capsys, "upd_403", raise_with=http_error(403, {}))
    assert rc == 1 and out == "Acme SecureCode: GitHub answered HTTP 403, nothing installed"
    st = json.loads((app / "update-state.json").read_text(encoding="utf-8"))
    assert st["ok"] is False and "backoff_until" not in st


def test_network_down_is_logged_and_recorded(tmp_path, monkeypatch, capsys):
    app = make_app(tmp_path)
    upd, rc, out, calls = run_main(app, monkeypatch, capsys, "upd_net", raise_with=urllib.error.URLError("getaddrinfo failed"))
    assert rc == 1 and out == "Acme SecureCode: no network or GitHub unreachable"
    st = json.loads((app / "update-state.json").read_text(encoding="utf-8"))
    assert st["result"] == "no network or GitHub unreachable" and st["ok"] is False
    assert "URLError" in (app / "update.log").read_text(encoding="utf-8")


def test_overlapping_runs_take_turns_through_the_lock(tmp_path, monkeypatch, capsys):
    app = make_app(tmp_path)
    (app / "update.lock").write_text("", encoding="utf-8")                      # a run in progress
    upd, rc, out, calls = run_main(app, monkeypatch, capsys, "upd_lock", status="up-to-date")
    assert rc == 0 and calls == [] and out.endswith("another update check is running, try again later")
    assert (app / "update.lock").exists()                                      # the other run's lock is left alone
    old = time.time() - 7200                                                   # a lock left by a crashed run
    os.utime(app / "update.lock", (old, old))
    upd, rc, out, calls = run_main(app, monkeypatch, capsys, "upd_lock2", status="up-to-date")
    assert rc == 0 and calls == ["check"] and not (app / "update.lock").exists()


def test_incomplete_downloads_are_refused_before_the_signature_check(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    upd = load(app / "scripts" / "updater.py", "upd_partial")
    monkeypatch.setattr(upd, "verify_signature", lambda *a: pytest.fail("a partial file must not reach the signature check"))

    def fetch(kind, url, dest):
        if kind == "release":
            return {"tag_name": "v7.0.0", "assets": [{"name": "Org_AI.zip", "url": "zip", "size": 5000},
                                                     {"name": "Org_AI.zip.sig", "url": "sig", "size": 3}]}
        Path(dest).write_bytes(b"x" * (1000 if url == "zip" else 3))           # connection dropped after 1000 bytes
    assert upd.check_and_update(CFG, None, fetch=fetch, workdir=tmp_path / "w") == "download-incomplete"

    def fetch2(kind, url, dest):
        if kind == "release":
            return {"tag_name": "v7.0.0", "assets": [{"name": "Org_AI.zip", "url": "zip"}, {"name": "Org_AI.zip.sig", "url": "sig"}]}
        raise upd.IncompleteDownload("got 10 of 20 bytes")
    assert upd.check_and_update(CFG, None, fetch=fetch2, workdir=tmp_path / "w2") == "download-incomplete"
    assert upd.result_line("download-incomplete").startswith("download was incomplete")
    assert upd.size_matches(tmp_path, True) and upd.size_matches(tmp_path, None)   # odd sizes are left to the signature


def test_download_compares_content_length(tmp_path, monkeypatch):
    upd = load(ROOT / "scripts" / "updater.py", "upd_cl")

    class Resp:
        status, headers = 200, {"Content-Length": "100"}
        def __init__(self): self.left = [b"y" * 40]
        def read(self, n): return self.left.pop() if self.left else b""
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class Opener:
        def open(self, req, timeout=60): return Resp()
    monkeypatch.setattr(upd.urllib.request, "build_opener", lambda *a: Opener())
    with pytest.raises(upd.IncompleteDownload):
        upd.download("https://api.github.com/repos/o/r/releases/assets/1", None, tmp_path / "a.zip")


def test_unsigned_or_older_releases_install_nothing(tmp_path):
    app = make_app(tmp_path, installed="7.0.0")
    upd = load(app / "scripts" / "updater.py", "upd_refuse")

    def fetch(tag, sig=True):
        assets = [{"name": "Org_AI.zip", "url": "zip"}] + ([{"name": "Org_AI.zip.sig", "url": "sig"}] if sig else [])
        return lambda kind, url, dest: {"tag_name": tag, "assets": assets} if kind == "release" else pytest.fail("no download")
    assert upd.check_and_update(CFG, None, fetch=fetch("v7.0.1", sig=False)) == "release-missing-signed-asset"
    assert upd.check_and_update(CFG, None, fetch=fetch("v6.2.2")) == "up-to-date"         # downgrade refused
    assert upd.check_and_update(CFG, None, fetch=fetch("v7.0.0")) == "up-to-date"
    assert upd.check_and_update(CFG, None, fetch=fetch("v7.0.0-rc1")) == "bad-release-tag"


# ---------- 6.2.2 installs accept a 7.0.0 release signed with the same key ----------

def release_7(tmp: Path, app: Path, key: Path):
    """A 7.0.0 release zip with the real package files. Its installer is a stub that declares the real VERSION and
    runs the real install_runtime into the temp app (the real main() would touch ~/.claude and Task Scheduler)."""
    real_ver = G.VERSION
    stub = (f'VERSION="{real_ver}"\nimport importlib.util, sys\nfrom pathlib import Path\n'
            'here=Path(__file__).resolve().parent\n'
            'spec=importlib.util.spec_from_file_location("realinst", here/"install-global.real.py")\n'
            'g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)\n'
            f'g.install_runtime(here, Path(r"{app}"))\n'
            f'Path(r"{app}", "install-report.json").write_text(\'{{"version": "{real_ver}"}}\')\n')
    z = tmp / "Org_AI.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("aisec/install-global.py", stub)
        zf.writestr("aisec/install-global.real.py", (ROOT / "install-global.py").read_text(encoding="utf-8"))
        for folder in ("scripts", "config", "docs"):
            for f in (ROOT / folder).rglob("*"):
                if f.is_file() and "__pycache__" not in f.parts:
                    zf.write(f, "aisec/" + f.relative_to(ROOT).as_posix())
        zf.write(ROOT / "AGENTS.md", "aisec/AGENTS.md")
    subprocess.run([KEYGEN, "-Y", "sign", "-f", str(key), "-n", "org-appsec-update", str(z)], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    sig = Path(str(z) + ".sig")

    def fetch(kind, url, dest):
        if kind == "release":
            return {"tag_name": f"v{real_ver}", "assets": [{"name": "Org_AI.zip", "url": "zip", "size": z.stat().st_size},
                                                        {"name": "Org_AI.zip.sig", "url": "sig", "size": sig.stat().st_size}]}
        shutil.copy2(z if url == "zip" else sig, dest)
    return fetch


@needs_keygen
@pytest.mark.parametrize("updater", ["tests/fixtures/updater-6.2.2.py", "scripts/updater.py"])
def test_a_6_2_2_install_accepts_the_7_0_0_release_signed_with_the_same_key(tmp_path, updater):
    assert G.VERSION.split(".")[0] == "7", "this test is about the 6.x to 7.x major update"
    app = make_app(tmp_path, installed="6.2.2", updater=ROOT / updater)
    key = tmp_path / "release_key"
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "t", "-f", str(key)], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    (app / "config" / "allowed_signers").write_text("security@org " + (tmp_path / "release_key.pub").read_text(), encoding="utf-8")
    upd = load(app / "scripts" / "updater.py", "upd_major_" + Path(updater).stem.replace(".", "_").replace("-", "_"))
    assert upd.check_and_update(CFG, None, fetch=release_7(tmp_path, app, key), workdir=tmp_path / "w") == "updated"
    assert json.loads((app / "install-report.json").read_text(encoding="utf-8"))["version"] == G.VERSION
    assert (app / "scripts" / "updater.py").read_bytes() == (ROOT / "scripts" / "updater.py").read_bytes()
    assert (app / "scripts" / "safe_git.py").is_file() and (app / "scripts" / "engines" / "__init__.py").is_file()
    assert json.loads((app / "config" / "brand.json").read_text(encoding="utf-8")) == {"product_name": "Acme SecureCode"}
    assert (app / "docs" / "ORG-FINDINGS.md").read_text(encoding="utf-8") == "# Our own pentest findings\n"
    # And the same release is not installed twice.
    upd2 = load(app / "scripts" / "updater.py", "upd_major_again_" + Path(updater).stem.replace(".", "_").replace("-", "_"))
    again = tmp_path / "again"; again.mkdir()
    assert upd2.check_and_update(CFG, None, fetch=release_7(again, app, key)) == "up-to-date"


@needs_keygen
def test_a_7_0_0_release_signed_by_another_key_is_refused_by_a_6_2_2_install(tmp_path):
    app = make_app(tmp_path, installed="6.2.2", updater=ROOT / "tests" / "fixtures" / "updater-6.2.2.py")
    good, evil = tmp_path / "good", tmp_path / "evil"
    for k in (good, evil):
        subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "t", "-f", str(k)], check=True,
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    (app / "config" / "allowed_signers").write_text("security@org " + (tmp_path / "good.pub").read_text(), encoding="utf-8")
    upd = load(app / "scripts" / "updater.py", "upd_major_evil")
    assert upd.check_and_update(CFG, None, fetch=release_7(tmp_path, app, evil), workdir=tmp_path / "w") == "SIGNATURE-INVALID"
    assert json.loads((app / "install-report.json").read_text(encoding="utf-8"))["version"] == "6.2.2"


def test_verify_global_reports_the_last_update_check(tmp_path):
    local = tmp_path / "local"
    app = local / "OrgAISecureAppSec"
    app.mkdir(parents=True)
    (app / "update-state.json").write_text(json.dumps({"last_check": "2026-11-03T10:00:00Z", "result": "up-to-date", "ok": True}),
                                           encoding="utf-8")
    env = dict(os.environ, PATH="", LOCALAPPDATA=str(local), XDG_DATA_HOME=str(local), XDG_CONFIG_HOME=str(tmp_path / "cfg"),
               CLAUDE_CONFIG_DIR=str(tmp_path / "claude"), HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    v = subprocess.run([sys.executable, "-I", str(ROOT / "verify-global.py")], env=env,
                       capture_output=True, text=True, timeout=120, encoding="utf-8")
    out = json.loads(v.stdout[:v.stdout.rindex("}") + 1])
    assert out["updates"]["last_check"] == "2026-11-03T10:00:00Z" and out["updates"]["result"] == "up-to-date"
    assert "next_run" in out["updates"] and out["updates"]["scheduler"]
