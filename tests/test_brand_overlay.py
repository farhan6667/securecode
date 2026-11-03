"""Brand overlay: an organization ships the package under its own name (config/brand.json) and keeps
auto-updating from NexaForge signed releases without the name, the task or its own files changing."""
import importlib.util, json, os, shutil, subprocess, sys, tempfile, types, urllib.error, zipfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
KEYGEN = shutil.which("ssh-keygen")
needs_keygen = pytest.mark.skipif(not KEYGEN, reason="ssh-keygen not installed")
CFG = {"repo": "org/nexaforge-securecode", "asset": "Org_AI.zip", "signer_identity": "security@org"}


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


G = load(ROOT / "install-global.py", "inst_brand_test")


def brand(app: Path, name):
    f = app / "config" / "brand.json"; f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"product_name": name}), encoding="utf-8")


def org_package(tmp: Path, product="Acme SecureCode") -> Path:
    """The organization's internal copy of the package: the real files plus its own brand.json."""
    pkg = tmp / "org_pkg"
    for folder in ("scripts", "config", "docs"):
        shutil.copytree(ROOT / folder, pkg / folder, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(ROOT / "AGENTS.md", pkg / "AGENTS.md")
    brand(pkg, product)
    return pkg


def install_app(tmp: Path, product="Acme SecureCode"):
    app = tmp / "local" / "OrgAISecureAppSec"
    G.install_runtime(org_package(tmp, product), app)
    (app / "install-report.json").write_text(json.dumps({"version": "6.2.0"}), encoding="utf-8")
    (app / "docs" / "ORG-FINDINGS.md").write_text("# Our own pentest findings\n", encoding="utf-8")
    return app


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    # Nothing in these tests may reach the real %LOCALAPPDATA% or ~/.claude.
    for k in ("LOCALAPPDATA", "XDG_DATA_HOME"):
        monkeypatch.setenv(k, str(tmp_path / "envlocal"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "envclaude"))


# ---------- name validation and fallback ----------

GOOD = ["NexaForge SecureCode", "Acme SecureCode", "Acme-Sec 2.0", "Team_X (Pilot) 2", "سیکیور کوڈ", "A"]
BAD = ["", " Acme", "Acme ", "Acme  SecureCode", 'Acme "Secure"', "Acme'S", "Acme/Sec", "Acme\\Sec", "Acme:Sec", "Acme*", "Acme?",
       "Acme<Sec>", "Acme|Sec", "Acme\nSec", "Acme\x00", "Acme\u202eceS", "Acme\u200bSec", "-Acme", "Acme&Sec", "Acme;Sec",
       "Acme$Sec", "Acme%Sec%", "x" * 61, 42, None, ["Acme"]]


@pytest.mark.parametrize("name", GOOD)
def test_valid_names_are_accepted_by_installer_and_updater(name):
    upd = load(ROOT / "scripts" / "updater.py", "upd_brand_valid")
    assert G.valid_product_name(name) and upd.valid_product_name(name)


@pytest.mark.parametrize("name", BAD)
def test_invalid_names_are_refused_by_installer_and_updater(name):
    upd = load(ROOT / "scripts" / "updater.py", "upd_brand_invalid")
    assert not G.valid_product_name(name) and not upd.valid_product_name(name)


def test_invalid_or_missing_brand_falls_back_to_default(tmp_path):
    app = tmp_path / "app"
    assert G.read_product_name(app) == "NexaForge SecureCode"                      # missing
    assert G.update_task_name(app) == "NexaForge SecureCode Update"
    f = app / "config" / "brand.json"
    for bad in ('{"product_name": "Acme/Sec"}', "not json", '["Acme SecureCode"]', '{"product_name": 7}', "{}",
                json.dumps({"product_name": "Acme SecureCode", "pad": "x" * 5000})):
        f.parent.mkdir(parents=True, exist_ok=True); f.write_text(bad, encoding="utf-8")
        assert G.read_product_name(app) == "NexaForge SecureCode", bad
        assert G.update_task_name(app) == "NexaForge SecureCode Update", bad
    f.write_text('\ufeff{"product_name": "Acme SecureCode"}', encoding="utf-8")       # Notepad BOM is fine
    assert G.update_task_name(app) == "Acme SecureCode Update"


def test_package_default_brand_is_nexaforge():
    assert json.loads((ROOT / "config" / "brand.json").read_text(encoding="utf-8")) == {"product_name": "NexaForge SecureCode"}


# ---------- installer copy rules ----------

def test_fresh_install_copies_default_and_reinstall_keeps_org_files(tmp_path):
    app = tmp_path / "app"
    G.install_runtime(ROOT, app)
    assert G.read_product_name(app) == "NexaForge SecureCode"
    brand(app, "Acme SecureCode")
    (app / "docs" / "ORG-FINDINGS.md").write_text("ours", encoding="utf-8")
    (app / "config" / "local-only.txt").write_text("keep", encoding="utf-8")
    G.install_runtime(ROOT, app)                                                    # re-install over it
    assert G.update_task_name(app) == "Acme SecureCode Update"
    assert (app / "docs" / "ORG-FINDINGS.md").read_text(encoding="utf-8") == "ours"
    assert (app / "config" / "local-only.txt").read_text(encoding="utf-8") == "keep"
    assert (app / "scripts" / "updater.py").read_bytes() == (ROOT / "scripts" / "updater.py").read_bytes()
    assert (app / "backups").is_dir()        # backups go to the given app folder, not the real one


def test_managed_install_keeps_brand_and_reports_it(tmp_path):
    root = tmp_path / "pf"
    brand(root / "OrgAISecureAppSec", "Acme SecureCode")
    for _ in range(2):
        p = subprocess.run([sys.executable, "-I", str(ROOT / "install-managed.py"), "--root", str(root)],
                           capture_output=True, text=True, timeout=120, encoding="utf-8")
        assert p.returncode == 0, p.stdout + p.stderr
        assert json.loads(p.stdout)["product_name"] == "Acme SecureCode"
    assert G.read_product_name(root / "OrgAISecureAppSec") == "Acme SecureCode"


# ---------- scheduled task name ----------

class FakeSchtasks:
    def __init__(self, existing=None):
        self.tasks = dict(existing or {})   # name -> XML text
        self.calls = []

    def __call__(self, args, **kw):
        self.calls.append(args)
        op, name = args[1], args[args.index("/TN") + 1]
        rc, out = 0, ""
        if op == "/Create":
            tr = args[args.index("/TR") + 1]
            self.tasks[name] = f"<Task><Actions><Exec><Arguments>{tr.replace(chr(34), '&quot;')}</Arguments></Exec></Actions></Task>"
        elif op == "/Query":
            rc, out = (0, self.tasks[name]) if name in self.tasks else (1, "")
        elif op == "/Delete":
            rc = 0 if self.tasks.pop(name, None) is not None else 1
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")


def update_ready_app(tmp: Path, product):
    app = tmp / "app"
    (app / "config").mkdir(parents=True, exist_ok=True)
    (app / "config" / "update.json").write_text(json.dumps(CFG), encoding="utf-8")
    (app / "config" / "allowed_signers").write_text("security@org ssh-ed25519 AAAAtest\n", encoding="utf-8")
    brand(app, product)
    return app


def test_task_name_follows_brand_and_reinstall_never_adds_a_second_task(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    app = update_ready_app(tmp_path, "Acme SecureCode")
    upd = str(app / "scripts" / "updater.py")
    other = "<Task><Exec><Arguments>-I &quot;C:\\elsewhere\\updater.py&quot;</Arguments></Exec></Task>"
    sch = FakeSchtasks({"Unrelated Task": other})
    assert G.register_updates(app, run=sch) == "scheduled daily (Task Scheduler: Acme SecureCode Update)"
    assert G.register_updates(app, run=sch).startswith("scheduled daily")         # re-run: same name, /F
    assert sorted(sch.tasks) == ["Acme SecureCode Update", "Unrelated Task"]
    assert json.loads((app / "update-task.json").read_text(encoding="utf-8"))["task_name"] == "Acme SecureCode Update"
    # The org renames its product: the old task (recorded, and running our updater) is replaced.
    brand(app, "Acme Guard")
    res = G.register_updates(app, run=sch)
    assert "removed old task Acme SecureCode Update" in res
    assert sorted(sch.tasks) == ["Acme Guard Update", "Unrelated Task"]
    assert upd.lower() in sch.tasks["Acme Guard Update"].replace("&quot;", '"').lower()


def test_legacy_task_is_removed_only_when_it_runs_our_updater(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    app = update_ready_app(tmp_path, "Acme SecureCode")
    upd = str(app / "scripts" / "updater.py")
    ours = f"<Task><Exec><Arguments>-I &quot;{upd}&quot;</Arguments></Exec></Task>"
    sch = FakeSchtasks({"NexaForge SecureCode Update": ours})
    assert "removed old task NexaForge SecureCode Update" in G.register_updates(app, run=sch)
    assert sorted(sch.tasks) == ["Acme SecureCode Update"]
    # Someone else's task under the legacy name (another app folder) is left alone.
    app2 = update_ready_app(tmp_path / "second", "Acme SecureCode")
    foreign = FakeSchtasks({"NexaForge SecureCode Update": "<Task><Arguments>C:\\other\\updater.py</Arguments></Task>"})
    G.register_updates(app2, run=foreign)
    assert sorted(foreign.tasks) == ["Acme SecureCode Update", "NexaForge SecureCode Update"]
    assert not any(c[1] == "/Delete" for c in foreign.calls)


def test_invalid_brand_gives_default_task_name(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "SYSTEM", "windows")
    app = update_ready_app(tmp_path, 'Evil" /TR calc')
    sch = FakeSchtasks()
    G.register_updates(app, run=sch)
    assert list(sch.tasks) == ["NexaForge SecureCode Update"]


def test_installer_banner_and_report_use_brand(tmp_path):
    local = tmp_path / "local"
    brand(local / "OrgAISecureAppSec", "Acme SecureCode")
    env = dict(os.environ, PATH="", LOCALAPPDATA=str(local), XDG_DATA_HOME=str(local),
               CLAUDE_CONFIG_DIR=str(tmp_path / "claude"), HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    p = subprocess.run([sys.executable, "-I", str(ROOT / "install-global.py"), "--verify-only"], env=env,
                       capture_output=True, text=True, timeout=120, encoding="utf-8")
    assert p.stdout.splitlines()[0] == "Acme SecureCode V" + G.VERSION
    assert json.loads((local / "OrgAISecureAppSec" / "install-report.json").read_text(encoding="utf-8"))["product_name"] == "Acme SecureCode"
    v = subprocess.run([sys.executable, "-I", str(ROOT / "verify-global.py")], env=env,
                       capture_output=True, text=True, timeout=120, encoding="utf-8")
    out = json.loads(v.stdout[:v.stdout.rindex("}") + 1])
    assert out["product_name"] == "Acme SecureCode" and out["update_task"] == "Acme SecureCode Update"
    assert v.stdout.strip().splitlines()[-1].startswith("Acme SecureCode: ")


# ---------- update from a signed NexaForge release ----------

def signed_update(tmp: Path, app: Path, installer_extra=""):
    """A NexaForge-named 6.3.0 release whose installer runs the real copy logic into the temp app."""
    key = tmp / "release_key"
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "t", "-f", str(key)], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    (app / "config" / "allowed_signers").write_text("security@org " + (tmp / "release_key.pub").read_text(), encoding="utf-8")
    stub = ('VERSION="6.3.0"\nimport importlib.util\nfrom pathlib import Path\n'
            f'spec=importlib.util.spec_from_file_location("realinst", r"{ROOT / "install-global.py"}")\n'
            'g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)\n'
            f'g.install_runtime(Path(__file__).resolve().parent, Path(r"{app}"))\n' + installer_extra)
    z = tmp / "pkg.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("aisec/install-global.py", stub)
        zf.writestr("aisec/config/brand.json", json.dumps({"product_name": "NexaForge SecureCode"}))
        zf.writestr("aisec/docs/COMMON-FINDINGS.md", "# Common findings, release 6.3.0\n")
        zf.writestr("aisec/scripts/updater.py", (ROOT / "scripts" / "updater.py").read_text(encoding="utf-8"))
    subprocess.run([KEYGEN, "-Y", "sign", "-f", str(key), "-n", "org-appsec-update", str(z)], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    sig = Path(str(z) + ".sig")

    def fetch(kind, url, dest):
        if kind == "release":
            return {"tag_name": "v6.3.0", "assets": [{"name": "Org_AI.zip", "url": "zip"}, {"name": "Org_AI.zip.sig", "url": "sig"}]}
        shutil.copy2(z if url == "zip" else sig, dest)
    return fetch


@needs_keygen
def test_update_from_nexaforge_release_keeps_brand_and_org_files(tmp_path):
    app = install_app(tmp_path)
    assert G.update_task_name(app) == "Acme SecureCode Update"
    upd = load(app / "scripts" / "updater.py", "upd_brand_e2e")
    status = upd.check_and_update(CFG, None, fetch=signed_update(tmp_path, app), workdir=tmp_path / "w")
    assert status == "updated"
    assert (app / "docs" / "COMMON-FINDINGS.md").read_text(encoding="utf-8") == "# Common findings, release 6.3.0\n"
    assert json.loads((app / "config" / "brand.json").read_text(encoding="utf-8")) == {"product_name": "Acme SecureCode"}
    assert (app / "docs" / "ORG-FINDINGS.md").read_text(encoding="utf-8") == "# Our own pentest findings\n"
    assert G.update_task_name(app) == "Acme SecureCode Update"
    assert upd.product_name() == "Acme SecureCode"
    assert upd.result_line(status) == "updated to 6.3.0"


@needs_keygen
def test_updater_restores_brand_even_if_a_release_installer_overwrites_it(tmp_path):
    app = install_app(tmp_path)
    clobber = (f'Path(r"{app}", "config", "brand.json").write_text(\'{{"product_name": "NexaForge SecureCode"}}\')\n'
               f'Path(r"{app}", "docs", "ORG-FINDINGS.md").unlink()\n')
    upd = load(app / "scripts" / "updater.py", "upd_brand_clobber")
    assert upd.check_and_update(CFG, None, fetch=signed_update(tmp_path, app, clobber), workdir=tmp_path / "w") == "updated"
    assert G.update_task_name(app) == "Acme SecureCode Update"
    assert (app / "docs" / "ORG-FINDINGS.md").read_text(encoding="utf-8") == "# Our own pentest findings\n"


# ---------- manual update: one clear line, return codes unchanged ----------

def manual_run(app: Path, monkeypatch, capsys, outcome):
    upd = load(app / "scripts" / "updater.py", "upd_brand_manual")
    (app / "config" / "update.json").write_text(json.dumps(CFG), encoding="utf-8")
    monkeypatch.setattr(upd, "token", lambda: None)

    def fake(cfg, tok, **kw):
        if isinstance(outcome, BaseException):
            raise outcome
        upd.LAST_RELEASE["tag"] = "v6.3.0"
        return outcome
    monkeypatch.setattr(upd, "check_and_update", fake)
    rc = upd.main()
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1, lines
    assert not (app / "update.lock").exists()
    return rc, lines[0]


@pytest.mark.parametrize("outcome,rc,line", [
    ("updated", 0, "Acme SecureCode: updated to 6.3.0"),
    ("up-to-date", 0, "Acme SecureCode: already up to date (6.2.0)"),
    ("SIGNATURE-INVALID", 1, "Acme SecureCode: signature invalid, nothing installed"),
    (urllib.error.URLError("getaddrinfo failed"), 1, "Acme SecureCode: no network or GitHub unreachable"),
    (TimeoutError("timed out"), 1, "Acme SecureCode: no network or GitHub unreachable"),
    ("not-configured", 0, "Acme SecureCode: auto-update is not configured (config/update.json), nothing to do"),
    ("VERSION-MISMATCH", 1, "Acme SecureCode: signed package version does not match the release tag, nothing installed"),
])
def test_manual_update_prints_one_line(tmp_path, monkeypatch, capsys, outcome, rc, line):
    app = install_app(tmp_path)
    assert manual_run(app, monkeypatch, capsys, outcome) == (rc, line)
