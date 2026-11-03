import importlib.util, json, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
KEYGEN = shutil.which("ssh-keygen")
pytestmark = pytest.mark.skipif(not KEYGEN, reason="ssh-keygen not installed")


def make_app(tmp: Path, installed="6.2.0"):
    app = tmp / "app"
    (app / "scripts").mkdir(parents=True)
    (app / "config").mkdir()
    shutil.copy2(ROOT / "scripts" / "updater.py", app / "scripts" / "updater.py")
    (app / "install-report.json").write_text(json.dumps({"version": installed}), encoding="utf-8")
    key = tmp / "release_key"
    subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "t", "-f", str(key)], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    (app / "config" / "allowed_signers").write_text("security@org " + (tmp / "release_key.pub").read_text(), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("upd_under_test", app / "scripts" / "updater.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod, key


def build_zip(tmp: Path, marker: Path, extra=None, version="6.3.0"):
    z = tmp / "pkg.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("aisec/install-global.py", f'VERSION="{version}"\nopen(r\'{marker}\', \'w\').write(\'installed\')\n')
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return z


def sign(key: Path, f: Path):
    subprocess.run([KEYGEN, "-Y", "sign", "-f", str(key), "-n", "org-appsec-update", str(f)], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    return Path(str(f) + ".sig")


def fetcher(tag, zip_path, sig_path, with_sig=True):
    assets = [{"name": "Org_AI.zip", "url": "zip"}] + ([{"name": "Org_AI.zip.sig", "url": "sig"}] if with_sig else [])
    def fetch(kind, url, dest):
        if kind == "release":
            return {"tag_name": tag, "assets": assets}
        shutil.copy2(zip_path if url == "zip" else sig_path, dest)
    return fetch


CFG = {"repo": "org/nexaforge-securecode", "asset": "Org_AI.zip", "signer_identity": "security@org"}


def test_signed_newer_release_installs():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d); mod, key = make_app(t); marker = t / "marker"
        z = build_zip(t, marker); s = sign(key, z)
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v6.3.0", z, s), workdir=t / "w") == "updated"
        assert marker.read_text() == "installed"


def test_tampered_release_is_rejected():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d); mod, key = make_app(t); marker = t / "marker"
        z = build_zip(t, marker); s = sign(key, z)
        with zipfile.ZipFile(z, "a") as zf:
            zf.writestr("aisec/evil.txt", "x")  # changed after signing
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v6.3.0", z, s), workdir=t / "w") == "SIGNATURE-INVALID"
        assert not marker.exists()


def test_release_signed_by_another_key_is_rejected():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d); mod, _ = make_app(t); marker = t / "marker"
        other = t / "attacker_key"
        subprocess.run([KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "x", "-f", str(other)], check=True,
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        z = build_zip(t, marker); s = sign(other, z)
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v6.3.0", z, s), workdir=t / "w") == "SIGNATURE-INVALID"
        assert not marker.exists()


def test_same_or_older_version_and_missing_signature_are_skipped():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d); mod, key = make_app(t); marker = t / "marker"
        z = build_zip(t, marker); s = sign(key, z)
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v6.2.0", z, s)) == "up-to-date"
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v6.1.9", z, s)) == "up-to-date"
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v6.3.0", z, s, with_sig=False)) == "release-missing-signed-asset"
        assert mod.check_and_update({"repo": ""}, "tok") == "not-configured"
        assert not marker.exists()


def test_old_signed_zip_under_new_tag_and_unknown_baseline_are_refused():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d); mod, key = make_app(t); marker = t / "marker"
        old = build_zip(t, marker, version="6.1.0"); s = sign(key, old)
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v99.0.0", old, s), workdir=t / "w") == "VERSION-MISMATCH"
        assert not marker.exists()
        (t / "app" / "install-report.json").unlink()
        z = build_zip(t, marker); s = sign(key, z)
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v6.3.0", z, s)) == "installed-version-unknown"


def test_wildcard_signer_and_zip_bomb_are_refused():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d); mod, key = make_app(t); marker = t / "marker"
        signers = t / "app" / "config" / "allowed_signers"
        signers.write_text("* " + (t / "release_key.pub").read_text(), encoding="utf-8")
        z = build_zip(t, marker); s = sign(key, z)
        assert mod.check_and_update(CFG, "tok", fetch=fetcher("v6.3.0", z, s), workdir=t / "w") == "SIGNATURE-INVALID"
        bomb = t / "bomb.zip"
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("aisec/big.bin", b"\0" * (201 * 1024 * 1024))
        with pytest.raises(RuntimeError):
            mod.safe_extract(bomb, t / "x")


def test_network_calls_refuse_non_github_urls():
    with tempfile.TemporaryDirectory() as d:
        mod, _ = make_app(Path(d))
        for bad in ("file:///C:/Windows/win.ini", "http://api.github.com/x", "https://evil.example/asset", "https://api.github.com.evil.example/x"):
            with pytest.raises(RuntimeError):
                mod.api(bad, "tok")
            with pytest.raises(RuntimeError):
                mod.download(bad, "tok", Path(d) / "x")


def test_path_traversal_in_signed_zip_is_refused():
    with tempfile.TemporaryDirectory() as d:
        t = Path(d); mod, key = make_app(t); marker = t / "marker"
        z = build_zip(t, marker, extra={"../../escape.txt": "x"}); s = sign(key, z)
        with pytest.raises(RuntimeError):
            mod.check_and_update(CFG, "tok", fetch=fetcher("v6.3.0", z, s), workdir=t / "w")
        assert not (t / "escape.txt").exists() and not marker.exists()
