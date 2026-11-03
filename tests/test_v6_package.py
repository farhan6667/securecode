import re, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ci_fails_closed_if_required_scanners_missing():
    with tempfile.TemporaryDirectory() as d:
        p = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "secgate.py"), ".", "--mode", "ci", "--fail-on", "high"],
                           cwd=d, text=True, capture_output=True, env={"PATH": d, "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")})
        assert p.returncode == 3, p.stdout
        assert "required security scanner missing" in p.stdout


def test_version_is_consistent():
    manifest = (ROOT / "MANIFEST.txt").read_text(encoding="utf-8")
    installer = (ROOT / "install-global.py").read_text(encoding="utf-8")
    v = re.search(r'VERSION="([\d.]+)"', installer).group(1)
    assert f"Version: {v}" in manifest


def test_package_passes_its_own_quick_gate():
    p = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "secgate.py"), ".", "--mode", "quick", "--fail-on", "high"],
                       cwd=ROOT, text=True, capture_output=True, encoding="utf-8", errors="replace")
    assert p.returncode == 0, p.stdout
