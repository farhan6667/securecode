import shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_quick_gate_blocks_the_vulnerable_sample():
    # Run outside the package so its own suppression file (which covers this fixture) does not apply.
    with tempfile.TemporaryDirectory() as d:
        shutil.copy2(ROOT / "tests" / "vulnerable_sample.py", d)
        p = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "secgate.py"), "vulnerable_sample.py", "--fail-on", "high"],
                           cwd=d, text=True, capture_output=True, encoding="utf-8", errors="replace")
        assert p.returncode == 2, p.stdout + p.stderr
        assert "COMMAND_INJECTION" in p.stdout and "RESULT: BLOCKED" in p.stdout, p.stdout
