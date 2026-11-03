"""The benchmark lab must keep finding what the built-in checks found when RESULTS.md was written.
A drop means a rule got weaker."""
import importlib.util, io, re
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_quick_mode_lab_floor():
    spec = importlib.util.spec_from_file_location("run_lab", ROOT / "benchmark" / "run_lab.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    buf = io.StringIO()
    with redirect_stdout(buf):
        m.main(["--mode", "quick"])
    out = buf.getvalue()
    found = int(re.search(r"found: (\d+) of", out).group(1))
    assert found >= 11, out
    assert re.search(r"\| L16 \|[^\n]*\| found \|", out), out          # Blade {!! !!}


def test_lab_paths_cannot_escape(tmp_path):
    spec = importlib.util.spec_from_file_location("run_lab2", ROOT / "benchmark" / "run_lab.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    for bad in ("../x.php", "/etc/x", "a/../../x"):
        try:
            m.materialize({"files": {bad: "x"}}, tmp_path)
            assert False, bad
        except ValueError:
            pass
