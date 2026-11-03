#!/usr/bin/env python3
"""Write the benchmark lab to a temporary folder, run the gate on it and report which planted issues
were found. Prints a Markdown table; the numbers in RESULTS.md come only from this script.

    py -I benchmark/run_lab.py                 # quick mode: built-in checks only
    py -I benchmark/run_lab.py --mode full     # plus Semgrep, Trivy, Gitleaks when installed
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECGATE = HERE.parent / "scripts" / "secgate.py"


def materialize(lab: dict, dest: Path):
    for rel, text in lab["files"].items():
        if rel.startswith(("/", "\\")) or ".." in re.split(r"[\\/]", rel):
            raise ValueError(f"unsafe lab path {rel!r}")
        f = dest / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("quick", "full"), default="quick")
    a = ap.parse_args(argv)
    lab = json.loads((HERE / "laravel-lab.json").read_text(encoding="utf-8"))
    d = Path(tempfile.mkdtemp(prefix="securecode-lab-"))
    try:
        materialize(lab, d)
        p = subprocess.run([sys.executable, "-I", str(SECGATE), ".", "--mode", a.mode, "--fail-on", "never", "--report"],
                           cwd=d, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
        rep = d / ".security" / "findings.json"
        data = json.loads(rep.read_text(encoding="utf-8")) if rep.exists() else {}
        findings = data.get("findings", data if isinstance(data, list) else [])
    finally:
        shutil.rmtree(d, ignore_errors=True)
    rows, hit = [], 0
    for e in lab["expected"]:
        target = e["file"].replace("\\", "/")
        match = [f for f in findings if str(f.get("file", "")).replace("\\", "/").endswith(target)
                 and e["rule_hint"].lower() in str(f.get("rule", "")).lower()]
        hit += bool(match)
        rows.append(f"| {e['id']} | {e['what']} | {'found' if match else 'missed'} | {', '.join(sorted({m['rule'].split('.')[-1] for m in match})) or '-'} |")
    print(f"Mode: {a.mode}. Planted issues found: {hit} of {len(lab['expected'])}.\n")
    print("| id | planted issue | result | rule |\n|---|---|---|---|")
    print("\n".join(rows))
    return 0 if p.returncode in (0, 2) else p.returncode


if __name__ == "__main__":
    raise SystemExit(main())
