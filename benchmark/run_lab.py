#!/usr/bin/env python3
"""Write each benchmark lab to a temporary folder, run the gate on it and report which planted issues
were found and whether any clean file was reported. Prints a Markdown table per lab; the numbers in
RESULTS.md come only from this script.

    py -I benchmark/run_lab.py                       # every lab, quick mode (built-in checks only)
    py -I benchmark/run_lab.py --mode full           # plus Semgrep, Trivy, Gitleaks when installed
    py -I benchmark/run_lab.py --lab spring          # one lab: laravel, spring, legacy or web
"""
import argparse, json, re, shutil, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SECGATE = HERE.parent / "scripts" / "secgate.py"
LABS = ("laravel", "spring", "legacy", "web")


def materialize(lab: dict, dest: Path):
    for rel, text in lab["files"].items():
        if rel.startswith(("/", "\\")) or ".." in re.split(r"[\\/]", rel) or re.match(r"^[A-Za-z]:", rel):
            raise ValueError(f"unsafe lab path {rel!r}")
        f = dest / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")


def hint_match(hint: str, rule: str) -> bool:
    # "a|b" means either rule name; an empty hint matches every rule.
    return any(h.lower() in rule.lower() for h in hint.split("|")) if hint else True


def run_gate(lab: dict, mode: str):
    d = Path(tempfile.mkdtemp(prefix="securecode-lab-"))
    try:
        materialize(lab, d)
        p = subprocess.run([sys.executable, "-I", str(SECGATE), ".", "--mode", mode, "--fail-on", "never", "--report"],
                           cwd=d, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
        rep = d / ".security" / "findings.json"
        data = json.loads(rep.read_text(encoding="utf-8")) if rep.exists() else {}
        findings = data.get("findings", data if isinstance(data, list) else [])
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return p.returncode, findings


def on_file(findings, rel):
    # The gate runs inside the lab folder, so finding paths are relative to it. Compare exactly:
    # "index.php" must not also match "public/index.php".
    target = rel.replace("\\", "/")
    out = []
    for f in findings:
        path = str(f.get("file", "")).replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        if path == target:
            out.append(f)
    return out


def score(name: str, lab: dict, findings: list, mode: str) -> tuple:
    rows, hit = [], 0
    for e in lab["expected"]:
        match = [f for f in on_file(findings, e["file"]) if hint_match(e["rule_hint"], str(f.get("rule", "")))]
        hit += bool(match)
        rows.append(f"| {e['id']} | {e['what']} | {'found' if match else 'missed'} | "
                    f"{', '.join(sorted({m['rule'].split('.')[-1] for m in match})) or '-'} |")
    clean = lab.get("clean", [])
    noisy = []
    for c in clean:
        fp = [f for f in on_file(findings, c["file"]) if hint_match(c.get("rule_hint", ""), str(f.get("rule", "")))]
        if fp:
            noisy.append(f"{c['file']} ({', '.join(sorted({f['rule'].split('.')[-1] for f in fp}))})")
    print(f"Lab: {name}. Mode: {mode}. Planted issues found: {hit} of {len(lab['expected'])}. "
          f"Clean files reported: {len(noisy)} of {len(clean)}.\n")
    print("| id | planted issue | result | rule |\n|---|---|---|---|")
    print("\n".join(rows))
    if noisy:
        print("\nFalse positives on clean files: " + "; ".join(noisy))
    print()
    return hit, len(lab["expected"]), len(noisy)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("quick", "full"), default="quick")
    ap.add_argument("--lab", choices=("all",) + LABS, default="all")
    a = ap.parse_args(argv)
    worst = 0
    for name in (LABS if a.lab == "all" else (a.lab,)):
        lab = json.loads((HERE / f"{name}-lab.json").read_text(encoding="utf-8"))
        rc, findings = run_gate(lab, a.mode)
        score(name, lab, findings, a.mode)
        if rc not in (0, 2):
            worst = rc
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
