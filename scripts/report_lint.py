#!/usr/bin/env python3
"""Lint a security report (REPORT.md from report.py, or a hand-edited copy) before it is handed over.

Errors (exit 1):
- a required section is missing,
- a finding row has no valid outcome label, severity or location,
- a Pass has no evidence, or Risk accepted has no named person and date,
- the text claims the application is secure ("100% secure", "fully secure", "unhackable", ...),
- the text contains an unmasked secret, or hidden control or bidirectional characters.
Warnings (printed, exit 0): first-person wording, and "exploited", "exfiltrated" or "compromised" with no
evidence column filled for that finding.
"""
from __future__ import annotations

import argparse, html, os, re, sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run with python -I
from report import OUTCOMES, SEV_ORDER, INVISIBLE, has_secret  # noqa: E402

REQUIRED = ["Executive summary", "Scope and method", "Findings", "Attack chains", "Retest", "Artifacts", "Limits"]
OVERCLAIM = re.compile(r"(?i)\b100\s*%\s*secure\b|\b(fully|completely|totally|perfectly|absolutely)\s+secure\b|\bunhackable\b|"
                       r"\bbullet-?proof\b|\bguarantee[sd]?\b[^.\n]{0,40}\bsecure\b|\bno vulnerabilities (exist|remain)\b|"
                       r"\bfree (of|from) (all )?vulnerabilities\b")
NEGATED_OVERCLAIM = re.compile(r"(?i)\b(not|never|no tool|does not|cannot|can't)\b[^.\n]{0,60}$")
FIRST_PERSON = re.compile(r"(^|[\s(])(I|[Ww]e|[Oo]ur|[Uu]s|[Mm]y)(?=[\s,.)])")
STRONG_CLAIM = re.compile(r"(?i)\b(exploited|exfiltrated|compromised|pwned)\b")
MD_ESCAPE = re.compile(r"\\([\\`*_{}\[\]()#+!|~>\-=])")


def split_row(line: str) -> list[str]:
    cells = re.split(r"(?<!\\)\|", line.strip())
    return [c.strip() for c in cells[1:-1]]


def lint(text: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []; warnings: list[str] = []
    plain = html.unescape(MD_ESCAPE.sub(r"\1", text))
    headings = [m.group(1).strip().lower() for m in re.finditer(r"(?m)^#{1,3}\s+(.+)$", text)]
    for sec in REQUIRED:
        if not any(h == sec.lower() or h.startswith(sec.lower() + " ") or h.startswith(sec.lower() + "(") for h in headings):
            errors.append(f"missing section: {sec}")
    if INVISIBLE.search(text):
        errors.append("hidden control or bidirectional characters in the report")
    for n, line in enumerate(plain.splitlines(), 1):
        for m in OVERCLAIM.finditer(line):
            if not NEGATED_OVERCLAIM.search(line[:m.start()]):
                errors.append(f"line {n}: overclaim '{m.group(0)}'; say what was tested and its limits instead")
        if has_secret(line):
            errors.append(f"line {n}: looks like an unmasked secret; redact it")
    section = ""; header: list[str] = []; rows = 0
    for n, line in enumerate(text.splitlines(), 1):
        hm = re.match(r"^#{1,3}\s+(.+)$", line)
        if hm:
            section = hm.group(1).strip().lower(); header = []; continue
        if not line.strip().startswith("|"):
            header = [] if not line.strip() else header
            continue
        cells = split_row(line)
        if not header:
            header = [c.lower() for c in cells]; continue
        if all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
            continue
        if not cells or not re.fullmatch(r"[FD]-\d{2,}", cells[0]):
            continue
        row = dict(zip(header, cells))
        fid = cells[0]
        if section == "findings":
            rows += 1
            if row.get("retest") not in OUTCOMES:
                errors.append(f"line {n}: {fid} has no valid outcome label (one of {', '.join(OUTCOMES)})")
            if row.get("severity") not in SEV_ORDER:
                errors.append(f"line {n}: {fid} has no valid severity")
            if not row.get("location") or row.get("location") == "-":
                errors.append(f"line {n}: {fid} has no location")
            if STRONG_CLAIM.search(line) and row.get("evidence") in (None, "", "-"):
                warnings.append(f"line {n}: {fid} says exploited/compromised but has no evidence")
        elif section == "retest":
            oc = row.get("outcome")
            if oc not in OUTCOMES:
                errors.append(f"line {n}: retest row {fid} has no valid outcome label")
            if oc == "Pass" and row.get("evidence") in (None, "", "-"):
                errors.append(f"line {n}: {fid} is Pass without evidence (name the test or command that reached the sink)")
            if oc == "Risk accepted" and not re.search(r"accepted by \S.{0,80}? on \d{4}-\d{2}-\d{2}", MD_ESCAPE.sub(r"\1", row.get("note", ""))):
                errors.append(f"line {n}: {fid} is Risk accepted without a named person and date")
    if rows == 0 and not re.search(r"(?i)no findings were reported", text):
        errors.append("the findings table has no rows and does not say that nothing was found")
    for n, line in enumerate(plain.splitlines(), 1):
        if FIRST_PERSON.search(line) and not line.lstrip().startswith("|"):
            warnings.append(f"line {n}: first-person wording; write as a neutral observer")
    return errors, warnings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Lint a security report before handover.")
    ap.add_argument("report", nargs="?", default=".security/REPORT.md")
    a = ap.parse_args(argv)
    p = Path(a.report)
    try:
        if p.stat().st_size > 20_000_000:
            print("report is larger than 20 MB; refused"); return 2
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        print(f"cannot read {p}"); return 2
    errors, warnings = lint(text)
    for w in warnings:
        print("WARNING:", w)
    for e in errors:
        print("ERROR:", e)
    print("REPORT LINT:", "FAIL" if errors else "PASS", f"({len(errors)} error(s), {len(warnings)} warning(s))")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
