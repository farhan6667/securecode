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
from report import OUTCOMES, SEV_ORDER, INVISIBLE, has_secret, COVERAGE_CLASSES, COVERAGE_STATUSES  # noqa: E402

REQUIRED = ["Executive summary", "Scope and method", "Findings", "Attack chains", "Retest", "Artifacts", "Limits"]
# "Coverage" is optional (a team that keeps .security/coverage.json gets it). When it is there, or when the report
# claims readiness, the table must be complete.
OVERCLAIM = re.compile(r"(?i)\b100\s*%\s*secure\b|\b(fully|completely|totally|perfectly|absolutely)\s+secure\b|\bunhackable\b|"
                       r"\bbullet-?proof\b|\bguarantee[sd]?\b[^.\n]{0,40}\bsecure\b|\bno vulnerabilities (exist|remain)\b|"
                       r"\bfree (of|from) (all )?vulnerabilities\b")
# 7.2: claims about the test itself. Looked for in prose only (a table cell quotes code and scanner text), and a
# sentence that denies or reports the claim ("never claimed", "the scanner said ... but") is not the claim.
OVERCLAIM_TEST = re.compile(r"(?i)\bpen(etration)?[ -]?test(ing)? (was |is |has been )?passed\b|"
                            r"\bpassed (the |a )?pen(etration)?[ -]?test\b|\bproduction[ -]ready\b|"
                            r"\bno (security )?issues (were )?found\b|\bno vulnerabilities (were )?found\b")
DENIED = re.compile(r"(?i)\b(not|never|no tool|does not|doesn't|cannot|can't|nobody|but|although|said|says|saying|reporting|"
                    r"reported|claim(s|ed)?|instead of)\b")
# A report that says the project is ready, however it is dressed: the generated line, or a readiness or handover
# label whose first word is READY. Markup is stripped before the search.
READY_PHRASE = re.compile(r"(?i)\bready\s+for\s+pen(etration)?[\s-]?test(ing)?\b")
READY_LABEL = re.compile(r"(?im)\b(readiness|handover|status)\b[^\n:]{0,30}:[^A-Za-z\n]{0,12}READY\b")
MARKUP = re.compile(r"<[^>\n]{0,300}>|[*_`~]")
LINE_MAX = 20_000                       # longer lines are checked up to here; the patterns need no more
TEXT_MAX = 5_000_000                    # a report is a few hundred kilobytes; more than this is refused, not linted
CODE_SPAN = re.compile(r"`[^`\n]{0,400}`")
QUOTED_DETAIL = re.compile(r"\s*- \*\*[FDRO]-\d{2,}\*\* \(")
QUOTED_LINE = re.compile(r"\s*(\||#{1,6}\s|- \*\*[FDRO]-\d{2,}\*\* \()")    # a table row, a heading, a finding detail or observation line
NEGATED_OVERCLAIM = re.compile(r"(?i)\b(not|never|no tool|does not|cannot|can't)\b[^.\n]{0,60}$")
FIRST_PERSON = re.compile(r"(^|[\s(])(I|[Ww]e|[Oo]ur|[Uu]s|[Mm]y)(?=[\s,.)])")
STRONG_CLAIM = re.compile(r"(?i)\b(exploited|exfiltrated|compromised|pwned)\b")
MD_ESCAPE = re.compile(r"\\([\\`*_{}\[\]()#+!|~>\-=])")


def split_row(line: str) -> list[str]:
    cells = re.split(r"(?<!\\)\|", line.strip())
    return [c.strip() for c in cells[1:-1]]


def lint(text: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []; warnings: list[str] = []
    if len(text) > TEXT_MAX:
        return [f"the report is larger than {TEXT_MAX // 1_000_000} MB; it was not checked"], []
    plain = html.unescape(MD_ESCAPE.sub(r"\1", text))
    headings = [m.group(1).strip().lower() for m in re.finditer(r"(?m)^#{1,3}\s+(.+)$", text)]
    for sec in REQUIRED:
        if not any(h == sec.lower() or h.startswith(sec.lower() + " ") or h.startswith(sec.lower() + "(") for h in headings):
            errors.append(f"missing section: {sec}")
    if INVISIBLE.search(text):
        errors.append("hidden control or bidirectional characters in the report")
    for n, raw_line in enumerate(text.splitlines(), 1):
        line = " ".join(html.unescape(MD_ESCAPE.sub(r"\1", raw_line)).splitlines())
        if len(line) > LINE_MAX:
            warnings.append(f"line {n}: longer than {LINE_MAX} characters; only the start was checked")
            line = line[:LINE_MAX]
        # What the report quotes is not what the report says: a table cell, a finding detail line, a heading (the
        # title carries the project folder's name) and inline code hold scanner text, code and names. A project
        # called "unhackable-shop", or a code line with "fully secure" in a comment, failed the lint of a report the
        # tool had written itself, and with it every handover pack for that project.
        # Decided on the line as written, before unescaping: text from a result file that starts with an escaped
        # "\*\*" is not the tool's own "- **F-01**" detail line and must not borrow its exemption.
        said = "" if QUOTED_LINE.match(raw_line) else CODE_SPAN.sub(" ", line)
        for m in OVERCLAIM.finditer(said):
            # only the 80 characters before the match: looking at the whole start of the line for every match made
            # one long line cost quadratic time
            if not NEGATED_OVERCLAIM.search(said[max(0, m.start() - 80):m.start()]):
                errors.append(f"line {n}: overclaim '{m.group(0)}'; say what was tested and its limits instead")
        if said:
            line_full, line = line, said
            for m in OVERCLAIM_TEST.finditer(line):
                a = max(line.rfind(".", 0, m.start()), line.rfind("!", 0, m.start()), line.rfind("?", 0, m.start()), m.start() - 200, -1) + 1
                b = min([x for x in (line.find(".", m.end()), line.find("!", m.end()), line.find("?", m.end())) if x != -1] + [m.end() + 200])
                if not DENIED.search(line[a:m.start()] + " " + line[m.end():b]):
                    errors.append(f"line {n}: overclaim '{m.group(0)}'; say what was tested and its limits instead")
            line = line_full
        if has_secret(line):
            errors.append(f"line {n}: looks like an unmasked secret; redact it")
    section = ""; header: list[str] = []; rows = 0; cov_open = 0
    labels = {label.lower(): 0 for _, label in COVERAGE_CLASSES}
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
        if section == "coverage" and len(cells) >= 2:
            name = html.unescape(MD_ESCAPE.sub(r"\1", cells[0])).strip().lower()
            if name not in labels:
                errors.append(f"line {n}: coverage row '{cells[0][:60]}' is not one of the review classes")
                continue
            labels[name] += 1
            if labels[name] > 1:
                errors.append(f"line {n}: coverage row '{cells[0][:60]}' appears more than once")
                continue
            if cells[1].lower() not in COVERAGE_STATUSES:
                errors.append(f"line {n}: coverage row '{cells[0][:60]}' has no valid status (one of {', '.join(COVERAGE_STATUSES)})")
            elif cells[1].lower() == "not examined":
                cov_open += 1
            elif len(cells) < 3 or cells[2] in ("", "-"):
                errors.append(f"line {n}: coverage row '{cells[0][:60]}' is {cells[1]} with no evidence or reason")
            continue
        if not cells or not re.fullmatch(r"[FDR]-\d{2,}", cells[0]):
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
            # 400: the report keeps up to 200 characters of the name, and escaping can double them
            if oc == "Risk accepted" and not re.search(r"accepted by \s*\S.{0,400}? on \d{4}-\d{2}-\d{2}", MD_ESCAPE.sub(r"\1", row.get("note", ""))):
                errors.append(f"line {n}: {fid} is Risk accepted without a named person and date")
    if rows == 0 and not re.search(r"(?i)no findings were reported", text):
        errors.append("the findings table has no rows and does not say that nothing was found")
    cov_rows = sum(1 for v in labels.values() if v)
    if "coverage" in headings and cov_rows < len(COVERAGE_CLASSES):
        errors.append(f"the coverage table has {cov_rows} of the {len(COVERAGE_CLASSES)} review classes; it needs one row for each")
    # not the title line: it carries the project folder's name
    # a table row and a finding detail or observation line quote a scanner or a reviewer ("status: ready" in a finding's
    # message is not the report saying the project is ready); a heading is kept, a forged one must be seen
    flat = MARKUP.sub("", "\n".join(
        CODE_SPAN.sub(" ", " ".join(html.unescape(MD_ESCAPE.sub(r"\1", rw)).splitlines())[:LINE_MAX])
        for rw in text.splitlines()[1:] if not rw.lstrip().startswith("|") and not QUOTED_DETAIL.match(rw)))
    if (READY_PHRASE.search(flat) or READY_LABEL.search(flat)) and (cov_open or cov_rows < len(COVERAGE_CLASSES)):
        errors.append("the report says READY FOR PENTEST REVIEW while review classes are not examined")
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
