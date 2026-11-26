#!/usr/bin/env python3
"""Build the handover pack a security team receives after "Complete Security Test", or verify one.

    py -I handover_pack.py                 build .security/handover/<project>-handover-<time>.zip
    py -I handover_pack.py --sbom --pdf    also write a CycloneDX SBOM with Trivy and a PDF of the report, when it can
    py -I handover_pack.py --verify PACK --expect-sha256 HASH    check a pack you received

The pack is the report plus everything a pentester asks for next, so the review can be checked instead of repeated:
the commit that was tested, the tools that ran, the coverage per review class, every finding with its retest proof,
what was not tested, and a SHA-256 of every file.

The report in the pack is built again here, from the result files as they are now. A REPORT.md or report-state.json
that was written earlier (or edited since) is never trusted: the verdict and the readiness in the pack always come
from the same findings, coverage and retest files the pack carries.

What the hashes are for: they show that a file no longer matches the manifest. A person who edits a file and the
manifest together gets a pack that is consistent again, so the hashes do not show who built it. The check that does:
the developer sends the pack's own SHA-256 (printed at the end) by a separate channel and the receiver passes it to
--expect-sha256.

Every text that goes into the pack is treated as attacker-controlled: secrets are redacted again, hidden characters are
made visible, and nothing is read through a link or from outside .security. The pack never says the application is
secure; it says what was reviewed.

Exit codes: 0 pack built and the review is ready or conditionally ready, or a verify that passed; 1 pack built but
NOT READY (the name says so), or a verify that failed; 2 bad arguments or an unreadable pack; 3 the results are
missing or the report fails its lint.
"""
from __future__ import annotations

import argparse, datetime, hashlib, io, json, os, re, stat, subprocess, sys, zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run with python -I
import report as R  # noqa: E402
from report import redact, visible, has_secret, READINESS  # noqa: E402

MAX_FILE = 50_000_000
MAX_TOTAL = 200_000_000
MAX_MEMBERS = 200
# name in the pack and in .security -> kind. json files are parsed and written again with every string redacted.
# REPORT.md, REPORT.html and report-state.json are not on this list: they are built here, never copied.
SOURCES = [
    ("findings-before.json", "json"), ("findings.json", "json"), ("findings-summary.txt", "text"), ("findings.sarif", "json"),
    ("review-findings.json", "json"), ("coverage.json", "json"), ("retest.json", "json"), ("artifacts.json", "json"),
    ("dast-findings.json", "json"), ("authz-matrix.md", "text"), ("RUNBOOK.md", "text"), ("sbom.cdx.json", "json"),
]
BUILT = ("REPORT.md", "REPORT.html", "report-state.json", "NOT-TESTED.md")
CORE = ("REPORT.md", "report-state.json", "findings.json", "NOT-TESTED.md")       # a pack without these is not a pack
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
# A value under a key with one of these names is a secret whatever it looks like ("password": "hunter2").
SECRET_KEY = re.compile(r"(?i)pass(word|wd|phrase)?$|^pwd$|secret|token|api[-_ ]?key|authori[sz]ation|credential|private[-_ ]?key|"
                        r"^cookie$|set-cookie|session[-_ ]?id|bearer|^auth$|access[-_ ]?key|client[-_ ]?secret|connection[-_ ]?string")
# Shapes report.redact has no pattern for.
MORE_SECRETS = [
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{10,}"), "https://hooks.slack.com/services/[REDACTED]"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}"), "[REDACTED]"),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}"), "[REDACTED]"),
    (re.compile(r"(?i)\b(basic|bearer|token)\s+[A-Za-z0-9+/._~=-]{12,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(aws_secret_access_key|x-api-key|x-auth-token)(\s*[:=]\s*)\S{8,}"), r"\1\2[REDACTED]"),
]


def scrub(s) -> str:
    s = "" if s is None else str(s)
    if len(s) > R.TEXT_FIELD_MAX:       # cut before any pattern runs: a pattern's cost must never depend on the input's size
        s = s[:R.TEXT_FIELD_MAX] + " [cut]"
    s = redact(s)
    for rx, repl in MORE_SECRETS:
        s = rx.sub(repl, s)
    s = visible(s)
    return "[withheld: looked like a secret]" if has_secret(s) else s


def _plain_dir(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and not (getattr(st, "st_file_attributes", 0) & 0x400)


def _read_plain(p: Path) -> bytes | None:
    """The bytes of a small plain file, or None. Never through a link, a junction or a hard link to somewhere else."""
    try:
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400 or st.st_nlink > 1 or st.st_size > MAX_FILE:
            return None
        return p.read_bytes()
    except OSError:
        return None


PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]{0,30}-----")
PEM_END = re.compile(r"-----END [A-Z0-9 ]{0,30}-----")


def _clean_text(b: bytes) -> bytes | None:
    """A text member, line by line. Decoded as report.py decodes result files: PowerShell 5.1 writes UTF-16, and read
    as UTF-8 that is one NUL between every two letters, which no pattern matches, so every secret went through. Text
    that still holds NULs after decoding is refused (None). A key block is dropped whole, in one pass over the lines."""
    text = R.decode_text(b)
    if "\x00" in text:
        return None
    out, in_key = [], False
    for ln in text.splitlines():
        if in_key:
            if PEM_END.search(ln):
                in_key = False
            continue
        if PEM_BEGIN.search(ln[:400]):
            out.append("[REDACTED KEY BLOCK]")
            in_key = not PEM_END.search(ln)
            continue
        out.append(scrub(ln))
    return "\n".join(out).encode("utf-8") + b"\n"


def _clean_json(b: bytes) -> bytes | None:
    def walk(v, key="", depth=0):
        if depth > 60:
            return "[too deep]"
        if isinstance(v, str):
            return "[REDACTED]" if SECRET_KEY.search(key) and v else scrub(v)
        if isinstance(v, list):
            return [walk(x, key, depth + 1) for x in v[:100_000]]
        if isinstance(v, dict):
            return {scrub(str(k))[:200]: walk(x, str(k), depth + 1) for k, x in v.items()}
        return v
    try:                                # decoded exactly as report.py reads it (byte order mark, UTF-16)
        return (json.dumps(walk(R.decode_json(b)), indent=1, ensure_ascii=True) + "\n").encode("ascii")
    except (ValueError, RecursionError, OverflowError):
        return None


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git_facts(root: Path) -> dict:
    """The commit that was tested. Uses the same safe git wrapper as the stop gate, so a repository's own config can
    not run a program here. Any failure leaves the field as 'unknown' and the pack says so."""
    out = {"commit": "unknown", "branch": "unknown", "uncommitted_files": None}
    try:
        from secgate import find_tool
        from safe_git import SafeGit
        exe = find_tool("git")
        if not exe:
            return out
        with SafeGit(exe, root) as g:
            rc, c = g.run("rev-parse", "--verify", "--quiet", "HEAD")
            if rc == 0 and re.fullmatch(r"[0-9a-f]{40,64}", c.strip()):
                out["commit"] = c.strip()
            rc, b = g.run("rev-parse", "--abbrev-ref", "HEAD")
            if rc == 0:
                out["branch"] = visible(b.strip())[:120]
            rc, s = g.run("status", "--porcelain", "-z", "--untracked-files=normal")
            if rc == 0:
                # the report files the test itself wrote do not make the tree "changed"
                names = [x[3:] for x in s.split("\0") if len(x) > 3]
                out["uncommitted_files"] = sum(1 for n in names if not n.replace("\\", "/").startswith(".security/"))
    except Exception:
        pass
    return out


def not_tested_md(model: dict, git: dict) -> bytes:
    out = ["# Not tested, and conditions on this handover", "",
           f"Handover readiness: {model['readiness']}.", ""]
    out += ["## Why this readiness", ""] + [f"- {R.md(x, 300)}" for x in model["readiness_why"][:40]] + [""]
    ne = model["coverage"]["open"]
    out += ["## Review classes that were not examined", ""] + ([f"- {x}" for x in ne] or ["None."]) + [""]
    if git.get("commit") == "unknown":
        out += ["## Commit", "", "- The tested commit could not be read; the pack is not tied to a commit.", ""]
    elif git.get("uncommitted_files"):
        out += ["## Commit", "", f"- {git['uncommitted_files']} file(s) differed from the commit when the pack was built; "
                "the commit hash alone does not describe what was tested.", ""]
    # tool notes and DAST notes come from result files: escaped like every cell of the report
    limits = list(R.LIMITS) + [f"{R.md(t)} did not run: `{R.md(d, 200)}`." for t, s, d in R.tools_table(model) if s == "did not run"]
    out += ["## Limits of the automated review", ""] + [f"- {x}" for x in limits] + [""]
    return "\n".join(out).encode("utf-8")


def make_sbom(root: Path, sec: Path) -> str:
    try:
        from secgate import find_tool
        exe = find_tool("trivy")
        if not exe:
            return "Trivy is not installed; no SBOM was written"
        target = sec / "sbom.cdx.json"
        if os.path.lexists(target) and _read_plain(target) is None:
            return "sbom.cdx.json exists and is not a plain file; left alone"
        p = subprocess.run([exe, "fs", "--quiet", "--format", "cyclonedx", "--output", str(target), "--skip-dirs", ".security", str(root)],
                           capture_output=True, timeout=600, check=False)
        return "SBOM written with Trivy" if p.returncode == 0 and target.is_file() else f"Trivy could not write the SBOM (exit {p.returncode})"
    except (OSError, subprocess.TimeoutExpired) as ex:
        return f"the SBOM step failed ({type(ex).__name__})"


def _write_plain(p: Path, data: bytes) -> bool:
    """Write next to the results, but never through a link someone planted at that name."""
    try:
        if os.path.lexists(p) and _read_plain(p) is None:
            return False
        tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, p)
        return True
    except OSError:
        try:
            os.unlink(tmp)              # the target was open or locked: leave no temp file behind
        except (OSError, UnboundLocalError):
            pass
        return False


def build(root: Path, sbom: bool = False, pdf: bool = False, now: datetime.datetime | None = None) -> tuple[int, str]:
    sec = root / ".security"
    if not _plain_dir(sec):
        return 3, "no plain .security folder here; run the security test first"
    notes = []
    if sbom:
        notes.append(make_sbom(root, sec))
    members: dict[str, bytes] = {}
    for name, kind in SOURCES:
        raw = _read_plain(sec / name)
        if raw is None:
            if os.path.lexists(sec / name):
                # There, but a link, a hard link, a folder or too large. Leaving it out would leave its findings out:
                # a hard-linked review-findings.json with an open High gave a READY pack.
                return 3, (f".security/{name} is there but is not a plain file under 50 MB (a link, a hard link or a folder); "
                           "the pack is not built without it. Replace it with an ordinary file.")
            continue
        data = _clean_text(raw) if kind == "text" else _clean_json(raw)
        if data is None and kind == "text":
            return 3, (f".security/{name} is not readable text (save it as UTF-8); the pack is not built with a file "
                       "it can not check for secrets.")
        if data is None:
            if name == "findings.sarif":            # a copy for other tools; the report does not read it
                notes.append(f"{name} is not valid JSON and was left out")
                continue
            # Every other file here is one the report reads. A pack that leaves one out while the report used it
            # (or could not) would not carry what its own verdict rests on.
            return 3, f".security/{name} is not valid JSON; the pack is not built without it. Fix or remove the file."
        members[name] = data
    if "findings.json" not in members:
        return 3, "missing: .security/findings.json. Run the gate first (secgate.py . --mode ci --fail-on high --run-tests)."

    def src(name):                      # report.py reads a path; give it only a plain file, never a link
        return (sec / name) if _read_plain(sec / name) is not None else None
    try:
        model = R.build(root, sec / "findings.json", src("findings-before.json"), src("dast-findings.json"), src("retest.json"),
                        src("artifacts.json"), src("review-findings.json"), src("coverage.json"))
        md, page = R.render_md(model), R.render_html(model)
        md.encode("utf-8"), page.encode("utf-8")
        import report_lint
        errors, warnings = report_lint.lint(md)
    except Exception as ex:             # hostile result files must give a message, not a traceback
        return 3, f"the report could not be built from the result files ({type(ex).__name__})"
    lint = f"{len(errors)} error(s), {len(warnings)} warning(s)"
    if errors:
        return 3, f"the report built from these results fails its lint ({lint}): " + "; ".join(errors[:5])
    readiness = model["readiness"] if model["readiness"] in READINESS else "NOT READY"
    state = {"verdict": model["verdict"], "why": visible(model["why"]), "readiness": readiness,
             "readiness_why": [visible(x) for x in model["readiness_why"]], "risk": model["risk"], "date": model["date"],
             "counts": R.counts(model["findings"]), "not_examined": model["coverage"]["open"],
             "fingerprints": {f["id"]: f["fp"] for f in model["findings"]}}
    git = git_facts(root)
    members["REPORT.md"] = md.encode("utf-8")
    members["REPORT.html"] = page.encode("utf-8")
    members["report-state.json"] = (json.dumps(state, indent=1, ensure_ascii=True) + "\n").encode("ascii")
    members["NOT-TESTED.md"] = not_tested_md(model, git)
    for n in ("REPORT.md", "REPORT.html", "report-state.json"):     # the folder and the pack say the same thing
        if not _write_plain(sec / n, members[n]):
            notes.append(f".security/{n} could not be refreshed (open in another program, or not a plain file); the pack holds the current one")
    if pdf:
        if _read_plain(sec / "REPORT.html") == members["REPORT.html"] and (not os.path.lexists(sec / "REPORT.pdf") or _read_plain(sec / "REPORT.pdf") is not None):
            ok, msg = R.print_pdf(sec / "REPORT.html", sec / "REPORT.pdf")
            got = _read_plain(sec / "REPORT.pdf") if ok else None
            if got:
                members["REPORT.pdf"] = got
            else:
                notes.append("no PDF: " + msg)
        else:
            notes.append("no PDF: REPORT.html or REPORT.pdf in .security is not a plain file")
    if sum(len(b) for b in members.values()) > MAX_TOTAL:
        return 3, "the pack would be larger than 200 MB"
    try:
        from secgate import GATE_VERSION
    except Exception:
        GATE_VERSION = "unknown"
    now = now or datetime.datetime.now(datetime.timezone.utc)
    ts = model["tool_status"] if isinstance(model.get("tool_status"), dict) else {}
    errs = ts.get("errors") if isinstance(ts.get("errors"), dict) else {}
    manifest = {
        "pack": "securecode-handover", "format": 1, "built": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "project": scrub(root.name)[:80], "securecode_version": GATE_VERSION, "git": git,
        "gate_mode": scrub(model["mode"])[:20],
        "scanners": {k: bool(ts.get(k)) for k in ("semgrep", "trivy", "gitleaks") if k in ts},
        "scanner_errors": sorted(scrub(str(k))[:40] for k in errs),
        "verdict": model["verdict"], "readiness": readiness, "readiness_why": [scrub(x)[:300] for x in model["readiness_why"][:40]],
        "report_lint": lint, "notes": notes,
        "not_included": sorted(n for n, _ in SOURCES if n not in members),
        "what_the_hashes_mean": "A file that no longer matches was changed. A file changed together with this manifest "
                                "matches again, so compare the pack's own SHA-256 with the one sent to you separately.",
        "files": [{"name": n, "bytes": len(b), "sha256": sha(b)} for n, b in sorted(members.items())],
    }
    mbytes = (json.dumps(manifest, indent=1, ensure_ascii=True) + "\n").encode("ascii")
    members["MANIFEST.json"] = mbytes
    members["MANIFEST.sha256"] = (sha(mbytes) + "  MANIFEST.json\n").encode("ascii")
    out_dir = sec / "handover"
    if os.path.lexists(out_dir):
        if not _plain_dir(out_dir):
            return 3, ".security/handover is not a plain folder"
    else:
        out_dir.mkdir()
    proj = re.sub(r"[^A-Za-z0-9._-]+", "-", root.name).strip("-.")[:40] or "project"
    tag = "" if readiness != "NOT READY" else "-NOT-READY"
    zpath = out_dir / f"{proj}-handover-{now.strftime('%Y%m%d-%H%M%S')}{tag}.zip"
    if os.path.lexists(zpath):
        return 3, f"{zpath.name} already exists"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n in sorted(members):
            z.writestr(zipfile.ZipInfo(n, date_time=now.timetuple()[:6]), members[n])
    fd = os.open(zpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(buf.getvalue())
    msg = [f"Wrote {zpath}", f"Pack SHA-256: {sha(buf.getvalue())}  (send this to the security team by a separate channel)",
           f"Tested commit: {git['commit']}" + (f" plus {git['uncommitted_files']} uncommitted file(s)" if git.get("uncommitted_files") else ""),
           f"Gate verdict: {model['verdict']}. Handover readiness: {readiness} (" + "; ".join(manifest["readiness_why"][:6]) + ")"]
    msg += [f"NOTE: {n}" for n in notes]
    return (1 if readiness == "NOT READY" else 0), "\n".join(msg)


def _members_of(pack: Path) -> dict[str, bytes] | None:
    """Every file of a pack by name, read in memory. Nothing is extracted to disk, so a hostile zip has no path to
    write to. Names with folders, odd characters or duplicates, too many or too large members: refused."""
    out: dict[str, bytes] = {}
    try:
        if pack.is_dir():
            if not _plain_dir(pack):
                return None
            names = sorted(os.listdir(pack))
            if len(names) > MAX_MEMBERS:
                return None
            for n in names:
                b = _read_plain(pack / n) if SAFE_NAME.match(n) else None
                if b is None:
                    return None
                out[n] = b
            return out
        if os.lstat(pack).st_size > MAX_TOTAL:
            return None
        with zipfile.ZipFile(pack) as z:
            infos = z.infolist()
            if len(infos) > MAX_MEMBERS or sum(i.file_size for i in infos) > MAX_TOTAL:
                return None
            for i in infos:
                if not SAFE_NAME.match(i.filename) or i.filename in out or i.file_size > MAX_FILE:
                    return None
                with z.open(i) as fh:
                    b = fh.read(MAX_FILE + 1)
                if len(b) > MAX_FILE:
                    return None
                out[i.filename] = b
        return out
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError, NotImplementedError):
        return None


def verify(pack: Path, expect: str | None = None) -> tuple[int, str]:
    members = _members_of(pack)
    if members is None:
        return 2, "the pack could not be read safely (not a pack, unexpected file names, or too large)"
    problems = []
    mb = members.get("MANIFEST.json")
    if mb is None:
        return 1, "FAIL: no MANIFEST.json in the pack"
    side = members.get("MANIFEST.sha256", b"").decode("ascii", "replace").split()
    if not side or side[0] != sha(mb):
        problems.append("MANIFEST.sha256 does not match MANIFEST.json")
    try:
        manifest = json.loads(mb.decode("ascii", "replace"))
        files = manifest["files"]
        # a listed name is printed below, so it must be a plain file name: no control characters, no path
        listed = {f["name"]: f for f in files if isinstance(f, dict) and isinstance(f.get("name"), str) and SAFE_NAME.match(f["name"])}
        if not isinstance(files, list) or len(listed) != len(files) or len(files) > MAX_MEMBERS:
            raise ValueError
    except (ValueError, KeyError, TypeError, RecursionError):
        return 1, "FAIL: MANIFEST.json is not readable"
    for n, f in sorted(listed.items()):
        b = members.get(n)
        if b is None:
            problems.append(f"{n} is listed but missing")
        elif sha(b) != f.get("sha256") or len(b) != f.get("bytes"):
            problems.append(f"{n} does not match the manifest")
    for n in sorted(set(members) - set(listed) - {"MANIFEST.json", "MANIFEST.sha256"}):
        problems.append(f"{n} is in the pack but not in the manifest")
    for n in CORE:
        if n not in listed:
            problems.append(f"{n} is not in the pack; this is not a complete handover pack")
    try:                                # the readiness in the manifest must be the one the report inside states
        st = json.loads(members.get("report-state.json", b"{}").decode("ascii", "replace"))
        if isinstance(st, dict) and st.get("readiness") != manifest.get("readiness"):
            problems.append("the manifest and report-state.json state a different readiness")
        ready = manifest.get("readiness")
        shown = members.get("REPORT.md", b"").decode("utf-8", "replace").replace("*", "")
        # the report prints a readiness line only for a project that keeps a coverage file; when it does, it must agree
        if isinstance(ready, str) and "Handover readiness:" in shown and f"Handover readiness: {ready}." not in shown:
            problems.append("REPORT.md does not state the readiness the manifest gives")
    except (ValueError, RecursionError):
        problems.append("report-state.json is not readable")
    own = sha(pack.read_bytes()) if pack.is_file() else None
    git = manifest.get("git") if isinstance(manifest.get("git"), dict) else {}
    head = (f"Pack SHA-256: {own}\n" if own else "") + \
        f"Built {scrub(str(manifest.get('built')))[:30]} from commit {scrub(str(git.get('commit')))[:70]}; " \
        f"readiness {scrub(str(manifest.get('readiness')))[:40]}; {len(listed)} file(s)."
    if expect is not None:
        want = expect.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", want):
            return 2, "--expect-sha256 takes the 64 hex characters the builder printed"
        if own is None:
            problems.append("--expect-sha256 needs the zip file, not a folder")
        elif own != want:
            problems.append("the pack's SHA-256 is not the one you were sent: this is not the pack that was built")
    if problems:
        return 1, head + "\nFAIL:\n" + "\n".join(f"- {p}" for p in problems[:50])
    if expect is None:
        return 0, head + ("\nCONSISTENT: every file matches the pack's own manifest. That does not show the pack is the one that "
                          "was built: someone who edits a file and the manifest together gets the same result. Check it against "
                          "the SHA-256 the developer sent you separately: --expect-sha256 <hash>.")
    return 0, head + "\nPASS: this is the pack with the SHA-256 you were sent, and every file matches its manifest."


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build or verify the security handover pack.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--sbom", action="store_true", help="write a CycloneDX SBOM with Trivy first, when it is installed")
    ap.add_argument("--pdf", action="store_true", help="also print the report to PDF with a local Chromium or Edge")
    ap.add_argument("--verify", metavar="PACK", default=None, help="check a pack (zip or folder) against its manifest")
    ap.add_argument("--expect-sha256", metavar="HASH", default=None, help="with --verify: the pack hash you were sent separately")
    a = ap.parse_args(argv)
    R.safe_stdout()
    if a.verify:
        code, msg = verify(Path(a.verify), a.expect_sha256)
    elif a.expect_sha256:
        code, msg = 2, "--expect-sha256 goes with --verify"
    else:
        code, msg = build(Path(a.root).resolve(), a.sbom, a.pdf)
    print(msg)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
