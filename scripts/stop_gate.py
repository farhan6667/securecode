#!/usr/bin/env python3
"""Org AI stop gate (Claude Code and Codex Stop hook).

When the agent is about to finish, scan the files changed in this git working tree with the
quick heuristics, agent-config and library checks. If a High or Critical finding is open, send
the agent back once to fix it (or explain why it is a false positive).

It also offers the developer a full security test at the end of substantial work: when the code
changed since the last offer reaches OFFER_FILES code files or OFFER_LINES changed lines, and no
full gate ("Run Security Test", secgate --mode ci or full) has run since those changes, the agent
is sent back once to ask the developer whether to run it now. The offer is recorded in
.security/pentest-offer.json before it is shown, so it comes once per change set and a "no" is
respected until enough new code changes. {"disabled": true} in that file turns it off for a project.

It never blocks twice in a row (stop_hook_active), so it cannot trap the session. Errors exit 0
silently: this is a safety net, the full gate is still secgate.py --mode ci.
"""
from __future__ import annotations
import hashlib, json, os, stat, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # hooks run with python -I
from secgate import local_scan, agent_scan, library_scan, config_scan, SEV, find_tool

MAX_FILES = 300
MAX_FILE_BYTES = 2_000_000      # skip generated/minified giants
MAX_TOTAL_BYTES = 20_000_000
TIME_BUDGET = 45                # seconds; the hook timeout is 90, the session must never wait on us

# Pentest offer threshold: tiny edits never trigger it.
OFFER_FILES = 3                 # changed code files since the last offer, or
OFFER_LINES = 40                # changed lines (added + deleted; an untracked file counts all its lines)
OFFER_MARKER = "pentest-offer.json"
MARKER_MAX = 1_000_000
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".php", ".rb", ".go", ".java", ".kt",
            ".kts", ".scala", ".cs", ".fs", ".vb", ".rs", ".swift", ".m", ".mm", ".c", ".h", ".cc", ".cpp", ".hpp", ".dart",
            ".sql", ".sh", ".bash", ".ps1", ".psm1", ".pl", ".lua", ".ex", ".exs", ".erl", ".clj", ".groovy", ".gradle",
            ".html", ".htm", ".twig", ".erb", ".ejs", ".hbs", ".cshtml", ".razor", ".jsp", ".asp", ".aspx"}


def _git(root: Path):
    exe = find_tool("git")              # never a git.exe planted in the project folder
    if not exe:
        return None

    def git(*args):
        p = subprocess.run([exe, *args], cwd=str(root), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=20)
        return p.stdout.splitlines() if p.returncode == 0 else []
    return git


def changed_files(root: Path):
    git = _git(root)
    if not git or not git("rev-parse", "--is-inside-work-tree"):
        return []
    untracked = set(git("ls-files", "--others", "--exclude-standard"))
    if git("rev-parse", "--verify", "--quiet", "HEAD"):
        names = set(git("diff", "--name-only", "HEAD")) | untracked
    else:                               # a new repo with no commit yet: staged plus untracked files
        names = set(git("diff", "--cached", "--name-only")) | untracked
    out = []
    for n in sorted(names)[:MAX_FILES]:
        fp = (root / n)
        if fp.is_file():
            out.append(fp)
    return out


def line_counts(root: Path) -> dict:
    """Changed lines per path (relative, "/" separated): added + deleted from git numstat, all lines of
    untracked files."""
    git = _git(root)
    if not git:
        return {}
    base = ["diff", "--numstat", "HEAD"] if git("rev-parse", "--verify", "--quiet", "HEAD") else ["diff", "--numstat", "--cached"]
    out = {}
    for row in git(*base):
        parts = row.split("\t")
        if len(parts) == 3:
            a, d, name = parts
            out[name] = (int(a) if a.isdigit() else 0) + (int(d) if d.isdigit() else 0)
    for name in git("ls-files", "--others", "--exclude-standard"):
        fp = root / name
        try:
            if fp.is_file() and fp.stat().st_size <= MAX_FILE_BYTES:
                with open(fp, "rb") as fh:
                    out[name] = fh.read().count(b"\n") + 1
        except OSError:
            pass
    return out


def _digest(fp: Path) -> str:
    st = fp.stat()
    if st.st_size > MAX_FILE_BYTES:
        return f"size:{st.st_size}:{int(st.st_mtime)}"
    return hashlib.sha256(fp.read_bytes()).hexdigest()


def _plain(st) -> bool:
    return not stat.S_ISLNK(st.st_mode) and not (getattr(st, "st_file_attributes", 0) & 0x400)


def _read_marker(f: Path) -> dict:
    try:
        st = os.lstat(f)
        if not stat.S_ISREG(st.st_mode) or not _plain(st) or st.st_size > MARKER_MAX:
            return {"_unusable": True}
        data = json.loads(f.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"_unusable": True}
    except FileNotFoundError:
        return {}
    except Exception:
        return {"_unusable": True}


def _write_marker(root: Path, data: dict) -> bool:
    """Write .security/pentest-offer.json, refusing links and junctions (a hostile repo must not redirect it)."""
    try:
        d = root / ".security"
        if os.path.lexists(d):
            st = os.lstat(d)
            if not stat.S_ISDIR(st.st_mode) or not _plain(st):
                return False
        else:
            d.mkdir()
        f = d / OFFER_MARKER
        if os.path.lexists(f):
            st = os.lstat(f)
            if not stat.S_ISREG(st.st_mode) or not _plain(st) or st.st_nlink > 1:
                return False
        tmp = d / (OFFER_MARKER + ".tmp")
        if os.path.lexists(tmp):
            os.unlink(tmp)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write((json.dumps(data, indent=1) + "\n").encode("utf-8"))
        os.replace(tmp, f)
        return True
    except Exception:
        return False


def _security_test_since(root: Path, newest_change: float) -> bool:
    """True when a full gate (ci or full mode) wrote .security/findings.json after the newest change."""
    f = root / ".security" / "findings.json"
    try:
        st = os.lstat(f)
        if not stat.S_ISREG(st.st_mode) or not _plain(st) or st.st_size > 50_000_000 or st.st_mtime < newest_change:
            return False
        return json.loads(f.read_text(encoding="utf-8")).get("mode") in ("ci", "full")
    except Exception:
        return False


def pentest_offer(root: Path, files: list) -> str | None:
    """The one-time offer text, or None. Records the offer before returning it."""
    marker = _read_marker(root / ".security" / OFFER_MARKER)
    if marker.get("_unusable") or marker.get("disabled") is True:
        return None                     # an unreadable marker must not turn into an offer on every stop
    snap = marker.get("snapshot") if isinstance(marker.get("snapshot"), dict) else {}
    code = []
    for fp in files:
        try:
            rel = fp.relative_to(root).as_posix()
        except ValueError:
            continue
        if fp.suffix.lower() in CODE_EXT and not rel.startswith(".security/"):
            code.append((rel, fp))
    if not code:
        return None
    current = {rel: _digest(fp) for rel, fp in code}
    delta = [rel for rel in current if snap.get(rel) != current[rel]]
    if not delta:
        return None
    lines = line_counts(root)
    delta_lines = sum(lines.get(rel, 0) for rel in delta)
    if len(delta) < OFFER_FILES and delta_lines < OFFER_LINES:
        return None
    newest = max((root / rel).stat().st_mtime for rel in delta)
    if _security_test_since(root, newest):
        return None
    record = {"snapshot": current, "offered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "files": len(delta), "lines": delta_lines,
              "note": "One offer per change set. Set \"disabled\": true to stop these offers in this project."}
    if not _write_marker(root, record):
        return None                     # if we cannot remember the offer, do not risk asking at every stop
    return ("Org AppSec: before you finish, offer the developer a full security test. This work changed "
            f"{len(delta)} code file(s) (about {delta_lines} lines) and no full security test has run since. Ask one "
            "short question, for example: \"Do you want me to run a full security test now (Run Security Test)? It "
            "reviews the changed code for access control, IDOR, injection and the other common pentest findings.\" "
            "If they say yes, run the org-appsec-security skill (Mode B). If they say no or later, accept it and "
            "finish; you will not be asked again for these changes. Do not start the test without their yes.")


def main() -> int:
    try:
        event = json.loads(sys.stdin.read())
        if event.get("stop_hook_active"):
            return 0
        root = Path(event.get("cwd") or os.getcwd()).resolve()
        os.chdir(root)   # config_scan resolves web-root folders relative to the project
        findings, total, start = [], 0, time.time()
        files = changed_files(root)
        for fp in files:
            size = fp.stat().st_size
            if size > MAX_FILE_BYTES:
                continue
            total += size
            if total > MAX_TOTAL_BYTES or time.time() - start > TIME_BUDGET:
                break
            findings += local_scan(fp) + agent_scan(fp) + library_scan(fp) + config_scan(fp)
    except Exception:
        return 0
    try:
        offer = pentest_offer(root, files)
    except Exception:
        offer = None
    serious = [f for f in findings if SEV.get(f["severity"], 9) <= SEV["HIGH"]]
    parts = []
    if serious:
        lines = [f"- [{f['severity']}] {f['rule']} {Path(f['file']).name}:{f.get('line', 0)}: {f['message'][:160]}" for f in serious[:15]]
        parts.append("Org AppSec stop gate: changed files still have High/Critical findings. Fix them (or explain "
                     "clearly why each is a false positive), then finish. Run 'Run Security Test' for the full gate.\n" + "\n".join(lines))
    if offer:
        parts.append(offer)
    if not parts:
        return 0
    print(json.dumps({"decision": "block", "reason": "\n\n".join(parts)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
