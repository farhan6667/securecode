#!/usr/bin/env python3
"""Org AI stop gate (Claude Code Stop hook).

When the agent is about to finish, scan the files changed in this git working tree with the
quick heuristics, agent-config and library checks. If a High or Critical finding is open, send
the agent back once to fix it (or explain why it is a false positive). It never blocks twice in a
row (stop_hook_active), so it cannot trap the session. Errors exit 0 silently: this is a
safety net, the full gate is still secgate.py --mode ci.
"""
import json, os, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # hooks run with python -I
from secgate import local_scan, agent_scan, library_scan, config_scan, SEV, find_tool

MAX_FILES = 300
MAX_FILE_BYTES = 2_000_000      # skip generated/minified giants
MAX_TOTAL_BYTES = 20_000_000
TIME_BUDGET = 45                # seconds; the hook timeout is 90, the session must never wait on us


def changed_files(root: Path):
    exe = find_tool("git")              # never a git.exe planted in the project folder
    if not exe:
        return []

    def git(*args):
        p = subprocess.run([exe, *args], cwd=str(root), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=20)
        return p.stdout.splitlines() if p.returncode == 0 else []
    if not git("rev-parse", "--is-inside-work-tree"):
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


def main() -> int:
    try:
        event = json.loads(sys.stdin.read())
        if event.get("stop_hook_active"):
            return 0
        root = Path(event.get("cwd") or os.getcwd()).resolve()
        os.chdir(root)   # config_scan resolves web-root folders relative to the project
        findings, total, start = [], 0, time.time()
        for fp in changed_files(root):
            size = fp.stat().st_size
            if size > MAX_FILE_BYTES:
                continue
            total += size
            if total > MAX_TOTAL_BYTES or time.time() - start > TIME_BUDGET:
                break
            findings += local_scan(fp) + agent_scan(fp) + library_scan(fp) + config_scan(fp)
    except Exception:
        return 0
    serious = [f for f in findings if SEV.get(f["severity"], 9) <= SEV["HIGH"]]
    if not serious:
        return 0
    lines = [f"- [{f['severity']}] {f['rule']} {Path(f['file']).name}:{f.get('line', 0)}: {f['message'][:160]}" for f in serious[:15]]
    reason = ("Org AppSec stop gate: changed files still have High/Critical findings. Fix them (or explain "
              "clearly why each is a false positive), then finish. Run 'Security Test Karo' for the full gate.\n" + "\n".join(lines))
    print(json.dumps({"decision": "block", "reason": reason}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
