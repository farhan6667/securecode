#!/usr/bin/env python3
"""PostToolUse edit hook: the quick gate on the one file that changed, advisory only.

Smart mode (7.1): it costs the agent nothing while code is clean. A clean result prints nothing (no context is
added to the model) and clean content is not checked twice (a small cache in the app folder, never in the
project); a High or Critical finding adds a short note with only those lines, every time that content is checked.
Deep review belongs to "Run Security Test"; blocking belongs to the Stop gate and to CI.
SECURECODE_HOOK_VERBOSE=1 restores the full report after every edit.
"""
import hashlib, json, os, stat, subprocess, sys, time
from pathlib import Path

CACHE_MAX = 400                 # entries; the oldest go first
FILE_MAX = 2_000_000            # bigger files are not hashed (and the quick gate skips them anyway)


def cache_dir() -> Path:
    """The app folder's cache (never the project): a cloned repository cannot plant or read what is in it."""
    d = os.environ.get("SECURECODE_CACHE_DIR")
    return Path(d) if d and os.path.isabs(d) else Path(__file__).resolve().parent.parent / "cache"


def cache_file() -> Path:
    return cache_dir() / "edit-hook.json"


def _plain(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and not (getattr(st, "st_file_attributes", 0) & 0x400) and st.st_nlink <= 1


def load_cache(f: Path) -> dict:
    try:
        if not _plain(f) or not f.exists() or f.stat().st_size > 1_000_000:
            return {}
        v = json.loads(f.read_text(encoding="utf-8"))
        return {k: x for k, x in v.items() if isinstance(k, str) and isinstance(x, dict)} if isinstance(v, dict) else {}
    except Exception:
        return {}


def save_cache(f: Path, data: dict, cap: int = CACHE_MAX) -> None:
    """Best effort, never through a link; a failure only means the next edit is checked again."""
    try:
        d = f.parent
        if os.path.lexists(d):
            st = os.lstat(d)
            if not stat.S_ISDIR(st.st_mode) or (getattr(st, "st_file_attributes", 0) & 0x400) or stat.S_ISLNK(st.st_mode):
                return
        else:
            d.mkdir(parents=True)
        if not _plain(f):
            return
        keep = dict(sorted(data.items(), key=lambda kv: kv[1].get("t", 0) if isinstance(kv[1].get("t"), int) else 0)[-cap:])
        tmp = d / (f.name + f".{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(json.dumps(keep).encode("utf-8"))
        os.replace(tmp, f)
    except Exception:
        pass


def serious_only(out: str) -> str:
    """The gate's header, counts and result lines plus only the High and Critical findings."""
    lines = out.splitlines()
    head = [ln for ln in lines if ln.startswith(("=== ", "Mode:", "Counts:"))][:3]
    bad = [ln[:400] for ln in lines if ln.startswith(("[CRITICAL]", "[HIGH]"))]
    bad.sort(key=lambda ln: 0 if ln.startswith("[CRITICAL]") else 1)
    tail = [ln for ln in lines if ln.startswith("RESULT:")][-1:]
    more = [f"... and {len(bad) - 30} more High/Critical lines (run the full gate for all)"] if len(bad) > 30 else []
    return "\n".join(head + bad[:30] + more + tail)


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0
    if not isinstance(event, dict):
        return 0
    cwd = event.get("cwd")
    cwd = cwd if isinstance(cwd, str) and cwd else os.getcwd()
    try:
        root = Path(cwd).resolve()
    except Exception:
        return 0
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0
    file_path = tool_input.get("file_path") or tool_input.get("path")
    # Only the changed file. Falling back to the whole working folder made every edit outside it
    # (for example a session started in the home folder) scan the entire home folder and time out.
    if not isinstance(file_path, str) or not file_path:
        return 0
    try:
        target = Path(file_path).resolve()
    except Exception:
        return 0
    if not target.is_file():
        return 0
    if not (target == root or root in target.parents):
        root = target.parent
    runner = Path(__file__).resolve().parent / "secgate.py"
    if not runner.exists():
        return 0
    verbose = os.environ.get("SECURECODE_HOOK_VERBOSE") == "1"
    key = hashlib.sha256(str(target).encode("utf-8", "replace")).hexdigest()[:24]
    digest = ""
    try:
        if target.stat().st_size <= FILE_MAX:
            # everything the quick gate's answer depends on: the content, the gate version (an update checks every
            # file again), the project root and its suppressions
            rs = runner.stat()
            h = hashlib.sha256(target.read_bytes())
            h.update(f"|{rs.st_size}:{int(rs.st_mtime)}|{root}|{os.environ.get('SECGATE_SUPPRESSIONS', '')}".encode("utf-8", "replace"))
            sup = root / "config" / "security-suppressions.yaml"
            if sup.is_file() and sup.stat().st_size <= FILE_MAX:
                h.update(sup.read_bytes())
            digest = h.hexdigest()
    except OSError:
        digest = ""
    cf = cache_file()
    cache = load_cache(cf) if digest and not verbose else {}
    if digest and cache.get(key, {}).get("sha") == digest:
        return 0                # this exact content was already checked and found clean
    try:
        p = subprocess.run(
            [sys.executable, "-I", str(runner), str(target), "--mode", "quick", "--fail-on", "high"],
            cwd=str(root), text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=110, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        # Only clean results are remembered: a finding is reported every time its content is checked, so a report
        # one session saw is never hidden from another session or agent.
        if digest and not verbose and p.returncode == 0:
            cache[key] = {"sha": digest, "t": int(time.time()), "rc": 0}
            save_cache(cf, cache)
        if p.returncode == 0 and not verbose:
            return 0            # clean (nothing at or above High): silent, no tokens spent
        if p.returncode not in (0, 2) and not verbose:
            text = f"The quick gate could not run on this file (exit {p.returncode}); it was not checked."
        else:
            text = p.stdout[-9000:].strip() if verbose else serious_only(p.stdout)   # filter first, then cut
        if not text:
            return 0
        payload = {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                   "additionalContext": "Org AppSec quick gate on the changed file (advisory; fix High/Critical before you finish):\n" + text}}
        print(json.dumps(payload))
        return 0
    except Exception as e:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                          "additionalContext": f"Org AppSec hook error (non-blocking): {e}"}}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
