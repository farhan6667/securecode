#!/usr/bin/env python3
import json, os, subprocess, sys
from pathlib import Path

def main():
    try:
        event=json.load(sys.stdin)
    except Exception:
        return 0
    if not isinstance(event,dict):
        return 0
    cwd=event.get("cwd")
    cwd=cwd if isinstance(cwd,str) and cwd else os.getcwd()
    try:
        root=Path(cwd).resolve()
    except Exception:
        return 0
    tool_input=event.get("tool_input") if isinstance(event,dict) else None
    if not isinstance(tool_input,dict):
        return 0
    file_path=tool_input.get("file_path") or tool_input.get("path")
    # Only the changed file. Falling back to the whole working folder made every edit outside it
    # (for example a session started in the home folder) scan the entire home folder and time out.
    if not isinstance(file_path,str) or not file_path:
        return 0
    try:
        target=Path(file_path).resolve()
    except Exception:
        return 0
    if not target.is_file():
        return 0
    if not (target == root or root in target.parents):
        root=target.parent
    runner=Path(__file__).resolve().parent/"secgate.py"
    if not runner.exists():
        return 0
    try:
        p=subprocess.run(
            [sys.executable,"-I",str(runner),str(target),"--mode","quick","--fail-on","high"],
            cwd=str(root),text=True,encoding="utf-8",errors="replace",stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=110,
            env={**os.environ,"PYTHONIOENCODING":"utf-8"}
        )
        out=p.stdout[-9000:].strip()
        if not out:
            return 0
        # Advisory only: the agent sees the result after every edit, but the edit is never blocked here.
        # Heuristics on one half-written file are noisy; blocking belongs to the Stop gate and to CI.
        payload={
            "hookSpecificOutput":{
                "hookEventName":"PostToolUse",
                "additionalContext":"Org AppSec quick gate result for changed file (advisory, fix High/Critical before you finish):\n"+out
            }
        }
        print(json.dumps(payload))
        return 0
    except Exception as e:
        print(json.dumps({"hookSpecificOutput":{
            "hookEventName":"PostToolUse",
            "additionalContext":f"Org AppSec hook error (non-blocking): {e}"
        }}))
        return 0

if __name__=="__main__":
    raise SystemExit(main())
