#!/usr/bin/env python3
"""Cursor adapter for the Org AI agent guard.

Cursor hook contract, checked against https://cursor.com/docs/hooks on 2026-11-03:
- hooks.json ("version": 1) at ~/.cursor/hooks.json (user), <project>/.cursor/hooks.json (project) or the
  enterprise file (Windows C:\\ProgramData\\Cursor\\hooks.json, macOS /Library/Application Support/Cursor/
  hooks.json, Linux /etc/cursor/hooks.json). Deny beats ask beats allow across all sources.
- Every hook gets JSON on stdin with common fields (conversation_id, hook_event_name, workspace_roots, ...).
- beforeShellExecution: {"command", "cwd", "sandbox"} -> {"permission": "allow"|"deny"|"ask",
  "user_message", "agent_message"}.
- beforeMCPExecution: {"tool_name", "tool_input" (a JSON string), "mcp_server_name", "url" or "command"}
  -> the same permission output.
- beforeReadFile: {"file_path", "content", "attachments": [{"type", "file_path"}]} -> {"permission":
  "allow"|"deny", "user_message"}. "ask" is not part of this hook's schema, so an ask becomes a deny here.
- Exit code 2 blocks; invalid JSON output blocks a permission hook; crashes and timeouts fail open unless the
  hook entry sets "failClosed": true. The template in templates/cursor/hooks.json sets it.
Cursor's generic preToolUse hook is not wired to the guard yet, so Cursor's own file edits are not checked.
Checked again on 2026-11-03 (https://cursor.com/docs/agent/hooks): preToolUse exists and lists Write and Delete as
matcher values, but the page documents neither the tool_input fields of those tools nor whether the hook runs
before the edit is applied, so wiring it now could deny every edit or miss them. OPEN-02 tracks this.

The adapter turns each Cursor event into the Claude Code tool event the guard already understands and
returns the guard's decision under the same owner/managed policy. The file content Cursor sends with
beforeReadFile is ignored and never logged.
"""
from __future__ import annotations
import json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # scripts/ (hooks run with -I)
import agent_guard as G  # noqa: E402

MAX_INPUT = 2_000_000


def _cwd(payload: dict) -> str:
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        return cwd
    roots = payload.get("workspace_roots")
    if isinstance(roots, list) and roots and isinstance(roots[0], str) and roots[0]:
        return roots[0]
    return os.getcwd()


def _safe_name(v) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", v)[:100] if isinstance(v, str) and v else "unknown"


def to_guard_events(payload: dict) -> list[dict]:
    """The guard events for one Cursor hook call. Raises ValueError on anything it cannot read, so the
    caller denies (fail closed)."""
    name = payload.get("hook_event_name")
    cwd = _cwd(payload)
    if name == "beforeShellExecution":
        cmd = payload.get("command")
        if not isinstance(cmd, str):
            raise ValueError("command missing")
        return [{"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd}]
    if name == "beforeMCPExecution":
        raw = payload.get("tool_input")
        if isinstance(raw, str):
            ti = json.loads(raw) if raw.strip() else {}
        elif isinstance(raw, dict) or raw is None:
            ti = raw or {}
        else:
            raise ValueError("tool_input is not JSON")
        if not isinstance(ti, dict):
            raise ValueError("tool_input is not an object")
        tool = f"mcp__{_safe_name(payload.get('mcp_server_name'))}__{_safe_name(payload.get('tool_name'))}"
        return [{"tool_name": tool, "tool_input": ti, "cwd": cwd}]
    if name == "beforeReadFile":
        paths = [payload.get("file_path")]
        for a in payload.get("attachments") or []:
            if isinstance(a, dict):
                paths.append(a.get("file_path"))
        if not isinstance(paths[0], str) or not paths[0]:
            raise ValueError("file_path missing")
        return [{"tool_name": "Read", "tool_input": {"file_path": p}, "cwd": cwd} for p in paths if isinstance(p, str) and p]
    raise ValueError(f"unsupported hook event {name!r}")


def handle(payload: dict, mode: str | None = None) -> dict:
    """Cursor's JSON answer for one hook call."""
    name = payload.get("hook_event_name")
    final = None
    for ev in to_guard_events(payload):
        final = G.stronger(final, G.decide(ev, mode))
        if final and final[0] == "deny":
            break
    if not final:
        return {"permission": "allow"}
    decision, reason = final
    if decision == "ask" and name == "beforeReadFile":
        decision, reason = "deny", reason + " (Cursor cannot ask before a file read, so this read is refused; open the file yourself if needed.)"
    msg = f"Org AI agent guard: {reason}"
    return {"permission": decision if decision in ("ask", "deny") else "deny", "user_message": msg, "agent_message": msg}


def main() -> int:
    try:
        data = sys.stdin.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ValueError("hook input too large")
        payload = json.loads(data)
        if not isinstance(payload, dict):
            raise ValueError("hook input is not an object")
        out = handle(payload)
    except Exception as e:
        msg = f"Org AI agent guard: could not check this action safely ({type(e).__name__})."
        print(json.dumps({"permission": "deny", "user_message": msg, "agent_message": msg}))
        return 2
    print(json.dumps(out))
    return 2 if out["permission"] == "deny" else 0


if __name__ == "__main__":
    raise SystemExit(main())
