#!/usr/bin/env python3
"""Codex CLI adapter for the Org AI agent guard (PreToolUse hook).

Codex hook contract, checked against https://learn.chatgpt.com/docs/hooks on 2026-11-03:
- Hooks live in ~/.codex/hooks.json, ~/.codex/config.toml ([[hooks.PreToolUse]]), the repo's .codex/ layer
  (only when trusted) or managed requirements.toml. Non-managed hooks run only after the user trusts them
  in /hooks.
- PreToolUse input: common fields (session_id, cwd, hook_event_name, model, permission_mode) plus
  tool_name ("Bash", "apply_patch" or an MCP name such as mcp__fs__read), tool_use_id and tool_input.
  Bash and apply_patch put their text in tool_input.command; MCP tools send their arguments.
- Deny: exit code 2 with the reason on stderr, or exit 0 with hookSpecificOutput.permissionDecision "deny". Any
  other exit code is a failed hook and the tool runs (codex-rs/hooks/src/events/pre_tool_use.rs). On Windows Codex
  runs the hook line in the session shell (PowerShell, cmd or bash; codex-rs/core/src/session/mod.rs), and
  'pwsh -Command' turns exit 2 into 1. So this adapter answers a deny with exit 0 and the JSON (V7L-02), and the
  Windows template line (commandWindows) starts with an unquoted Python path, which every one of those shells runs.
- permissionDecision "ask" is parsed but NOT supported yet: Codex marks the hook failed and runs the tool.
  So every "ask" from the guard is turned into a deny here, with the reason, and the person runs the
  command themselves. Owner mode therefore cannot prompt inside Codex today.
- Codex docs call tool hooks "a useful guardrail, not a complete enforcement boundary"; hosted tools such
  as web search do not pass through PreToolUse.

The Stop hook needs no adapter: scripts/stop_gate.py already speaks Codex's Stop format
({"decision": "block", "reason": ...} and stop_hook_active).
"""
from __future__ import annotations
import json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # scripts/ (hooks run with -I)
import agent_guard as G  # noqa: E402

MAX_INPUT = 2_000_000
PATCH_FILE = re.compile(r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+?)\s*$", re.M)


def to_guard_events(payload: dict) -> list[dict]:
    tool = payload.get("tool_name")
    ti = payload.get("tool_input")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) and payload.get("cwd") else os.getcwd()
    if not isinstance(tool, str) or not tool:
        raise ValueError("tool_name missing")
    if tool == "apply_patch":
        patch = ti.get("command") if isinstance(ti, dict) else ti
        if isinstance(patch, list):
            patch = "\n".join(str(x) for x in patch)
        if not isinstance(patch, str):
            raise ValueError("patch text missing")
        files = PATCH_FILE.findall(patch)
        if not files:
            raise ValueError("no file names found in the patch")
        # Patch paths are relative to the session folder; judge them where they land.
        return [{"tool_name": "Write", "tool_input": {"file_path": f if os.path.isabs(f) else os.path.join(cwd, f)}, "cwd": cwd}
                for f in files[:500]]
    if not isinstance(ti, dict):
        raise ValueError("tool_input is not an object")
    if tool == "Bash":
        cmd = ti.get("command")
        if isinstance(cmd, list) and all(isinstance(x, str) for x in cmd):
            cmd = " ".join(cmd)
        if not isinstance(cmd, str):
            raise ValueError("command missing")
        return [{"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd}]
    return [{"tool_name": tool, "tool_input": ti, "cwd": cwd}]


def handle(payload: dict, mode: str | None = None):
    """(exit_code, stderr_text). Codex cannot ask, so ask becomes deny."""
    final = None
    for ev in to_guard_events(payload):
        final = G.stronger(final, G.decide({**ev, "agent": "codex"}, mode))
        if final and final[0] == "deny":
            break
    if not final:
        return 0, ""
    decision, reason = final
    if decision == "ask":
        return 2, (f"Blocked by Org AI agent guard: this needs the developer's approval and Codex hooks cannot ask yet. "
                   f"{reason} If it is intended, the developer runs it themselves.\n")
    return 2, f"Blocked by Org AI agent guard: {reason}\n"


def deny_json(reason: str) -> str:
    """Codex's JSON deny. Answered with exit 0, because a non-zero exit code does not survive every shell (V7L-02)."""
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                              "permissionDecisionReason": reason.strip() or "Blocked by Org AI agent guard."}})


def main() -> int:
    """Allow: exit 0, no output. Deny (and every error): exit 0 with the JSON deny on stdout, reason also on stderr."""
    try:
        data = sys.stdin.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ValueError("hook input too large")
        payload = json.loads(data)
        if not isinstance(payload, dict):
            raise ValueError("hook input is not an object")
        rc, err = handle(payload)
    except Exception as e:
        rc, err = 2, f"Blocked by Org AI agent guard: could not check this action safely ({type(e).__name__}).\n"
    if rc == 0:
        return 0
    try:
        print(deny_json(err), flush=True)
        sys.stderr.write(err)
    except BaseException:
        return 2                                       # could not answer in JSON: exit 2 still blocks in cmd and sh
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
