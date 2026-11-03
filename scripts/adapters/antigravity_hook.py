#!/usr/bin/env python3
"""Antigravity adapter for the Org AI agent guard (PreToolUse hook).

Antigravity hook contract, checked against https://antigravity.google/docs/hooks on 2026-11-03:
- Hooks live in <workspace>/.agents/hooks.json or the global ~/.gemini/config/hooks.json (App, CLI and IDE):
  {"<hook name>": {"PreToolUse": [{"matcher": "<regex on the tool name>", "hooks": [{"type": "command",
  "command": "...", "timeout": <seconds>}]}]}}. /hooks in the CLI lists what is loaded.
- PreToolUse stdin: toolCall.name, toolCall.args, stepIdx, plus conversationId, workspacePaths (absolute),
  transcriptPath, artifactDirectoryPath, modelName. There is no top-level cwd.
- Built-in tools (argument names are PascalCase): run_command {CommandLine, Cwd}, write_to_file {TargetFile},
  replace_file_content and multi_replace_file_content {TargetFile}, view_file {AbsolutePath}, list_dir
  {DirectoryPath}, find_by_name {SearchDirectory, Pattern}, grep_search {SearchPath, Query}, read_url_content
  {Url}, search_web {query}.
- Output on stdout: {"decision": "allow" | "auto_approve" | "deny" | "ask" | "force_ask" | ..., "reason": ...}.
  "allow" hands over to the next hook or the default policy (it is not a hard allow), which is what the guard wants.
  A guard "ask" is sent as "force_ask", so a cached "Always Allow" for the tool cannot skip it.
- Exit codes, timeouts and crashes are NOT documented; only the JSON decision is. So this adapter always exits 0 and
  puts the decision in that JSON, with an explicit "deny" on every error path (a non-zero exit might be read as
  "the hook failed" and let the tool run). Whether Antigravity blocks when the hook itself crashes or times out is
  untested.
"""
from __future__ import annotations
import json, os, re, shlex, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # scripts/ (hooks run with -I)
import agent_guard as G  # noqa: E402

MAX_INPUT = 2_000_000


def _s(v, what):
    if not isinstance(v, str) or not v:
        raise ValueError(f"{what} missing")
    return v


def _workspace(payload: dict) -> str | None:
    ws = payload.get("workspacePaths")
    if isinstance(ws, list) and ws and isinstance(ws[0], str) and ws[0]:
        return ws[0]
    return None


def to_guard_events(payload: dict) -> list[dict]:
    """The guard events for one PreToolUse call. Raises ValueError on anything it cannot read (the caller denies)."""
    call = payload.get("toolCall")
    if not isinstance(call, dict):
        raise ValueError("toolCall missing")
    tool = _s(call.get("name"), "toolCall.name")
    args = call.get("args")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ValueError("toolCall.args is not an object")
    cwd = _workspace(payload) or os.getcwd()

    def ev(name, inp, where=cwd):
        return {"tool_name": name, "tool_input": inp, "cwd": where}

    if tool == "run_command":
        cmd = _s(args.get("CommandLine"), "CommandLine")
        c = args.get("Cwd")
        if c is not None and not isinstance(c, str):
            raise ValueError("Cwd is not text")
        # The model chooses Cwd, so it must not become a trusted project root: the guard sees an explicit cd into it.
        # On Windows the command may run in PowerShell or cmd: judge both shell readings, the stronger one wins.
        return shell_events(cmd, c, cwd)
    if tool == "write_to_file":
        return [ev("Write", {"file_path": _s(args.get("TargetFile"), "TargetFile")})]
    if tool in ("replace_file_content", "multi_replace_file_content"):
        return [ev("Edit", {"file_path": _s(args.get("TargetFile"), "TargetFile")})]
    if tool == "view_file":
        return [ev("Read", {"file_path": _s(args.get("AbsolutePath"), "AbsolutePath")})]
    if tool == "list_dir":
        return [ev("LS", {"path": _s(args.get("DirectoryPath"), "DirectoryPath")})]
    if tool == "find_by_name":
        inp = {"pattern": _s(args.get("Pattern"), "Pattern")}
        if isinstance(args.get("SearchDirectory"), str) and args["SearchDirectory"]:
            inp["path"] = args["SearchDirectory"]
        return [ev("Glob", inp), ev("Grep", {"pattern": "x", "glob": inp["pattern"]})]
    if tool == "grep_search":
        inp = {"pattern": str(args.get("Query") or "")}
        out = []
        if isinstance(args.get("SearchPath"), str) and args["SearchPath"]:
            inp["path"] = args["SearchPath"]
            out.append(ev("Read", {"file_path": args["SearchPath"]}))     # the search path may be one (secret) file
        inc = args.get("Includes")
        if isinstance(inc, str):
            inc = [inc]
        if inc is not None and not (isinstance(inc, list) and all(isinstance(x, str) for x in inc)):
            raise ValueError("Includes is not a list of globs")
        out.append(ev("Grep", inp))
        for g in (inc or [])[:200]:
            out.append(ev("Grep", {"pattern": "x", "glob": g}))
        return out
    if tool == "read_url_content":
        return [ev("WebFetch", {"url": _s(args.get("Url"), "Url")})]
    if tool == "search_web":
        return [ev("WebSearch", {k: v for k, v in args.items() if k == "query"})]
    # MCP tools and anything else: every path-shaped argument is judged (as an MCP argument, so a path outside the
    # project is the "unknown" class), and a CommandLine argument is judged as a shell command.
    name = "mcp__antigravity__" + re.sub(r"[^A-Za-z0-9_.-]", "_", tool)[:100]
    out = [ev(name, args)]
    # CommandLine, and Input sent to a running command (send_command_input), are shell text too.
    for key in ("CommandLine", "Input", "Command", "command"):
        if isinstance(args.get(key), str) and args[key].strip():
            out += shell_events(args[key], None, cwd)
    return out


def shell_events(cmd: str, folder: str | None, cwd: str) -> list[dict]:
    """Guard events for one shell command run in `folder` (chosen by the model). The event cwd stays the workspace;
    the folder change is spelled out as a cd so the guard judges it."""
    bash, ps = cmd, cmd
    if folder:
        bash = f"cd -- {shlex.quote(folder)} && {cmd}"
        ps = "Set-Location -LiteralPath '" + folder.replace("'", "''") + "'; " + cmd
    out = [{"tool_name": "Bash", "tool_input": {"command": bash}, "cwd": cwd}]
    if os.name == "nt":
        out.append({"tool_name": "PowerShell", "tool_input": {"command": ps}, "cwd": cwd})
    return out


def handle(payload: dict, mode: str | None = None) -> dict:
    """Antigravity's JSON answer for one PreToolUse call."""
    final = None
    for e in to_guard_events(payload):
        final = G.stronger(final, G.decide(e, mode))
        if final and final[0] == "deny":
            break
    if not final:
        return {"decision": "allow"}
    decision, reason = final
    msg = f"Org AI agent guard: {reason}"
    return {"decision": "force_ask" if decision == "ask" else "deny", "reason": msg}


def main() -> int:
    try:
        data = sys.stdin.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ValueError("hook input too large")
        payload = json.loads(data)
        if not isinstance(payload, dict):
            raise ValueError("hook input is not an object")
        if not os.environ.get("CLAUDE_PROJECT_DIR") and _workspace(payload):
            os.environ["CLAUDE_PROJECT_DIR"] = _workspace(payload)
        out = handle(payload)
    except Exception as e:
        out = {"decision": "deny", "reason": f"Org AI agent guard: could not check this action safely ({type(e).__name__})."}
    try:
        print(json.dumps(out), flush=True)
    except BaseException:
        return 2                 # nothing could be written; whatever Antigravity does with that, it is not an allow from us
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
