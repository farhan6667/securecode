#!/usr/bin/env python3
"""Gemini CLI adapter for the Org AI agent guard (BeforeTool hook).

Gemini CLI hook contract, checked against https://geminicli.com/docs/hooks/, .../docs/hooks/reference/ and
.../docs/reference/tools/ on 2026-11-03:
- settings.json (project .gemini/settings.json, user ~/.gemini/settings.json, system /etc/gemini-cli/settings.json):
  {"hooks": {"BeforeTool": [{"matcher": "<regex on the tool name>", "hooks": [{"type": "command", "command": "...",
  "timeout": <ms>}]}]}}. Project hooks are fingerprinted and must be trusted again when they change.
- BeforeTool stdin: session_id, transcript_path, cwd, hook_event_name, timestamp, tool_name, tool_input (the raw model
  arguments), mcp_context (MCP tools only).
- Built-in tools: run_shell_command {command, dir_path}, write_file {file_path, content}, replace {file_path, ...},
  read_file {file_path}, read_many_files {include, exclude}, glob {pattern, dir_path}, grep_search (legacy
  search_file_content) {pattern, dir_path, include_pattern}, list_directory {dir_path}, web_fetch {prompt},
  google_web_search {query}. MCP tools are named mcp_<server>_<tool>.
- Exit 2 blocks the tool and uses stderr as the reason. Exit 0 with {"decision": "deny", "reason": ...} also blocks.
  Any other exit code, and stdout that is not JSON, ALLOW the tool (fail open). So this adapter only ever exits 0
  (allow) or 2 (deny), and every error path exits 2.
- There is no "ask" decision. An "ask" from the guard becomes a deny with the reason, and the person runs the
  command themselves (as with Codex).
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


def _opt(ti, key):
    v = ti.get(key)
    if v is None or v == "":
        return None
    if not isinstance(v, str):
        raise ValueError(f"{key} is not text")
    return v


def shell_events(cmd: str, folder: str | None, cwd: str) -> list[dict]:
    """Guard events for one shell command that the tool runs in `folder` (chosen by the model). The event cwd
    stays the session folder; the folder change is spelled out as a cd so the guard judges it."""
    bash, ps = cmd, cmd
    if folder:
        bash = f"cd -- {shlex.quote(folder)} && {cmd}"
        ps = "Set-Location -LiteralPath '" + folder.replace("'", "''") + "'; " + cmd
    out = [{"tool_name": "Bash", "tool_input": {"command": bash}, "cwd": cwd}]
    if os.name == "nt":
        out.append({"tool_name": "PowerShell", "tool_input": {"command": ps}, "cwd": cwd})
    return out


def _mcp_name(tool: str, payload: dict) -> str:
    ctx = payload.get("mcp_context") if isinstance(payload.get("mcp_context"), dict) else {}
    server = ctx.get("server_name") or ctx.get("serverName") or "gemini"
    rest = tool[4:]
    if isinstance(server, str) and rest.startswith(server + "_"):
        rest = rest[len(server) + 1:]
    safe = lambda v: re.sub(r"[^A-Za-z0-9_.-]", "_", v)[:100] or "unknown"   # noqa: E731
    return f"mcp__{safe(str(server))}__{safe(rest)}"


def to_guard_events(payload: dict) -> list[dict]:
    """The guard events for one BeforeTool call. Raises ValueError on anything it cannot read (the caller denies)."""
    tool = _s(payload.get("tool_name"), "tool_name")
    ti = payload.get("tool_input")
    if not isinstance(ti, dict):
        raise ValueError("tool_input is not an object")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) and payload.get("cwd") else os.getcwd()

    def ev(name, inp, where=cwd):
        return {"tool_name": name, "tool_input": inp, "cwd": where}

    if tool == "run_shell_command":
        cmd = _s(ti.get("command"), "command")
        d = _opt(ti, "dir_path")
        # The model chooses dir_path, so it must not become a trusted project root: the guard sees an explicit cd
        # into it and judges that move like any other. On Windows Gemini CLI runs commands through PowerShell, and
        # people paste either kind: judge both readings, the stronger one wins.
        return shell_events(cmd, d, cwd)
    if tool == "write_file":
        return [ev("Write", {"file_path": _s(ti.get("file_path"), "file_path")})]
    if tool == "replace":
        return [ev("Edit", {"file_path": _s(ti.get("file_path"), "file_path")})]
    if tool == "read_file":
        return [ev("Read", {"file_path": _s(ti.get("file_path"), "file_path")})]
    if tool == "read_many_files":
        entries = []
        for key in ("paths", "include"):                # both are read when both are given
            v = ti.get(key)
            if v is None:
                continue
            if isinstance(v, str):
                v = [v]
            if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
                raise ValueError(f"{key} is not a list of paths")
            entries += v
        if not entries:
            raise ValueError("read_many_files names no paths")
        # Each entry may be a file or a glob: judge it both ways, so a secret name or a protected place is caught.
        out = []
        for x in entries[:500]:
            out.append(ev("Read", {"file_path": x}))
            out.append(ev("Grep", {"pattern": "x", "glob": x}))
        return out
    if tool == "glob":
        inp = {"pattern": _s(ti.get("pattern"), "pattern")}
        where = _opt(ti, "dir_path") or _opt(ti, "path")
        if where:
            inp["path"] = where
        return [ev("Glob", inp), ev("Grep", {"pattern": "x", "glob": inp["pattern"]})]
    if tool in ("grep_search", "search_file_content"):
        inp = {"pattern": _s(ti.get("pattern"), "pattern")}
        where = _opt(ti, "dir_path") or _opt(ti, "path")
        if where:
            inp["path"] = where
        inc = _opt(ti, "include_pattern") or _opt(ti, "include")
        if inc:
            inp["glob"] = inc
        out = [ev("Grep", inp)]
        if where:
            out.append(ev("Read", {"file_path": where}))     # a search path may be a single (secret) file
        return out
    if tool == "list_directory":
        return [ev("LS", {"path": _s(ti.get("dir_path") or ti.get("path"), "dir_path")})]
    if tool == "web_fetch":
        return [ev("WebFetch", {k: v for k, v in ti.items() if k in ("prompt", "url")})]
    if tool == "google_web_search":
        return [ev("WebSearch", {k: v for k, v in ti.items() if k == "query"})]
    if tool.startswith("mcp_"):
        return [ev(_mcp_name(tool, payload), ti)]
    # Any other tool (edit, save_memory, write_todos, an extension's tool) is judged like an MCP tool: every
    # path-shaped argument, a path outside the project is the "unknown" class, and a command argument is a shell
    # command. The prefix keeps a name like "Read" from passing for a built-in Claude Code tool.
    out = [ev("mcp__gemini__" + (re.sub(r"[^A-Za-z0-9_.-]", "_", tool)[:100] or "unknown"), ti)]
    if isinstance(ti.get("command"), str):
        out += shell_events(ti["command"], None, cwd)
    return out


def extra_checks(payload: dict) -> list[tuple[str, str]]:
    """Results the path rules cannot see: (class, reason) pairs that go through the owner/managed policy."""
    tool, ti = payload.get("tool_name"), payload.get("tool_input")
    out = []
    if not isinstance(ti, dict):
        return out                                      # to_guard_events refuses it
    if tool == "save_memory":
        out.append(("unknown", "save_memory writes lasting instructions into ~/.gemini/GEMINI.md, which every later session follows"))
    if tool == "read_many_files" and ti.get("useDefaultExcludes") is False:
        broad = [x for x in (ti.get("include") or []) + (ti.get("paths") or [])
                 if isinstance(x, str) and re.fullmatch(r"[./\\]*(?:\*\*?[/\\]?)*\*?\.?\*?", x)]
        if broad:
            out.append(("unknown", "read_many_files with default excludes turned off and a broad glob can read every file, "
                                   "including secrets that are not git-ignored"))
    return out


def handle(payload: dict, mode: str | None = None):
    """(exit_code, stdout_json, stderr_text). Gemini CLI cannot ask, so ask becomes deny."""
    final = None
    if mode is None and G.guard_is_off():
        return 0, {"decision": "allow"}, ""      # the owner switched the command guard off (scripts/guard_switch.py)
    m = mode if mode is not None else G.load_policy()[0]
    for r in extra_checks(payload):
        final = G.stronger(final, G.apply_policy(r, m, f"{payload.get('tool_name')}"))
    for e in to_guard_events(payload):
        if final and final[0] == "deny":
            break
        final = G.stronger(final, G.decide({**e, "agent": "gemini"}, m))
        if final and final[0] == "deny":
            break
    if not final:
        return 0, {"decision": "allow"}, ""
    decision, reason = final
    if decision == "ask":
        msg = (f"Blocked by Org AI agent guard: this needs the developer's approval and Gemini CLI hooks cannot ask. "
               f"{reason} If it is intended, the developer runs it themselves.")
    else:
        msg = f"Blocked by Org AI agent guard: {reason}"
    return 2, {"decision": "deny", "reason": msg}, msg + "\n"


def main() -> int:
    try:
        data = sys.stdin.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ValueError("hook input too large")
        payload = json.loads(data)
        if not isinstance(payload, dict):
            raise ValueError("hook input is not an object")
        if not os.environ.get("CLAUDE_PROJECT_DIR") and isinstance(os.environ.get("GEMINI_PROJECT_DIR"), str):
            os.environ["CLAUDE_PROJECT_DIR"] = os.environ["GEMINI_PROJECT_DIR"]
        rc, out, err = handle(payload)
        print(json.dumps(out), flush=True)
        if err:
            sys.stderr.write(err)
        return rc
    except BaseException as e:   # any failure, including a broken pipe while answering, must be exit 2 (deny)
        try:
            msg = f"Blocked by Org AI agent guard: could not check this action safely ({type(e).__name__})."
            print(json.dumps({"decision": "deny", "reason": msg}))
            sys.stderr.write(msg + "\n")
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
