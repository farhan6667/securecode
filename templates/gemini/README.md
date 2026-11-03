# Gemini CLI and Antigravity

NexaForge SecureCode gives Gemini CLI and Google Antigravity the same rules (`AGENTS.md`) and the same gate
(`scripts/secgate.py`) as the other agents, plus the agent guard through a hook adapter (see the end of this
page). Checked against the official docs on 2026-11-03.

## Gemini CLI

Gemini CLI reads `GEMINI.md` context files: a global one in `~/.gemini/GEMINI.md`, and project ones found in
the workspace folders and their parents. The file name can be changed with `context.fileName` in
`settings.json`, which takes one name or a list.
Source: https://geminicli.com/docs/cli/gemini-md/

Pick one of these two ways:

1. **Read AGENTS.md directly (recommended).** Copy `AGENTS.md` to `~/.gemini/AGENTS.md` and merge
   `settings.json` from this folder into `~/.gemini/settings.json` (keep your other keys). Gemini CLI then
   loads `AGENTS.md` and still loads any `GEMINI.md`.
2. **Keep the default name.** Copy `AGENTS.md` and `GEMINI.md` from this folder into `~/.gemini/`.
   `GEMINI.md` imports `AGENTS.md` with Gemini CLI's `@./AGENTS.md` import syntax.
   Source: https://geminicli.com/docs/reference/memport/

Run `/memory show` in Gemini CLI to confirm the rules were loaded.

The Gemini CLI docs carry a notice that, for unpaid tier and Google One users, Gemini CLI was replaced by
Antigravity CLI on 18 June 2026. If that applies to you, use the Antigravity steps below.

## Antigravity (app, IDE and CLI)

Antigravity reads `AGENTS.md` and `GEMINI.md` natively, with no settings change:
- global: `~/.gemini/AGENTS.md` (or `~/.gemini/GEMINI.md`, `~/.gemini/config/AGENTS.md`), and rule files in
  `~/.gemini/config/rules/*.md` (these need YAML frontmatter);
- per project: `AGENTS.md` or `GEMINI.md` in the workspace folder and each folder up to the repository root,
  `.agents/AGENTS.md`, and `.agents/rules/*.md` (the older `.agent/rules/` still works).
Rules add up; one does not replace another. Antigravity does not load rules from subfolders below the workspace.
Source: https://antigravity.google/docs/rules/

So copying `AGENTS.md` to `~/.gemini/AGENTS.md` covers both Gemini CLI (with the setting above) and Antigravity.

Antigravity workflows (saved prompts started with `/name`) are not needed: say "Run Security Test" or
"Run Advisory QA" as in the other agents. The workflows page says current workflows stop working on
19 October 2026 in favour of Agent skills. Source: https://antigravity.google/docs/ide/workflows/

## The agent guard (7.0.1)

Both tools get the agent guard through a small adapter. Replace `<PYTHON>` with the full path of your Python and
`<APP>` with the installed runtime folder (Windows: `%LOCALAPPDATA%\OrgAISecureAppSec`), using forward slashes.

**Gemini CLI.** Merge `settings.hooks.json` (macOS and Linux) or `settings.hooks.windows.json` (Windows) from this
folder into `~/.gemini/settings.json` (keep your other keys). Use the Windows file on Windows: Gemini CLI runs hook
commands in PowerShell there, and a line that starts with a quoted path needs PowerShell's `&` in front. Without it
PowerShell stops with a parse error, the hook fails, and Gemini CLI runs the tool anyway (checked live with Gemini
CLI 0.50.0, finding V7L-01). After installing, check that a blocked action really is blocked (see below). It runs `scripts/adapters/gemini_hook.py` as a `BeforeTool` hook on every tool. Shell commands, file writes,
edits, reads, searches, web fetches and MCP calls are checked. Gemini CLI has no "ask" decision, so anything the
guard would ask about is refused with the reason, and you run it yourself if you meant it. Gemini CLI lets a tool
run when a hook exits with a code other than 0 or 2 or prints something that is not JSON, so the adapter only ever
exits 0 (allow) or 2 (deny), and every error is a deny. Source: https://geminicli.com/docs/hooks/reference/
That promise only holds once Python is started: a wrong `<PYTHON>` path, a missing `&` on Windows or a broken
quote fails before the adapter runs, and Gemini CLI then lets the tool run. Project-level hooks also load only in a
trusted folder. Quick check after installing: ask Gemini CLI to read `.env` in a test folder; it must answer that
the agent guard blocked it, not that the file is missing.

**Antigravity.** Copy `../antigravity/hooks.json` (macOS, Linux) or `../antigravity/hooks.windows.json` (Windows)
to `~/.gemini/config/hooks.json` (all workspaces) or to `.agents/hooks.json` in one workspace, then check it with `/hooks` in the Antigravity CLI. It runs
`scripts/adapters/antigravity_hook.py` as a `PreToolUse` hook. Antigravity supports allow, deny and ask, so owner
mode asks there (as `force_ask`, which a cached "Always Allow" cannot skip). The docs do not say what happens when a
hook crashes or times out; the adapter always answers with an explicit decision, but whether Antigravity blocks a
call when the hook itself fails is untested. The docs do not say which shell runs the hook line, so on Windows
`<PYTHON>` goes in without quotes and must have no spaces (use the 8.3 short path, for example from
`for %I in ("C:\Program Files\Python314\python.exe") do @echo %~sI` in cmd). That line runs the same in PowerShell,
Windows PowerShell and cmd; a quoted first word does not run in PowerShell (V7L-02).
Source: https://antigravity.google/docs/hooks/

The per-edit gate check and the injection watch are still Claude Code only.
