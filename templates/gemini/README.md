# Gemini CLI and Antigravity

NexaForge SecureCode gives Gemini CLI and Google Antigravity the same rules (`AGENTS.md`) and the same gate
(`scripts/secgate.py`) as the other agents. The agent guard hooks are not wired up for these two yet (see the
end of this page). Checked against the official docs on 2026-11-03.

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

## Hooks: future work, not in this release

Both tools have pre-tool hooks today, so a port of the agent guard is possible later:
- Gemini CLI: `BeforeTool` hooks in `settings.json`; a hook can deny a call or exit with code 2 to block it.
  Source: https://geminicli.com/docs/hooks/
- Antigravity: `PreToolUse` in `.agents/hooks.json` or `~/.gemini/config/hooks.json`, with allow, deny or ask
  decisions. The docs do not say whether a crashed or timed-out hook blocks the call or lets it through, so
  fail-closed behaviour must be tested before anyone relies on it. Source: https://antigravity.google/docs/hooks/

Until then, on these two tools the rules and the gate (and CI) are the controls, not the guard.
