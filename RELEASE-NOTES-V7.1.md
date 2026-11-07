# SecureCode 7.1: a quieter guard, and a switch for it

SecureCode now stays out of the way while you code, does the deep work when you ask for it, and no longer stops an
unattended run with a question nobody can answer.

## Why

Two kinds of noise made developers switch the guard off. While coding, the edit hook and the security test offer spoke
up too often. And the command guard asked about unusual commands whatever mode Claude Code was in, so a run in auto or
bypass mode stopped at the first question. A guard that people remove protects nobody, so 7.1 makes it quiet where quiet
is safe, and gives you a switch for the guard alone where it is not enough.

## What changed

**Smart mode (while you code)**
- The edit hook is silent when the file is clean. It adds nothing unless the quick gate finds a High or Critical issue,
  and then it shows only those lines. `SECURECODE_HOOK_VERBOSE=1` brings back the full report.
- The stop hook sends the agent back once per finding and session. Its memory sits in the app folder, never in the
  project, so a cloned repository cannot silence it.
- The security test offer waits for a feature's worth of work (10 code files or 300 changed lines) and comes once per
  session. `SECURECODE_MODE=coding` turns it off: type "Run Security Test" when the program is done.
- The rules say it plainly: write secure code while coding, one short self-check before "done", and the long
  checklists only for "Run Security Test".

**The command guard and Claude Code's permission mode**
- It now reads the permission mode (owner mode only). `bypassPermissions` asks nothing. `auto` and `dontAsk` let a
  plain install go on to Claude's own permission system and refuse everything else that would have asked, with a reason,
  so the agent works another way instead of waiting. A missing or odd mode counts as attended and asks as before.
- Secrets, pipe-to-shell, the agent's own settings, global Claude settings and a guard timeout are refused in every
  mode, bypass too.
- An install is a plain install only when it is the verb first, known value-less flags and plain registry package names.
  A source or index option, a URL, a git or file source, a workspace, a brace expansion that hides one, and `npx` or
  `dlx` options that move a package's source are the new "odd install": they ask exactly as before for a person and in
  managed mode, and are refused in auto mode.
- Every ask that auto or bypass mode answered without a person is written to the guard audit.
- A publish hidden behind an option and its value (`cargo --color never publish`, `pnpm --filter web publish`) is now
  caught. 7.0.0 let it through in every mode.

**`guard_switch.py`: turn off the command guard alone**
- From your own terminal: `py -I guard_switch.py off`, `on` or `status`. Only the command guard is switched off. The
  rules, the edit check, the stop gate, the secret shield and "Run Security Test" stay on.
- Honoured in owner mode only, never for a managed install or a broken policy file. It needs a person at a terminal and
  survives updates. `verify-global.py` shows `command guard OFF` while it is off. All five agent adapters follow it.
- It is a convenience, not a barrier: a terminal check is not authentication, and a script an agent writes and runs
  itself can still edit the policy file. Details in `docs/AI-AGENT-SECURITY.md`.

**Fewer false alarms and smaller fixes**
- The Python that runs the guard, called by its full path, and a PowerShell assignment written without spaces
  (`$env:X="v"`) no longer ask. Both asked in every mode before. A PowerShell quoted string statement is no longer an
  unknown command either. Hijack variables such as PATH, NODE_OPTIONS and LD_PRELOAD still ask.
- The audit now records which AI tool asked (`claude`, `cursor`, `codex`, `gemini`, `antigravity` or `other`).
- The updater asks again without a token when a public repository answers a token with 401, 403 or 404 (a gh login for
  another account, an expired token, an SSO rule). A rate limit still backs off, and a private repository still fails
  visibly.
- The test suite no longer writes made-up asks into the repository's own guard audit file, and the guard does not log
  into its own source folder.
- The README no longer promises that a project will "pass the pentest the first time"; that was never measured.

## What did not change

The secret shield, the High and Critical block on stop, "Run Security Test" (deep review, full gate, retests, report),
the scanners and the CI gate. Nothing that blocks a dangerous action was relaxed for a person or for managed mode. A
differential run of the 7.0.0 guard against this one found only tightenings, all listed in `docs/AI-AGENT-SECURITY.md`.

## Tests and review

{{TESTRUN}}

The guard change had six independent AI review rounds, each attacking the last round's fixes, and the switch one. They
found real bugs every time until the last rounds, all fixed with a test that fails without the fix (FINDINGS V71-GA01 to
V71-GA03, SM-01 to SM-06). This is not a third-party audit.

## Open, and what this release does not do

- In bypass mode the guard does not follow wrapped commands (loops, names built at run time). Do not read bypass mode as
  a protected mode.
- A command the guard has no objection to goes on to Claude's own permission system in auto mode. That includes installs
  with no package name (`npm install`, `pip install -r requirements.txt`), which read whatever the manifest says.
- A package manager or verb the guard has no model for (`npm update`, `pip download`, `composer create-project`) returns
  no verdict, and project-level `.claude/settings.json` and `.mcp.json` writes are allowed in every mode.
- A typo-squatted package name is not caught by the guard.
- In an attended session the guard still asks for shell syntax it does not model (`$( )`, variable prefixes, inline
  Python, `xargs`, remote commands, reads in sibling folders). Planned for 7.2, together with an adaptive mode.
- Not measured: tokens saved per session, and how often a project passes a human pentest the first time.
