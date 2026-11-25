# SecureCode 7.2: a command guard that stays on and stays quiet

The command guard is now quiet while you code and strict when something looks wrong, so there is no reason to switch it
off. The 7.1 work (a quieter edit hook, a guard that knows when nobody is there, a switch for the guard alone) is part of
this release: 7.1 was prepared but never tagged, so 7.2.0 is the one release that carries both.

## Why

A guard that asks about everything gets removed, and then it protects nobody. In one real working session the guard asked
34 times in about 80 minutes and about three quarters of the questions were noise: a full path to Python, a PowerShell
assignment, `$( )`, a variable in front of a command, a read in a folder next to the project, inline Python, `xargs`, a
read-only command over ssh. 7.1 removed the first two. 7.2 removes the rest, without making the guard blind.

## What changed

**Adaptive mode (the default)**
- The guard has two readings. **Coding** is the one an attended developer gets: shell syntax the guard cannot follow, but
  whose commands it did check, is allowed and written to the audit. **Strict** is the 7.1 reading: the same shapes ask.
- It switches to strict by itself on a risk signal in the session: a command was blocked (a secret read, pipe-to-shell, the
  agent's own settings), three questions in ten minutes, or something was downloaded in the last fifteen minutes. The
  memory of this sits in the app cache, keyed by the session, never in the project.
- Auto, don't-ask and bypass runs, and managed installs, are always strict. You can pin the mode: `guard_switch.py mode
  adaptive|coding|strict`. A pinned mode never switches by itself.
- The mode is in every audit line (`guard_mode`) and allowed shapes are logged as `coding-allowed`.
- Hard denies are the same in both: secrets, pipe-to-shell, the agent's own files and settings, `rm -rf ~`. What still asks
  in both: an unknown program, `sudo`, a destructive or exposing command, a package install, and anything on a server that
  changes it (a restart, a write, a key).

**Syntax the guard now follows (the inner command is still checked)**
- `$( ... )`: the command inside runs through the same model as a command of its own. Its output is only accepted where it
  is harmless: an argument of `echo`, a listing or size (`ls`, `wc`, `du`), a git read or `git commit -m "$(cat <<'EOF' ...)"`.
  As a program name, a path that is read or written, an installer argument or an interpreter argument it stays a question.
- PowerShell: `(Get-Item x).Length`, `$f = Get-Content a.txt`, `Write-Output (Get-Date)`. The command inside is checked; a
  bare word on the right of `=` is a command and is judged as one.
- A variable in front of a command (`X_URL=... pytest`). The variables that change what programs load or run still ask
  (`PATH`, `IFS`, `BASH_ENV`, `ENV`, `LD_*`, `DYLD_*`, `PYTHON*`, `NODE_*`, `NPM_*`, `GIT_*`, `*_PROXY` and more).
  This is a deny list, so it can miss a name; it is judged by the command around it as well.
- `xargs` with a listing or size command, `echo` or a git read. `xargs cat`, `xargs rm` and every `-I` form still ask.
- `ssh host "command"` for a read-only command (`systemctl status`, `journalctl`, `docker ps` and `logs`, `ls`, `cat`,
  `tail`, `grep`, `df`...). A restart, a write, a redirect, a substitution, a secret file name or an ssh option that runs a
  program asks or is denied. Extra wrapper names can be listed in the policy.
- Inline code: `python -c`, `node -e` and here-documents. The code is read as text: code that reaches the network, starts a
  process, reads the environment, evaluates code or changes files still asks. This is a text filter, not a sandbox, and a
  project script is not read at all.
- Folders next to your project: `guard_switch.py workspace add <folder>` lets the agent read them (never write). Every
  secret rule still applies there.
- A quoted program path with a space in a folder (`"C:/Users/John Doe/proj/.venv/Scripts/python.exe" -m pytest`) is a path,
  not an unknown command. It asked on every call for anyone with a space in their home or project path.

**Rules and checklists (text only, no new guard logic and no new questions for the developer)**
- `AGENTS.md` has a new section 9 and the global rules file a new rule 10 for AI features, agents and MCP in the code the
  agent writes: untrusted model output and tool text, least permissions, no secrets in prompts, limits on tokens and loops,
  MCP token handling, and installing unfamiliar packages with scripts off first.
- `docs/SOURCE-CODE-REVIEW.md` maps its sections to the OWASP Top 10:2025 list and gains sections on the software supply chain,
  mishandling of exceptional conditions, and AI features, agents and MCP (OWASP Top 10 for LLM Applications 2025 and for
  Agentic Applications 2026, the MCP Security Best Practices and Authorization pages, the npm docs on trusted publishing,
  scripts and config, SLSA). Every source is listed with its URL and the date it was read (2026-11-25). The agentic bullets
  are this project's own checks under OWASP's names, because only the names were read.
- The security review skill lists the new checks for "Run Security Test" and "Run Advisory QA".

**Carried over from 7.1**
- A quiet edit hook, a stop gate that sends the agent back once per finding, a security test offer that waits for a
  feature's worth of work, and `SECURECODE_MODE=coding`.
- The guard reads Claude Code's permission mode: bypass asks nothing, auto and don't-ask let a plain install go on to
  Claude's own permission system and refuse the rest with a reason. Secrets, pipe-to-shell, the agent's own settings and a
  guard timeout are refused in every mode.
- `guard_switch.py off|on|status` for the command guard alone (owner mode, needs a person at a terminal).
- Fewer false alarms and smaller fixes: the guard's own Python by full path, PowerShell assignments without spaces,
  a publish hidden behind an option, the AI tool recorded in the audit, the updater retrying without a token for a public
  repository, the test suite no longer writing into the repository's own audit.

## What did not change

The secret shield, the High and Critical block on stop, "Run Security Test" (deep review, full gate, retests, report), the
scanners and the CI gate. Nothing that blocks a dangerous action was relaxed, and nothing was relaxed for managed mode.

## Tests and review

{{TESTRUN}}

## Open, and what this release does not do

- Coding mode is a convenience for an attended developer, not a boundary. The guard follows the shapes above and nothing
  else; a script an agent writes and runs is not read, and inline code is only a text filter.
- In bypass mode the guard does not follow wrapped commands (loops, names built at run time). Do not read bypass mode as a
  protected mode.
- A command the guard has no objection to goes on to Claude's own permission system in auto mode. That includes installs
  with no package name (`npm install`, `pip install -r requirements.txt`).
- A package manager or verb the guard has no model for (`npm update`, `pip download`, `composer create-project`) returns no
  verdict, and project-level `.claude/settings.json` and `.mcp.json` writes are allowed in every mode.
- The guard audit is a file in the project, not tamper-proof. Treat it as a convenience log, not evidence.
- A typo-squatted package name is not caught.
- The risk signals need a session id from the AI tool. Claude Code, Codex, Gemini CLI, Cursor and Antigravity send one and
  the adapters pass it on; an event without one stays in coding mode and never switches. Pin the mode to strict if you want
  that.
- Not measured: tokens saved per session, and how often a project passes a human pentest the first time.
