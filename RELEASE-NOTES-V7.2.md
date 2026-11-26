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
- Bypass runs and managed installs are always strict. An auto or don't-ask run reads like an attended one (coding until a
  risk signal), because coding mode asks nobody anyway, so a person being there added no check; without a session id it
  stays strict. You can pin the mode: `guard_switch.py mode adaptive|coding|strict`. A pinned mode never switches by itself.
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

**A task you leave running (overnight, any permission mode, any AI tool)**
- `guard_switch.py unattended on` or `SECURECODE_UNATTENDED=1`: every question the guard would ask becomes a refusal with
  the reason and the words "carry on with the rest of the work", so the session never waits on a prompt nobody answers.
  It only ever turns a question into a refusal, never into an allow, in owner and managed mode alike; that is why an
  environment variable may switch it on. It holds in every permission mode: with the switch on, a bypass run no longer
  lets a force push through and an auto run no longer passes a named install on.
- The held list: what was refused or blocked while nobody was there is kept in the app cache, per project, redacted, and
  `guard_switch.py held` prints it grouped with counts. `guard_switch.py status` shows the mode and the count.
- A question that was refused only because nobody could be asked counts as a question for the risk signals, not as a
  block. Before, one refused `kill` made the whole session strict for two hours, the same as a secret read. A real
  block (a secret read, a guard timeout) in a run with nobody there is remembered for the project for two hours, so a
  loop that starts a new session per step does not begin each step with a clean record.
- Stop gate: with unattended mode on, the security test offer is not asked; it goes on the held list and the developer
  is asked in the next attended session. A developer who works in auto or bypass mode without the switch still gets the
  offer. With the switch set in the policy file (a person at a terminal, not the environment variable) a finding that
  was shown is not sent back to another session of the same project for two hours; a loop that starts a new session per
  step paid one extra turn per step. The stop gate still honours no suppression file: the agent can write, commit or
  git-ignore that file, and the stop gate is the last local check before it stops.

**Complete Security Test: a pentester next to every developer**

- New trigger phrases: "Complete Security Test", "Full Security Test", "Complete Security Test Karo", and the command
  `/complete-security-test`. They mean the whole project, not the latest diff.
- `.security/review-findings.json`: bugs the agent finds by reading code (the IDOR and logic bugs scanners miss) get R- ids,
  appear in the report, are retested and count for the verdict. Before, they never reached the report.
- The report is still written by a script from the result files, so it costs no tokens, and the agent is told to write
  no other document for the handover and not to read the report back.
- `report_lint.py` also refuses "pentest passed", "production ready" and "no issues found" as the report's own words.
- Off by default, preview: a team that keeps a `.security/coverage.json` gets a coverage table of 24 review classes and
  a handover readiness line in the report, and `scripts/handover_pack.py` can zip the results with hashes for the security
  team. The agent does not write these by default, because they cost tokens on every test. Five review rounds each still
  found problems in this optional part (V72-42 to V72-51, all fixed and tested) and no round came back clean for it
  (V72-O13), so treat it as a help for the security team, never as its decision.
- The report is stricter about what counts. A finding the latest gate run reports is open even when an older
  findings-before.json does not list it. A Pass for a finding the latest run still reports is a Fail. A review finding with
  an unknown severity is taken as High. A compensating control needs evidence, a name and a date. A result file that is
  there but can not be read gives BLOCKED, not "no findings". Findings are sorted before the report's cap, so
  informational noise can not push a Critical out. Retest entries name a finding by its fingerprint, which the report
  prints next to each id.
- The skill caps the fix loop at three rounds and no longer calls its own work a pentest.

**Fewer tokens**
- The gate prints findings sorted by severity, deduplicated, with paths relative to the project, and Low and Info as counts
  per rule. Before, the first 100 in scan order were printed, so many Low lines could push a Critical off the list.
- `.security/findings-summary.txt` is the short view the agent reads; the full JSON stays for people and the report.
- A re-run says what changed since the last run in one line.
- The edit hook shows a file's High and Critical lines once per session and one short line after that until they change.
- The always-loaded rules block in `~/.claude/CLAUDE.md` is shorter; the long steps load with the skill.

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

The secret shield, the High and Critical block on stop, the scanners and the CI gate. Nothing that blocks a dangerous
action was relaxed, and nothing was relaxed for managed mode. One reading did get wider and is stated here plainly: an
auto or don't-ask run in owner mode now gets the coding reading for shell syntax (and only that class) that an attended
session already got without a question; the tests hold that it allows nothing the attended coding reading does not.

## Tests and review

- Tests: 8,711 passed and 19 skipped on Windows with Python 3.14 and pytest 8.4.2 on 2026-11-25, from a path without
  spaces. Three tests in `tests/test_v7_engines.py` failed on that machine on this branch and on the branch before these
  changes, because Bandit is already installed there and the tests expect an empty tools folder. The CI run on the
  release commit is the reference; see the Actions tab.
- The command guard (adaptive mode and the syntax it follows) had seven review rounds by separate AI reviewers. Round 8
  was not run, and the root cause of the last round is open (V72-O8 in FINDINGS.json).
- Unattended mode, the held list and the stop gate had three rounds. The third found nothing at high or medium: 80,676
  decisions over 560 events, every permission mode, owner and managed, with the switch on and off.
- The report, its lint and the optional handover pack had five rounds. Each found high or medium problems, fewer and
  narrower each time; all are fixed with tests (V72-42 to V72-51). No round came back clean for that part (V72-O13),
  which is why coverage, readiness and the pack are off by default.
- The last change (the skill no longer asks for a coverage file or a pack) removed steps and was not reviewed again.
- Every confirmed finding has a test and an entry in FINDINGS.json. Open entries are listed there as open.
- Reviewers were AI agents given the code and not the author's conclusions. That is not the same as a review by an
  outside person, and none has been done for 7.2.

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
- Unattended mode stops the guard's own questions. It does not stop the AI tool's own permission prompts: in Claude Code's
  default mode a command that is not on your allow list still waits for you. For an overnight run use the tool's auto or
  accept mode together with unattended mode.
- The held list and the coverage file are written by the agent's own session. They are a record for an honest workflow,
  not evidence against an agent that was told to lie; the security team's own test is the check.
- Coverage says a class was examined and names the evidence. Nothing verifies that the evidence is good; the report lint
  only checks that it is there.
- The handover pack is not signed. Its hashes show a file that no longer matches the manifest; a file and the manifest
  edited together match again. The pack's own SHA-256, sent separately, is the check.
- With unattended mode set in the policy file the stop gate keeps a shown finding from other sessions for two hours. A
  session that edits the same file is still told by the edit hook.
- A retest entry is matched to a finding by its id only where the id can not move (a scanner finding of the first run,
  or a review finding that names its own id). A DAST finding, a finding that appeared later and a review finding with no
  id of its own are matched by fingerprint; the report prints every fingerprint and says so when an entry was not used.
  Retest files written for 7.0 that name DAST findings by id only need the fingerprint added. Without a
  findings-before.json the ids of scanner findings follow the latest run, so keep that first-run file.
- A result file that is there but can not be read as JSON gives BLOCKED, not "no findings".
- Unattended mode set by the environment variable can be set by a project's own settings. That can only make the guard
  refuse more, and move the test offer to the held list.
- Local DAST is still unauthenticated: it sees what an anonymous visitor sees.
- Not measured: tokens saved per session, and how often a project passes a human pentest the first time.
