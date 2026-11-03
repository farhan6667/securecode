# NexaForge SecureCode 7.0.0

7.0 is the biggest change since the first release. The agent guard is rebuilt around a positive model, the gate
gets per-language scanners, new rules and three new labs, there is an automated pentest flow with a report, and
updates now catch up on laptops that were off at check time. Installs of 6.x update to 7.0 by themselves (same
release key); nothing to do by hand.

## Agent guard

- **Allow what is clearly safe, ask about the rest.** The second outside-style attack round showed that a list of
  dangerous shapes is never complete. The guard now normalizes each command like bash or PowerShell would
  (quotes, escapes, brace expansion, `~` and `$HOME` spellings, `cd` and `git -C`), resolves every path, and
  allows a command only when it is a known everyday development command whose every path stays in the project or
  a temp folder. Anything else is "unknown".
- **Owner mode and managed mode.** On your own machine an unknown command, a force push, `git reset --hard`, a
  public repo or gist, or a package publish asks you and shows the exact command; every ask is logged to
  `.security/guard-audit.jsonl`. Managed installs refuse them. A missing or broken policy means managed.
  Secrets, the agent's own config, startup files and the scanner tools folder are refused in both modes.
- **Every tool goes through the guard** (the hook matcher is `.*`), and any string argument that looks like a path
  or a file URL is checked, whatever its name or nesting.
- **Cursor and Codex adapters** (`scripts/adapters/`, templates in `templates/cursor` and `templates/codex`),
  set up with `install-global.py --agent cursor` or `--agent codex`. Cursor: shell, MCP and file reads (Cursor has no hook before its own file edits). Codex:
  shell, `apply_patch` and MCP; Codex hooks cannot ask yet, so an ask becomes a deny there.
- **Git without the repo's programs.** The stop gate, the scanners and the engines run git with the repo's
  fsmonitor, hooks, filter and textconv drivers and signature verifiers switched off (`scripts/safe_git.py`); a
  config it cannot fully neutralise means git does not run.
- **End-of-task offer.** After a bigger change (3 or more code files or 40 or more lines) the agent offers
  "Run Security Test" once.
- Measured: 1 ask and 0 denies on a corpus of 256 everyday commands (0.4 percent), and the round-2 Hypothesis
  fuzzer passes.

## Per-language engines

- `scripts/securecode.py setup` installs pinned, hash-checked scanners into a tools folder outside every project:
  Semgrep, Trivy, Gitleaks, osv-scanner, Bandit, pip-audit, gosec, govulncheck, ESLint with
  eslint-plugin-security, Retire.js, OWASP Dependency-Check and SpotBugs with Find Security Bugs; npm audit comes
  with npm. Security Code Scan and CodeQL are manual (no pinnable checksum, and CodeQL's licence).
- The gate runs the ones that are installed and match the project's languages; missing ones are NOTE lines.
  In `ci` mode the scanned repo cannot configure them (package-owned configs, inline suppressions ignored).
- Scanner output is untrusted input: a malformed Semgrep, Trivy or Gitleaks report is "scanner output unreadable"
  and counts as a failed required scanner, so `ci` mode blocks instead of passing.

## Rules and labs

- 21 Java and Spring Boot Semgrep rules (deserialization, XXE, JNDI, SpEL, query concatenation, permitAll, CSRF
  off, Actuator, IDOR, mass assignment, missing `@Valid`, trust-all TLS, weak password hashing, weak random tokens).
- Legacy audit for planted code: obfuscated eval, request-driven exec, PHP in upload or image folders.
- Code checks: missing input validation, debug flags from the request, tokens built from user data, short numeric
  codes, public env secrets, production source maps, auth routes without throttling, deny-list "fixes", PHP APIs
  deprecated up to 8.5.
- Database and default-value checks: root or empty-password database users, no TLS, bound to every interface,
  GRANT ALL, sensitive columns, guessable default credentials and secret keys, exposed admin paths and tools.
- Laravel IDOR through route model binding (`show(Invoice $invoice)` with no `authorize`) is now found by a new
  rule. It reads the route files, FormRequests and policies first, so routes that are already protected are not
  reported. It does not follow checks hidden in helper methods or in only one branch.
- Lab results from `py -I benchmark/run_lab.py --mode full` on this release: Laravel 18 of 18, Spring 20 of 20,
  legacy 17 of 17, web 22 of 22, with 0 clean files reported in every lab.

## Secret shield and MCP check

- `scripts/secret_shield.py` runs after each tool and masks keys, tokens and passwords in the output before the
  agent sees it (Claude Code `updatedToolOutput`). `secret_shield.py sweep` finds secrets already sitting in a
  project.
- `scripts/mcp_scan.py` reads your MCP server configs offline and reports plain-text tokens, `@latest` or
  unpinned packages and risky launch commands. Details and limits: `docs/SECRET-SHIELD-AND-MCP.md`.

## Automated pentest

- `scripts/report.py` writes REPORT.md and a print-ready REPORT.html (optional PDF) with an executive summary,
  scope, findings with impact and retest labels, attack chains and limits. Every value from scanners is treated
  as hostile: secrets are redacted, hidden characters shown, Markdown and HTML escaped, and the HTML has a strict
  content security policy. `scripts/report_lint.py` refuses overclaims, unlabelled findings and unmasked secrets.
- `scripts/local_dast.py` runs an OWASP ZAP baseline or API scan against your own app on loopback only (passive
  unless you add `--active`). Staging scans share one target check (`scripts/dast_target.py`) that refuses cloud
  metadata, link-local and, unless you name them, private addresses.
- `scripts/fix_pr.py` opens a fix branch and a draft pull request: a dry run unless you say `--open`, never the
  default branch, no force push, and gitleaks on the added lines first.

## Gemini CLI and Antigravity

- The rules and the gate now work there too: `templates/gemini/` has the settings and a `GEMINI.md` that loads
  `AGENTS.md`, and Antigravity reads `~/.gemini/AGENTS.md` without a setting. The agent guard is wired to both
  through their pre-tool hooks (`scripts/adapters/gemini_hook.py` and `antigravity_hook.py`), set up with
  `install-global.py --agent gemini` or `--agent antigravity`. Gemini CLI enforcement was checked live with the
  CLI's own test mode; for Antigravity the filled-in hook line is tested through PowerShell, Windows PowerShell
  and cmd.

## Install and outside-test fixes

- **Committed secrets stay out of reach** (V7P-01, high). The guard allowed git pathspecs such as `<rev>:<path>`
  (`git show HEAD:.env`), which read a committed secret file straight from git's object store. They are now
  checked like any other path.
- **The secret shield masks app secret keys with a longer name** (V7P-02), such as `SECRET_KEY_BASE`, where the
  secret word is followed by more of the name.
- **A huge MCP config no longer stalls the gate** (V7P-03). The config scan read the file again for every server,
  which was quadratic on a hostile `.mcp.json`; it is now one pass.
- **Gemini CLI, Codex and Antigravity hooks on Windows really block** (V7L-01 and V7L-02, high). The hook lines
  failed in the shell these tools use on Windows, and a failed hook lets the tool run. The lines are fixed and now
  tested through pwsh, Windows PowerShell and cmd.
- **Python paths with spaces work in hook lines** (V7GAP-H, high). Windows hook lines start with an unquoted
  Python, so the installer writes the 8.3 short path, or refuses the adapter when there is no safe form.
- **One command sets up the other agents** (V7GAP-4). `install-global.py --agent cursor|codex|gemini|antigravity`
  fills the paths, backs up and merges your config, and `verify-global.py` shows which adapters are installed.
- **"Run Security Test" finds Python on Windows** (V7GAP-1). The skill and rules carry the exact Python that
  installed them.
- **Windows users can check the signature** (V7GAP-2). The docs give the PowerShell form of the check.
- **Old Python is refused up front** (V7GAP-3). Python older than 3.10 stops with the version found and how to
  get a current one.
- **The docs match the release zip** (V7GAP-A and V7GAP-C). They name the `aisec/` folder inside the zip, and
  `doctor` and `setup` are pointed at your project, not at SecureCode itself.
- **Update task problems are visible** (V7GAP-F, V7GAP-G and V7GAP-I). A task that could not be created is a
  failed check; `--no-update-task` installs without it; and a schedule-only failure exits 4, so the updater
  reports "updated, schedule warning" instead of a failed install.
- **Local DAST works with Docker stopped** (V7GAP-5). A local ZAP jar is preferred over a Docker that is installed
  but not running. `securecode.py setup --engine zap` installs ZAP 2.17.0, pinned with its SHA-256.
- **A crashing scanner no longer hides the rest** (V7GAP-9). In `ci` mode the gate still prints every other
  finding and a readable error for the scanner that failed.
- **OWASP ASVS 5.0 chapters are mapped** (V7GAP-7) in `docs/STANDARDS-COVERAGE.md`, as guidance for reviewers,
  not a compliance claim.
- **More ways to read a committed secret through git are closed** (V7P2-02 high, V7P2-03). `git cat-file --batch`
  fed from stdin or a file, `--pathspec-from-file`, pathspec magic, and `git archive`, `format-patch` or
  `stash show` of a secret are refused in managed mode and asked about on your own machine; dumps of the whole
  tree ask first.
- **The secret shield cannot be stalled into giving up** (V7P2-01 high). A crafted tool output could make one
  pattern so slow that the hook timed out and the original output went through; every pattern is now linear,
  measured up to 2 MB.
- **The guard reads commands the way the shell does** (V7P3-01 high). PowerShell treats a lone carriage return as
  a new line and curly quotes as quotes, and Git Bash drops carriage returns; the guard now does the same before
  it decides.
- **Very large tool calls are no longer cut short** (V7P3-02 high). A file tool call with hundreds of paths was
  checked only up to a limit; past a much higher limit the call is now asked about or refused, never passed.
- **A control character in a file path is refused** (V7P4-01 high). A newline inside a file tool's path skipped
  the path check, and Windows still resolved the path; this was there since 6.2.0.
- **The shield sees through terminal colours and more secret shapes** (V7P3-03, V7P3-04). Colour codes or NUL
  bytes around a token no longer hide it, and `Authorization` headers, XML passwords and `redis://:pw@host` are
  masked.

## Update mechanism

- **Windows:** the daily task is created from an XML definition. It runs at 11:00 (up to 30 minutes random delay)
  and 10 minutes after you log on, starts as soon as possible after a missed run, needs a network, stops after
  an hour, and restarts up to 3 times if it fails to start. This also removes a 261-character command limit that
  made the installer skip the task on long paths. An update re-creates the task, so 6.x installs get it too.
- **Linux and macOS:** `install-global.py --update-timer` (or the install script with that flag) installs a systemd
  user timer with `Persistent=true` or a launchd agent that also runs at login, so a missed check catches up.
  Without the flag the crontab line is printed as before.
- **Updater:** a GitHub rate limit (403 or 429) is logged with a retry time and the run exits cleanly; an
  incomplete download is refused before the signature check; two runs never overlap; unsigned, older or
  differently signed releases are refused as before. Each run records its time and result, and
  `verify-global.py` shows the last check, its result and the next run.
- Proven in a test: a 6.2.2 updater (a copy of the released file) installs a 7.0.0 release signed with the same
  key and keeps the organization's brand name and findings file; a 7.0.0 release signed with another key is
  refused.

## Proof from this release's runs

- Tests: 1611 passed, 13 skipped (the skips are on tests/skip-allowlist.json) on Windows, Python 3.14; CI runs the same suite on Windows and Linux with Python 3.10, 3.12
  and 3.13 and fails on any skip that is not on tests/skip-allowlist.json.
- The gate on its own repository: `secgate.py . --mode ci --fail-on high` passes (0 critical, 0 high).
- Labs: the numbers in "Rules and labs" above.

## Known gaps

These are open entries in `FINDINGS.json` (ids in brackets):

- A Claude Code transcript may keep the original tool output before the secret shield masks it, so a withheld
  secret could still sit in `~/.claude/projects`. Run `secret_shield.py sweep` to find it. This needs a live
  check on a real session (V7S-05).
- The secret shield does not see secrets in the tool input, Monitor tool output, or secrets with no recognisable
  shape (V7S-07).
- Engines installed with pip or npm have only their own package hash-checked, not their dependencies (V7E-02).
- nuclei resolves the staging host again itself, so a DNS answer that changes between the check and the scan
  can still move a nuclei scan (V7I-06).
- Cursor has no hook before its own file edits, so those edits are not checked by the guard (OPEN-02).
- Only shell commands are classed as destructive or exposure: an MCP tool that publishes a package, or wrappers
  with their own arguments such as `sudo -u x npm publish`, are not recognized (OPEN-03).
- The guard reads command text, so a script or test the agent wrote earlier can do anything once it runs. Use the
  native sandbox where your tool has one (OPEN-04).
- A repo's `diff.external` cannot be switched off through the environment; nothing in the gate runs plain
  `git diff` today (OPEN-05).
- Task Scheduler restarts a task only when it fails to start, not when the updater exits with an error, and the
  systemd service has no restart, so after a network error the next try is the next logon, boot or day (OPEN-06).
- The gate lists git driver keys from an engine's working folder rather than the project, which matters only for
  CodeQL with `--run-tests` (OPEN-07).
- Semgrep is installed in CI by exact version, not by hash (OPEN-08).
- `git clean -fdx` or `find . -delete` on the whole tree can still remove `.security` with its audit files, and
  the size cap during the ZAP download is the global 400 MB, not the pinned size; the SHA-256 is still checked
  (OPEN-09).
- `git log -p`, `git grep "" HEAD` and reading a blob by its id can still print a committed secret; blocking them
  would break everyday git, so the secret shield is the control there (OPEN-10).
- The secret shield misses some shapes: space-separated values (`.netrc`, `--password X`, Dockerfile `ENV`),
  cookies, keys whose name has no secret word (`APP_KEY`, `SIGNING_KEY`), XML CDATA and a few odd byte tricks
  (V7P3-L1, V7P3-L2, V7P4-L1, V7P4-L2). Very long strings under non-path keys of a tool call are not checked
  (V7P4-L3).

Other limits, documented but not tracked as findings:

- The Laravel binding rule does not follow authorization done in helper methods or in only one branch.
- Codex and Antigravity enforcement is tested by running the filled-in hook lines through their documented
  shells, not yet in a live session. Gemini CLI enforcement was checked live with the CLI's own test mode.

## Review history

Up to 6.2.2: five internal review rounds and two outside-style attack rounds (the second with fuzzing). The 7.0
guard is the answer to the second attack round, and each fix has a regression test. The 7.0 merge also had one
independent internal review (a separate agent), which found two ways a repo's git config could still run a
program and three update-mechanism bugs; all are fixed with tests. Before release there were four more
internal attack rounds, each by a separate agent with fuzzing and live shell checks, each attacking the previous
round's fixes: 6 high and 5 medium findings in total (V7P, V7P2, V7P3, V7P4), all fixed with regression tests
that fail without the fix. The fourth round still found one high, so we expect more edge cases in a
pattern-based guard; treat it as a strong tripwire, not a sandbox. This is not a third-party audit.

## Try it

Existing installs update by themselves within a day, or run the updater by hand. New installs: download
`NexaForge_SecureCode.zip` and `.sig` from the release, check the signature (see SECURITY.md), extract it and
follow `ONE_PROMPT_INSTALL.md`.
