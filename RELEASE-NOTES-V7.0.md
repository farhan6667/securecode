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
  installed by hand. Cursor: shell, MCP and file reads (Cursor has no hook before its own file edits). Codex:
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
- Lab results from `py -I benchmark/run_lab.py --mode full` on this release: Laravel 17 of 18, Spring 20 of 20,
  legacy 17 of 17, web 22 of 22, with 0 clean files reported in every lab. The Laravel miss is L18 (IDOR through
  route model binding), which static rules do not find; the review's authorization matrix and cross-user tests
  are the control for it.

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
  `AGENTS.md`, and Antigravity reads `~/.gemini/AGENTS.md` without a setting. Both tools have pre-tool hooks;
  wiring the guard to them is future work.

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

- Tests: 932 passed, 9 skipped (Windows, Python 3.14; the skips are symlink tests this machine has no rights for,
  three optional engines that are not installed, and the real Task Scheduler test, which runs on CI runners only). CI installs Semgrep, Trivy, Gitleaks and ssh-keygen in the
  test job now and fails when a test is skipped that is not on `tests/skip-allowlist.json`.
- The gate on its own repository: `secgate.py . --mode ci --fail-on high` passes (0 critical, 0 high).
- Labs: the numbers in "Rules and labs" above.

## Known gaps

These are open entries in `FINDINGS.json`:

- IDOR through Laravel route model binding is not found by the static rules (lab L18).
- Engines installed with pip or npm have only their own package hash-checked, not their dependencies.
- nuclei resolves the staging host again itself, so a DNS answer that changes between the check and the scan
  can still move a nuclei scan.
- Cursor has no hook before its own file edits, so those edits are not checked by the guard.
- Only shell commands are classed as destructive or exposure: an MCP tool that publishes a package, or wrappers
  with their own arguments such as `sudo -u x npm publish`, are not recognized.
- The guard reads command text, so a script or test the agent wrote earlier can do anything once it runs. Use the
  native sandbox where your tool has one.
- A repo's `diff.external` cannot be switched off through the environment; nothing in the gate runs plain
  `git diff` today.
- Semgrep is installed in CI by exact version, not by hash, and the gate lists git driver keys from an engine's
  working folder rather than the project (matters only for CodeQL with `--run-tests`).
- Task Scheduler restarts a task only when it fails to start, not when the updater exits with an error, and the
  systemd service has no restart, so after a network error the next try is the next logon, boot or day.

## Review history

Up to 6.2.2: five internal review rounds and two outside-style attack rounds (the second with fuzzing). The 7.0
guard is the answer to the second attack round, and each fix has a regression test. The 7.0 merge also had one
independent internal review (a separate agent), which found two ways a repo's git config could still run a
program and three update-mechanism bugs; all are fixed with tests. This is not a third-party audit.

## Try it

Existing installs update by themselves within a day, or run the updater by hand. New installs: download
`NexaForge_SecureCode.zip` and `.sig` from the release, check the signature (see SECURITY.md), extract it and
follow `ONE_PROMPT_INSTALL.md`.
