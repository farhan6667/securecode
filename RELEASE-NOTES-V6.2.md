# NexaForge SecureCode 6.2.0 (first public release, public preview)

NexaForge SecureCode is a security layer for AI-assisted coding in Claude Code, Cursor and Codex. This is
its first public release under the MIT licence. It is marked as a preview: it has been used and tested on
Windows with Claude Code, and reports from other setups are very welcome.

## What it does
- **Secure by default.** Rules for the agent (`AGENTS.md`, a global CLAUDE.md block) and a self-review of
  every change before the agent says "done".
- **Deep source code review.** "Security Test Karo" (find, fix, re-test) and "Advisory QA Karo" (readiness
  advisory, no changes until approved), with OWASP Top 10 and API Top 10 checklists. For access control the
  agent writes `.security/authz-matrix.md` and one cross-user test per route; a row without a passing test
  stays open.
- **Gate** (`secgate.py`): Semgrep (own rules, Laravel authorization rules and registry packs), Trivy,
  Gitleaks, the project's own tests (npm, pytest, go, PHP artisan or PHPUnit, dotnet), and built-in checks
  for outdated front-end libraries, web-root exposure, cookies, headers (framework-aware for Laravel, Express
  and ASP.NET Core), TLS, deletes over GET, default credentials, unsupported PHP and Laravel, raw template
  output, Android manifests, poisoned AI instruction files and risky repo agent configs. `ci` mode fails
  closed when a scanner is missing or errors. Retire.js and Psalm taint analysis are used when installed.
- **Agent guard** (Claude Code PreToolUse hook): blocks secret reads, writes to the agent's own settings,
  pipe-to-shell, force pushes and public repo creation; asks before pushes and installs.
- **Signed auto-update** from this GitHub repo (ed25519 via ssh-keygen, no downgrade, safe extract), with an
  optional internal product name that updates never change.
- **Templates**: Laravel security middleware and settings, and example security tests.
- **Benchmark**: an own Laravel lab with 18 planted issues; results and their limits in `benchmark/RESULTS.md`.

## Fixed before this release (independent review rounds 3 and 4)
- The gate could run a `semgrep.bat`, `trivy.bat` or `gitleaks.bat` planted in the scanned repo on Windows
  and report a fake clean scan. Scanners are now taken from absolute PATH entries only.
- The guard let git and many other programs (curl -o, tar -C, mkdir, npm --prefix, .NET file APIs) write into
  the agent's own config folder, and missed abbreviated or aliased force pushes. It now refuses every
  non-reading command that names that folder, and git option prefixes and aliases are handled.
- Semgrep injection rules rated WARNING (for example Laravel SQL injection) never blocked at `--fail-on high`.
- The release script could have packed local drafts; releases now take only files committed to git.
- A signer file saved by Notepad with a byte order mark made every update fail; it is now read correctly.
- The per-edit hook scanned the whole working folder when the edited file was outside it, and timed out.
  It now scans only the changed file and only advises; blocking is the Stop gate's and CI's job.
- Also: symlinked files and folder junctions are no longer followed, console output can no longer forge
  result lines, null scanner JSON no longer crashes the gate, the stop gate works in a repo with no commits,
  and the updater refuses a second redirect hop.

## Try it
Download `NexaForge_SecureCode.zip` and `.sig` from this release, check the signature (see SECURITY.md),
extract it and follow `ONE_PROMPT_INSTALL.md`.

## Known limits
See `SECURITY-CONTEXT.md`. The guard reduces risk; it is not a sandbox. The deep review is done by the AI and
can miss business logic, so a human pentest stays in place.
