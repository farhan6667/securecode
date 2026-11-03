# Security context (threat model) for NexaForge SecureCode itself

**What it is.** Python scripts, Claude Code hooks and settings, and Markdown instructions installed on
developer machines, plus CI templates. It runs with the developer's own rights and sees their code.

**Who or what can reach it.**
- The AI agent (Claude Code, Cursor, Codex, Gemini CLI, Antigravity): reads the rules. Claude Code sends every
  tool event to the hooks; Cursor and Codex send shell, MCP and (Codex) patch events to the guard adapters when
  they are installed; Gemini CLI and Antigravity get the rules and the gate only. It may be prompt-injected by
  repo files, web pages or MCP output, so the hooks treat its input as untrusted.
- Project repositories: their files are scanned; their `.claude/`, `.mcp.json`, `.cursor/`, `.codex/` configs are checked.
- The updater: reads public release data from GitHub (it sends the developer's GitHub login only when one
  exists, for private forks) and installs only releases signed with the release key.
- Administrators: managed install under Program Files.

**What it must never do.**
- Leak secrets: it reads `.env` and keys only to scan them locally and never prints secret values.
- Run code from a project or a download without verification (no shelling out with strings; scanners
  run as argument arrays; updates require a valid signature).
- Fail open on the guard: malformed input, errors or over-long commands are blocked.
- Be modifiable by the agent: the guard blocks edits to its own runtime folder; managed installs are read-only.

**Accepted risks (documented, not bugs).**
- The agent guard (7.0) is a positive model, not a sandbox and not a security boundary. Two outside review
  rounds showed that listing dangerous shapes can never be complete (round 2 found 432 bypass shapes), so the
  guard now allows only what it understands:
  - One normalizer runs first. It lexes the command like bash or PowerShell would (quotes, `$'..'`, escapes,
    line continuations, bounded brace expansion, `[^x]` classes), expands `~`, `~user`, `$HOME`, `$env:X`,
    `${X:-y}`, `%X%`, `$PWD`, `[Environment]::GetFolderPath(...)`, follows `cd`, `pushd`, `Set-Location`, `git -C`
    and `--work-tree`, and resolves every path to an absolute, collapsed path, including where links inside the
    project really point.
  - A shell command is allowed only when every statement is a known everyday development command (git, ls, cat,
    grep, sed print and substitute, find without `-exec`, python, node, npm, pip and build tools on project files),
    every path resolves inside the project or a temp folder, and no unmodelled feature is present (functions,
    aliases, `eval`, `$(...)`, process substitution, inline `-c` code, an interpreter fed from a pipe or here-doc,
    a file written and run in the same command, encoded PowerShell).
  - Everything else is the "unknown" class: owner mode asks and shows the literal command, managed mode denies.
    A file or folder below home that is not protected (for example `~/Downloads/x.pdf`) is simply "outside the
    project": ask or deny by mode, never the home-folder hard deny.
  - Hard denies in both modes: reading secrets (also whole folders such as `~/.ssh`), writing the agent's config
    (`~/.claude`, `~/.claude.json`, `CLAUDE_CONFIG_DIR`, other agents' config folders), the org runtime and update
    keys, the 7.0 scanner tools folder (`%LOCALAPPDATA%\NexaForgeTools`, `~/.local/share/nexaforge-tools`,
    `NEXAFORGE_TOOLS_DIR`), the guard policy and audit log, shell, login and Python startup files (`.pth` in
    site folders or outside the project, `sitecustomize`, `usercustomize`, `pyvenv.cfg` outside the project),
    `.git/config` and `.git/hooks`, writes into the home folder itself or a folder above a protected one, and a
    download or decoded data piped into an interpreter.
  - File, MCP and every other tool: the hook matcher is `.*`, and every string argument that looks like a path
    or file URL is judged, whatever its key or nesting.
  - The guard keeps its own 2 second deadline and answers "unknown" when it runs out; every regex is linear.
  The measured ask rate on a corpus of 256 everyday commands is under 1 percent
  (`tests/test_guard_positive_model.py`), and the round-2 Hypothesis fuzzer runs in CI (`tests/test_fuzz_guard.py`).
  **Out of scope, by design:** code execution inside allowed commands. A project script or test the agent wrote
  in an earlier tool call (`python build.py`, `npm test`) can itself open any file; the guard only reads command
  text and cannot see what a program does once it runs. A fully malicious agent with that ability is not stopped
  by any hook. Use Claude Code's native sandbox (OS-level file and network confinement) where it is available;
  native Windows has none today. Commands that only mention a protected place inside free text that the guard
  cannot model (an interpreter here-doc, an unknown tool) are refused, which can be a false positive.
  Up to 6.2.2 the package had five internal review rounds and two outside-style attack rounds (the second
  with fuzzing); the 7.0 guard is the answer to the second attack round. Their regression tests are in
  `tests/test_review*_regressions.py` and `tests/test_guard_positive_model.py`. None of these was a
  third-party audit.
  Known gaps that remain: links created outside the agent after the check, an MCP tool that publishes or
  creates a public repo (only shell commands are classed), and secret gists (only public gists are refused).
- The stop gate and the scanners run git inside the project with a safe environment (`scripts/safe_git.py`):
  `core.fsmonitor` off, an empty hooks folder, every filter, textconv and merge driver the repo defines replaced,
  pager, ssh, credential and editor programs switched off, inherited `GIT_*` variables dropped, and NUL-separated,
  unquoted file names. A repo's `diff.external` cannot be switched off this way; the stop gate passes
  `--no-ext-diff` and `git log` only uses it with `--ext-diff`.
- Global rules and settings: Edit, Write and MultiEdit on the user's own `~/.claude/CLAUDE.md`,
  `~/.claude/rules/**/*.md` and `settings(.local).json` return "ask", never a silent allow and never deny. The
  owner may legitimately ask for a rule change; a prompt-injected agent still needs the owner's yes in the
  prompt. Hooks, skills, agents, commands and anything else in that folder are denied, and shell commands
  may not write any of it. An "ask" is only as strong as the person answering it: approve rule edits only
  when you asked for them. (An older per-user install was seen letting a CLAUDE.md edit through with no prompt; run the updater.
6.2.1 denied `rules/*.md` edits outright; they are "ask" now, like CLAUDE.md.)
- secgate ci mode ignores the scanned repo's own scanner settings (`.gitleaks.toml`, inline `gitleaks:allow`,
  `# nosemgrep`, `.semgrepignore`, `.trivyignore`, `trivy.yaml`, `trivy-secret.yaml`) and uses package-owned
  ones (`config/gitleaks-ci.toml`, `config/ci-empty.ignore`, semgrep's default excludes). gitleaks 8.x always
  reads a repo-root `.gitleaksignore`, so in ci mode that file is itself a HIGH finding. full and quick
  modes still honour the developer's own files on purpose and print a note when they are present.
- Reading inside the user's `.claude` folder with a non-reader command (for example `node -v` started there)
  is refused. That is a deliberate false positive.
- Advisory hooks (injection watch, stop gate, per-edit check) fail open so they never trap a session.
- The per-user install can be removed by its user; enforcement is the managed install and CI.
- Per-user installs run the hooks with the user's own Python, which lives in a user-writable folder. The
  guard blocks the agent from writing `.pth`, `sitecustomize.py` and `py.ini`, but any other program running
  as that user could still disarm the hooks that way. The managed install (all-users Python, read-only
  runtime) is the answer where that matters.
- The guard matches text, so a command that only mentions a protected path inside a string (for example an
  edit to a config template) is blocked too. Use the Edit tool for such files.
- Heuristic rules have false positives; the self-scan suppressions cover the package's own rule tables only
  (and, since 7.0, the deliberately vulnerable labs and test fixtures, each by exact file with an expiry).
- The legacy audit (`malware_scan`) reads `vendor/` and the first 5 MB of image files, because planted code
  hides there. It only reads: it never runs, decodes into a file, moves or deletes anything, and the skill
  tells the agent to show every hit to the owner first. Its patterns are text heuristics: an attacker who
  knows them can write a webshell they miss, so a clean sweep is not proof that a server is clean.
  Known misses, accepted: payloads split across lines (`eval(` on one line, `$_POST[x])` on the next),
  variable indirection (`$c=$_POST[x]; eval($c)`), variable functions built from strings
  (`$f='sys'.'tem'; $f(...)`), `${'_GE'.'T'}`, `extract($_REQUEST)`, a JSP with the parameter and the
  exec on separate lines, and Python `getattr(os,'system')(...)`. A real file-integrity baseline or a
  YARA scan of the live server is the next layer.
- The default-value checks use a short bundled list of guessable passwords and secrets (about 50 each),
  so an uncommon weak password is not found; strong secrets committed to the repo are Gitleaks' job.
- The new code and database checks never print secret values: env findings show the variable name only and
  connection strings are redacted in the finding.

**Per-language engines and their supply chain (7.0).** `scripts/securecode.py setup` installs third-party
scanners into a tools folder outside every project (`%LOCALAPPDATA%\NexaForgeTools`,
`~/.local/share/nexaforge-tools`, or `NEXAFORGE_TOOLS_DIR`). What protects that step, and what does not:
- Nothing installs without `--yes`. The plan printed first names the source, the exact version, the checksum
  and the licence. The agent rules ("ask before installing") still apply on top: the agent shows the plan and
  waits for the owner's yes.
- Direct downloads (osv-scanner, Trivy, Gitleaks, Dependency-Check, Find Security Bugs) are https only, from
  github.com release hosts only (redirects are checked too), size-capped, and verified against the SHA-256 in
  `scripts/engines/engines.lock.json` before anything is extracted. Archives are extracted member by member;
  absolute paths, `..` and links are refused. A mismatch deletes the file and installs nothing.
- pip engines (Bandit, pip-audit, Semgrep) get their own virtual environment. The engine's own wheel is checked
  against the pinned PyPI hash before install. Its dependencies are resolved by pip from your index and are
  NOT hash-pinned: a compromised dependency release on PyPI would still get in. Accepted for now; a full
  hashed lock per engine is planned.
- Go engines (gosec, govulncheck) use `go install module@version` with the Go checksum database forced on
  (`GOSUMDB`, and `GONOSUMDB`, `GOPRIVATE`, `GOINSECURE`, `GOFLAGS` cleared); afterwards the module hash recorded
  in the binary must equal the pinned `h1:` value.
- npm engines (ESLint with eslint-plugin-security, Retire.js) install with `--ignore-scripts` in the tools
  folder (no project `.npmrc`), and the lockfile integrity of each pinned package must equal the registry value.
  Transitive npm packages are not pinned by us.
- Security Code Scan has no checksum we could pin (a NuGet tool package), so it is manual only. CodeQL is never
  installed because of its licence terms.
- The tools folder is user-writable, like PATH. The agent guard denies agent writes there in both modes (also
  through `NEXAFORGE_TOOLS_DIR`), but any other program running as the user could still replace a scanner with
  a fake that reports nothing. CI with freshly installed, hash-checked tools stays the enforcement point.
- Engine output is treated as untrusted input: reports are size-capped, parsed defensively (wrong types are
  skipped, not crashed on), control and bidi characters are stripped from messages, and engines run with
  argument arrays, timeouts and no shell. A `.bat`/`.cmd` call is refused when an argument contains a character
  cmd.exe would re-interpret.
- Engines that would run the project's own code are gated: Psalm and Security Code Scan (MSBuild) run only with
  `--run-tests`; pip-audit runs with `--no-deps --disable-pip` so it never builds or installs the requirements;
  Dependency-Check runs with its yarn, pnpm, npm, bundle-audit, mix, go-mod, dotnet-assembly and OSS Index
  analyzers off; Go engines run with `GOTOOLCHAIN=local`, `CGO_ENABLED=0` and `GOWORK=off`; ESLint loads only
  a config we generate, never the repo's `eslint.config.*` (which is code).
- ci mode stops the scanned repo from configuring these engines: osv-scanner gets a package-owned `--config`
  (repo `osv-scanner.toml` files are ignored), Bandit gets `--ini` (repo `.bandit` ignored) and
  `--ignore-nosec`, gosec gets `-nosec`, ESLint gets `--no-inline-config` and an empty suppressions file (repo
  `eslint-suppressions.json` ignored), npm audit runs on a copy of `package.json` and the lockfile in a private
  folder with an explicit registry (repo `.npmrc` ignored), and Retire.js gets the package's empty
  `--ignorefile`. What ci mode cannot control: Security Code Scan reads `SecurityCodeScan.config.yml`,
  `.editorconfig` and rulesets from the project; Dependency-Check and SpotBugs only scan what is present
  (a repo can leave out compiled classes); a `.gitignore` can hide files from osv-scanner (but such files are
  not committed, so CI does not see them either). Engine failures are NOTE lines, not blocks, so a repo that
  makes an optional engine crash loses that engine's findings; Semgrep, Trivy and Gitleaks still fail closed.
  A Semgrep, Trivy or Gitleaks report that cannot be read (wrong types, deep nesting, huge numbers, oversized)
  is a NOTE "scanner output unreadable" and counts as a failed required scanner, so ci mode blocks.
- Suppression expiry dates must be plain `YYYY-MM-DD`; any other form (`20260115`, `2026-W01`) counts as
  expired, with a NOTE naming the entry.
- Data that leaves the machine: osv-scanner (api.osv.dev), govulncheck (vuln.go.dev), npm audit (the npm
  registry) and pip-audit (PyPI) send package names and versions; Dependency-Check downloads NVD data. No
  source code is sent by any engine.

**Automated pentest scripts (7.0, new attack surface).**
- `report.py` reads `.security/*.json` that scanners filled with text taken from the scanned code and from
  HTTP responses, so every value is attacker-controlled. It redacts secret values (gitleaks-style patterns;
  secret-type findings show no excerpt at all), shows control, zero-width and bidirectional characters as
  `[U+XXXX]`, escapes Markdown (pipes, links, headings, raw HTML) and HTML, and gives REPORT.html a
  `default-src 'none'` CSP so a missed escape still cannot run script. Malformed or oversized (50 MB) input
  gives a BLOCKED report, not a crash. `report_lint.py` refuses overclaims ("100% secure"), unlabelled
  findings, a Pass without evidence, a risk acceptance without a name and date, unmasked secrets and hidden
  characters. Optional PDF printing runs a locally installed Chrome or Edge headless, with a throwaway
  profile, on the local file only.
- `local_dast.py` sends traffic, so its target check is the security boundary. It accepts http(s) only, with no
  user info, backslashes or zone ids in the URL. Hosts are parsed the way browsers parse them (decimal, octal
  and hex IPv4 forms, IPv4-mapped IPv6) and must be loopback; a DNS name is resolved once, every answer must be
  loopback, and ZAP gets the pinned IP literal, so DNS rebinding cannot move the scan. Anything else needs the
  existing person-set `SECURITY_DAST_ALLOW=true` plus an exact `SECURITY_DAST_URL` and the staging checks of
  `run-nuclei-authorized.py`.
- Staging scans (`run-nuclei-authorized.py`, `run-zap-authorized.py`, and local_dast's staging mode) share
  `scripts/dast_target.py`: the same browser-style host parsing, the name resolved once and every answer checked
  (IPv4 inside IPv6 too: mapped, compatible, NAT64, 6to4, Teredo). Cloud metadata names and addresses
  (`metadata`, `metadata.goog`, `metadata.google.internal`, `metadata.azure.com`, `instance-data`,
  169.254.169.254, 169.254.170.2, fd00:ec2::254, 100.100.100.200), link-local, multicast and reserved addresses
  are always refused; private and loopback ones only pass when a person names the exact host in
  `SECURITY_DAST_PRIVATE_HOSTS`. ZAP gets the checked answer pinned with `docker --add-host`, and docker is
  taken from an absolute PATH entry. Accepted: nuclei resolves the name again itself, so a host whose DNS
  answer changes between the check and the scan can still move a nuclei scan; the URL is set by a person. With Docker on Windows or macOS the container reaches the host through Docker
  Desktop's fixed `host.docker.internal` name (not attacker DNS); on Linux it uses host networking. The ZAP
  image is pinned by digest. The ZAP plan is written as JSON, so no value can change its structure.
  `--start` is the only way it starts a program: the command typed by the person, split into an argument list
  (no shell; shell operators refused; the program looked up on PATH, never in the project folder; cmd.exe
  metacharacters refused on Windows), refused when the port is already taken, with a start timeout and a
  process-tree teardown. Accepted: the agent could still pass `--start` itself. The skill tells it to use only
  the developer's own command, and the agent guard's normal rules apply to that command line. The developer's
  app is a program they asked to run; `--active` sends attack payloads to it and is opt-in.
- `fix_pr.py` writes to git and GitHub. It is a dry run unless `--open` is given. It never stages untracked
  files (only `git add -u`, plus files named one by one with `--add`, which must be inside the repo, not
  ignored, and not secret-looking names such as `.env` or key files); it refuses when new files are already
  staged that were not named; it refuses without gitleaks and when gitleaks or the built-in patterns find a
  secret in the added lines; it creates only `securecode/fix-YYYYMMDD[-n]` branches, refuses the default and
  protected branch names, pushes an explicit refspec with no force, and the agent guard asks the person before
  the push. The PR body is the escaped report summary. Accepted: the PR holds code the agent wrote; a person
  still reviews it before merging.

**Owner mode vs managed mode (7.0).** The guard's policy file `config/guard-policy.json` lives in its own
runtime folder, never in a project, so a cloned repo cannot choose its mode.
- Owner mode (the per-user default) trusts the person at the keyboard: destructive actions (force, mirror or
  delete push, `git reset --hard`, `git branch -D`) and exposure actions (public repo or gist, package publish)
  become an "ask" that shows the literal command, with the collapsed form added when it differs, and control,
  bidi and invisible characters spelled out. The threat it still handles is a prompt-injected agent: it cannot
  do these without the person's yes, and the person sees exactly what will run. The accepted risk is the person
  approving without reading. A command too long to show (over 2000 characters) is denied.
- Managed mode (written by `install-managed.py` into the read-only runtime) trusts nobody at the keyboard: those
  classes are denied as in 6.2. A per-user owner policy is ignored when `managed-settings.json` or the managed
  runtime exists on the machine (Program Files on Windows, `/Library/Application Support/ClaudeCode` on macOS,
  `/etc/claude-code` on Linux).
- Fail closed: a missing, unreadable, oversized, linked or malformed policy (unknown keys, duplicate keys, a mode
  other than the two names) means managed mode. The repo checkout ships no policy file, so it runs managed.
- Never relaxed in either mode: secrets (never an "ask"), pipe-to-shell, writes to the agent's own config, the
  runtime, update keys, the policy file and the audit log, home and root deletes, and evasion routes (git
  aliases or config that turn a push into a force push, `gh api --input`). Each statement is checked by every
  deny rule even when it also matches a class, so `git push -f > ~/.claude/x` stays a deny.
- Anything outside the positive model (the "unknown" class: an unknown command, a path outside the project,
  inline interpreter code, an unmodelled shell feature) asks in owner mode and is denied in managed mode.
- New dependencies (`npm i x`, `pip install x`, ...) ask in both modes. In owner mode the installer also moves the
  three force-push and hard-reset Claude Code permission rules from deny to ask; otherwise they would refuse
  before the guard could ask.
- Audit: every "ask" appends one line to `.security/guard-audit.jsonl` in the project (UTC time, mode, tool,
  command and reason, truncated, with token-like values, inline passwords and URL credentials removed). The
  agent may not write that file through the guard, but it is a convenience record in a project folder, not a
  tamper-proof log (the agent can still delete `.security/` as a whole). It does not record the person's answer.
  The write refuses links, junctions, hard links, the home folder and drive roots.
- Known gaps: an MCP tool that publishes or creates a public repo is not classed (only shell commands are);
  `sudo -u user npm publish` and other wrappers with arguments may not be recognized as a publish; branch
  deletes through other tools are not seen.

**Cursor and Codex adapters.** `scripts/adapters/cursor_hook.py` maps Cursor's `beforeShellExecution`,
`beforeMCPExecution` and `beforeReadFile` hooks to the same checks; Cursor has no hook before file edits, so
Cursor's own edits are not checked by the guard. `beforeReadFile` cannot ask, so an ask is a deny there. The
template sets `failClosed: true`, because Cursor otherwise lets the action through when a hook crashes.
`scripts/adapters/codex_hook.py` covers Codex `PreToolUse` (shell, `apply_patch` file names, MCP); Codex parses
an "ask" but runs the tool anyway, so the adapter turns every ask into a deny. Codex documents its hooks as a
guardrail, not a complete boundary, and hosted tools such as web search bypass them.

**Secret shield (7.0, PostToolUse).** `scripts/secret_shield.py` sees the output of Bash, BashOutput,
PowerShell, Read, Grep, WebFetch and MCP tools. When a high-confidence secret pattern matches it returns
`updatedToolOutput` (a copy of the output in the same shape, every secret value replaced by a typed marker;
documented for all tools) plus `decision: "block"` with a reason that names the source and type, never the
value, and an audit line in `.security/shield-audit.jsonl` (no values).
- Trust: the tool output is attacker-controlled text. The shield only pattern-matches it; it never runs,
  decodes into a file or follows it. Every regex is bounded (linear per start position), the scan is capped at
  2 million characters and a 4 second deadline, nesting deeper than 64 levels is withheld.
- Fail-safe choice: output beyond the cap or the deadline is withheld (fail closed); malformed input and
  internal errors fail open, the latter with a warning to the agent, because a PostToolUse hook cannot un-run
  the tool, a crashed or timed-out hook is non-blocking in Claude Code anyway, and a broken redactor must not
  trap every session.
- Accepted: the tool already ran (the guard is the preventive control); telemetry keeps the original output and
  the transcript may too (open finding V7S-05; `sweep` lists what leaked, read only, masked); the audit file is
  in the project and not yet guard-protected (V7S-06); documentation example keys pass through unchanged.

**MCP scan (7.0).** `scripts/mcp_scan.py` reads MCP configs of Claude Code, Cursor, Codex, Gemini CLI and VS
Code, prints env and header names only, and flags risky launches. secgate full and ci run it on project
configs only (never user files, never a connect).
- `--connect NAME --yes` starts one named stdio server: it is code execution by design, so the command is
  printed first, nothing starts without `--yes`, the program is looked up on PATH only (never the project
  folder), `.bat`/`.cmd` with cmd.exe metacharacters are refused, the answer is size-capped and time-limited,
  and the process tree is killed afterwards. Remote servers are never contacted. Tool text is untrusted:
  findings show it redacted, cut short, with hidden characters spelled out.
- The lock (`.security/mcp-lock.json`) pins tool, instruction and launch hashes. It is refused through links.
  Accepted: whoever can write the project can re-pin (V7S-06); the regex checks catch common poisoning shapes,
  not all of them.

**End-of-task pentest offer.** `stop_gate.py` asks the agent once to offer "Run Security Test" when 3 or more code
files or 40 or more changed lines (added plus deleted; all lines of a new file) changed since the last offer and no
ci or full gate report is newer than those changes. The offer is recorded in `.security/pentest-offer.json`
before it is shown, so it comes once per change set; if that record cannot be written or read, no offer is made
(it never nags). It is a nudge, not a control: the agent can write that file or a fake report to silence it.

**Deployment.** Per user (`%LOCALAPPDATA%\OrgAISecureAppSec`), managed (`%ProgramFiles%\OrgAISecureAppSec`),
CI (pinned, hash-verified scanners). Updates from the public GitHub repo `farhan6667/nexaforge-securecode`
(or an organization's own fork), signed with an offline ed25519 key.
