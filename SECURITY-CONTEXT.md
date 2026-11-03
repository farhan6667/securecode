# Security context (threat model) for NexaForge SecureCode itself

**What it is.** Python scripts, Claude Code hooks and settings, and Markdown instructions installed on
developer machines, plus CI templates. It runs with the developer's own rights and sees their code.

**Who or what can reach it.**
- The AI agent (Claude Code, Cursor, Codex, Gemini CLI, Antigravity): reads the rules; Claude Code also sends
  tool events to the hooks. It may be
  prompt-injected by repo files, web pages or MCP output, so the hooks treat its input as untrusted.
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
- The agent guard is a pattern-based, best-effort layer. It is not a sandbox and not a security boundary.
  It reads command text, so an attacker who already has arbitrary code execution (a script that opens files
  itself, paths built at run time from variables, unusual encodings, interpreters and tools the guard has
  never heard of) can still find gaps. Each review round has found new ones, and more will exist. Native
  Windows has no Claude Code OS sandbox; 7.0 plans a real sandbox (OS-level file and network confinement for
  the agent) so the guard becomes a second line instead of the only one.
  What it does today: any shell command that names the agent's own config folder or the runtime is refused
  unless every stage only reads (no method calls, script blocks, `$(...)` or write options such as `sort -o`);
  wildcards are judged by what they could expand to (`.cl*`, `OrgAIS*`, `id*`, `*env`); a command other than a
  plain reader may not target the home folder itself or a folder above a protected one (tree copies and
  archive extraction into `~`); macOS `/Users/x`, root-relative `\Users\x`, `~user`, `%SystemDrive%` and
  `Documents and Settings` count as home.
  Known gaps that remain: paths built at run time, links created outside the agent, MCP tools that hide a
  path deep inside nested arguments, plain shell aliases defined earlier in the session, a downloader
  hidden inside a script file, and secret gists (only public gists are refused). Up to 6.2.2 the package had
  five internal review rounds and two outside-style attack rounds (the second with fuzzing); their regression
  tests are in `tests/test_review*_regressions.py`. None of these was a third-party audit.
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
- The tools folder is user-writable, like PATH. A program running as the user (or a prompt-injected agent
  allowed to write there) could replace a scanner with a fake that reports nothing. The agent guard does not
  protect this folder yet. CI with freshly installed, hash-checked tools stays the enforcement point.
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

**Deployment.** Per user (`%LOCALAPPDATA%\OrgAISecureAppSec`), managed (`%ProgramFiles%\OrgAISecureAppSec`),
CI (pinned, hash-verified scanners). Updates from the public GitHub repo `farhan6667/nexaforge-securecode`
(or an organization's own fork), signed with an offline ed25519 key.
