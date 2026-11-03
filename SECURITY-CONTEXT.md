# Security context (threat model) for NexaForge SecureCode itself

**What it is.** Python scripts, Claude Code hooks and settings, and Markdown instructions installed on
developer machines, plus CI templates. It runs with the developer's own rights and sees their code.

**Who or what can reach it.**
- The AI agent (Claude Code, Cursor, Codex): sends tool events to the hooks; reads the rules. It may be
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
  hidden inside a script file, and secret gists (only public gists are refused). Six independent review
  rounds and their regression tests are in `tests/test_review*_regressions.py`.
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
- Heuristic rules have false positives; the self-scan suppressions cover the package's own rule tables only.

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
  `run-nuclei-authorized.py`. With Docker on Windows or macOS the container reaches the host through Docker
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
