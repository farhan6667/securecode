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

**End-of-task pentest offer.** `stop_gate.py` asks the agent once to offer "Run Security Test" when 3 or more code
files or 40 or more changed lines (added plus deleted; all lines of a new file) changed since the last offer and no
ci or full gate report is newer than those changes. The offer is recorded in `.security/pentest-offer.json`
before it is shown, so it comes once per change set; if that record cannot be written or read, no offer is made
(it never nags). It is a nudge, not a control: the agent can write that file or a fake report to silence it.

**Deployment.** Per user (`%LOCALAPPDATA%\OrgAISecureAppSec`), managed (`%ProgramFiles%\OrgAISecureAppSec`),
CI (pinned, hash-verified scanners). Updates from the public GitHub repo `farhan6667/nexaforge-securecode`
(or an organization's own fork), signed with an offline ed25519 key.
