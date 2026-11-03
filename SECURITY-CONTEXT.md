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
- Pattern-based guard: a determined command (a script that opens files itself, unusual encodings) can get
  past it. It reduces risk; it is not a sandbox. Native Windows has no Claude Code OS sandbox. Since 6.2 any
  shell command that names the agent's own config folder is refused unless it only reads, so new write
  routes need no new rule. Known gaps that remain: paths built at run time from variables the guard cannot
  see, links created outside the agent, MCP tools that hide a path deep inside nested arguments, and plain
  shell aliases defined earlier in the session. Four independent review rounds and their regression tests
  are in `tests/test_review*_regressions.py`.
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

**Deployment.** Per user (`%LOCALAPPDATA%\OrgAISecureAppSec`), managed (`%ProgramFiles%\OrgAISecureAppSec`),
CI (pinned, hash-verified scanners). Updates from the public GitHub repo `farhan6667/nexaforge-securecode`
(or an organization's own fork), signed with an offline ed25519 key.
