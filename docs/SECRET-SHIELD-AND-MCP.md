# Secret shield and MCP scan (7.0)

Two 7.0 features that close gaps the agent guard leaves open. The secret shield keeps secrets out of what the
AI agent reads back from its tools. The MCP scan checks the MCP servers your agents are set up to start,
without starting them, and can pin each server's tool list so a silent change shows up.

Both run offline. Nothing is sent to a vendor.

## Secret shield

### What it does

The agent guard stops the agent from opening `.env` files and key files. A secret can still reach the model
through output the guard allows: `cat config.php`, a failing test that prints a connection string, an
environment dump, a search hit, a web page, or an MCP tool's answer.

`scripts/secret_shield.py` runs as a Claude Code PostToolUse hook for `Bash`, `BashOutput`, `PowerShell`,
`Read`, `Grep`, `WebFetch` and every `mcp__` tool. It scans the tool's output and, when it finds a secret:

1. Gives Claude Code a copy of the output in which each secret value is replaced by a marker such as
   `[REDACTED by secret shield: github-token]`. This uses `updatedToolOutput`, which the Claude Code hooks
   reference documents for all tools ("Replaces the tool's output with the provided value before it is sent
   to Claude. The value must match the tool's output shape"). The shield copies the original output and only
   changes the strings inside it, so the shape always matches (for `Bash`: `stdout`, `stderr`,
   `interrupted`, `isImage`; for `Read`: `type` and `file` with its numbers).
2. Returns `decision: "block"` with a reason that names the file or command and the secret type, never the
   value, and tells the agent to stop, not to fetch the secret another way, and to ask you. `"block"` on its
   own does not hide output (the docs say Claude still sees the original); it is there so an older Claude
   Code that ignores `updatedToolOutput` still gets the instruction.
3. Appends one line to `.security/shield-audit.jsonl` in the project: time, tool, source (redacted), secret
   types and count. Never a value.

Documentation examples and placeholders are left alone: AWS's published example keys (they end in
`EXAMPLE`), the jwt.io sample token, `your_api_key_here`, `${VAR}` references, `process.env.X`, repeated
characters, and private key headers with no key body. The sweep can list them as LOW with `--include-examples`.

### What it detects

| Type | Examples of what matches |
|---|---|
| Cloud keys | AWS access key ids and secret keys, Google API keys, Azure storage account keys |
| Code hosts | GitHub classic and fine-grained tokens, GitLab tokens |
| Chat and payments | Slack tokens and webhook URLs, Stripe live and test keys |
| AI and package registries | Anthropic and OpenAI keys, npm and PyPI tokens |
| Private keys | `-----BEGIN ... PRIVATE KEY-----` blocks (RSA, EC, OpenSSH, PGP and others) |
| Tokens and URLs | JWTs, database URLs with a password (Postgres, MySQL, MongoDB, Redis, AMQP, SQL Server, JDBC), other URLs with a password |
| HTTP headers | `Authorization: Bearer ...`, `Basic ...` and `token ...` values (curl -v output, request logs) |
| XML config | `<password>...</password>` and `key="DbPassword" value="..."` pairs (web.config, NuGet.config, Maven settings.xml) |
| Generic | A secret-named key (`password`, `client_secret`, `api_key`, `token`, ...) assigned a long, random-looking value |

Terminal colour codes and NUL bytes between characters (UTF-16 text printed by a UTF-8 tool) are ignored while
scanning, so a coloured `rg --color always` hit is still found.

### Fail-safe behaviour

A PostToolUse hook runs after the tool already ran, so the choice is about what the model sees:

| Situation | What happens | Why |
|---|---|---|
| Secret found | Output replaced, block reason, audit line | The strongest documented mechanism |
| Output bigger than 2 million characters, or the scan passes its own 4 second deadline | The part that was not scanned is replaced by a "withheld, not scanned" marker (fail closed) | We cannot vouch for text we did not read. Claude Code shortens big outputs anyway |
| Malformed hook input | Exit 0, no output | There is no output we could replace |
| Unexpected internal error | Exit 0 with a warning to the agent (fail open) | A broken redactor cannot be trusted to build a correct replacement, and a hook that breaks every call would trap the session |
| The hook process crashes or hits the 20 second hook timeout | Claude Code treats it as non-blocking and shows the original output (fail open) | This is Claude Code's own rule for PostToolUse; the 4 second internal deadline keeps us far from it |

Every regex has bounded repetition and no nested quantifiers. The tests feed 1 to 2 MB "regex bombs" and
check each finishes inside the budget.

### What it does not do

- It does not stop the tool from running. A command that sends a secret somewhere has already done so; the
  agent guard (PreToolUse) is the control for that.
- It cannot promise the secret stays out of the local transcript. The docs say telemetry captures the
  original output before the hook runs, and do not say which version the transcript keeps. Run the sweep.
- Secrets in the tool's input (the command the agent typed) are not changed; that text came from the model.
- The `Monitor` tool streams output as notifications, not as a tool result, so the shield does not see it.
- Images, PDFs and other binary payloads (base64 data) pass through unscanned, so they are never corrupted.
  A secret shown inside a screenshot is not caught.
- Pattern matching misses secrets with no recognisable shape (a short password in a field called `pw`).
- The audit file lives in the project and the agent could delete `.security/`. It is a record, not proof.

### Sweep: find secrets that already leaked

```
py -I scripts/secret_shield.py sweep              # Claude Code transcripts and this project's log files
py -I scripts/secret_shield.py sweep path/to/logs  # any files or folders
py -I scripts/secret_shield.py sweep --json
```

With no path it reads `~/.claude/projects` (or `CLAUDE_CONFIG_DIR/projects`) and the project's `*.log` files
and `logs/`, `log/`, `storage/logs/`, `var/log/` folders. It only reads. For each hit it prints the file, line,
type and a masked preview (a public prefix like `ghp_` and the length, never the value), then how to revoke
each kind. It exits 1 when a live secret was found. It never edits a transcript: revoke first, then delete or
redact the listed files yourself.

## MCP scan

### Config mode (offline, default)

```
py -I scripts/mcp_scan.py                 # project and user configs
py -I scripts/mcp_scan.py --project-only  # what the gate runs
py -I scripts/mcp_scan.py --json
```

It reads these files and never changes them:

| Client | Project file | User file |
|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json` (top-level servers and this project's entry) |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| Codex | `.codex/config.toml` | `~/.codex/config.toml` (or `CODEX_HOME`) |
| Gemini CLI | `.gemini/settings.json` | `~/.gemini/settings.json` |
| VS Code | `.vscode/mcp.json` | |

It lists every server with its command, arguments (secret-looking values redacted) and the NAMES of its env
variables and headers, never their values. It flags:

| Rule | Severity | Meaning |
|---|---|---|
| MCP_PIPE_TO_SHELL | HIGH | The launch downloads a script and pipes it into a shell |
| MCP_INSECURE_REMOTE | HIGH (LOW on loopback) | Remote server over plain http |
| MCP_FILESYSTEM_ROOT | HIGH | The server is handed `/` or a whole drive |
| MCP_INLINE_SECRET | HIGH | A literal secret in env, a header, an argument or the URL |
| MCP_DOCKER_PRIVILEGED | HIGH | `docker run --privileged` |
| MCP_FILESYSTEM_HOME | MEDIUM | The server is handed the whole home folder |
| MCP_UNPINNED_PACKAGE | MEDIUM | `npx`, `uvx`, `pipx run`, `pnpm dlx`, `docker run` without an exact version or digest, or `@latest` |
| MCP_SHELL_WRAPPER | MEDIUM (LOW for a plain `cmd /c npx ...`) | Started through `bash -c` or `cmd /c` with shell operators, which hides what runs. The command inside the wrapper is still checked for pinning |
| MCP_TRUSTED_SERVER | MEDIUM | Gemini `trust: true` (tools run without asking) |
| MCP_LAUNCH_CHANGED | MEDIUM | The launch differs from the one pinned in the lock |
| MCP_UNSCOPED_PACKAGE | LOW | An unscoped npm name, easier to typosquat |
| MCP_INLINE_SECRET_EXAMPLE | LOW | A placeholder value where a secret would go |

`secgate.py --mode full` and `--mode ci` run this mode on the project's own configs and include the findings.
The gate never reads user-level files (the result must not depend on whose machine runs it) and never starts
a server.

### Connect mode: check the tools a server offers

```
py -I scripts/mcp_scan.py --connect my-server            # prints the exact command, starts nothing
py -I scripts/mcp_scan.py --connect my-server --yes      # starts it, lists tools, pins hashes
py -I scripts/mcp_scan.py --connect my-server --yes --approve   # accept a change you reviewed
```

Starting a server runs its code on your machine, so it only happens for stdio servers you name, and only with
`--yes`. Remote (http) servers are never contacted. The program is looked up on PATH, never in the project
folder. The scan sends `initialize` and `tools/list` over JSON-RPC, waits at most `--timeout` seconds (20 by
default), then kills the server's process tree.

It checks every tool's name, description and input schema, and the server's instructions, for:

| Rule | Severity | Sign |
|---|---|---|
| MCP_TOOL_HIDDEN_UNICODE | HIGH | Zero-width, bidirectional or Unicode tag characters |
| MCP_TOOL_INJECTION | HIGH | Text aimed at the model: `<IMPORTANT>`, "ignore previous instructions", "do not tell the user" |
| MCP_TOOL_EXFIL | HIGH | Send, upload or forward the result, a file, the conversation or credentials to a URL |
| MCP_TOOL_SENSITIVE_PATH | HIGH | Mentions `~/.ssh`, `id_rsa`, `.aws/credentials`, `.netrc`, `mcp.json`, `.claude.json` |
| MCP_TOOL_DIRECTIVE | MEDIUM | Weaker directions that honest tools also use: "before using this tool", "system prompt" |
| MCP_TOOL_SHADOWING | HIGH | Tries to change how another tool is used ("when you use the send_email tool, also ...") |
| MCP_TOOL_CROSS_REFERENCE | MEDIUM | Names another server's tool |
| MCP_TOOL_LONG_DESCRIPTION | LOW | Over 4000 characters |

Then it pins a SHA-256 of each tool (name, title, description, input and output schema, annotations), of the
server instructions and of the launch line in `.security/mcp-lock.json`. The first clean run pins
automatically. A server with HIGH findings is not pinned until you pass `--approve`. On later runs a changed
tool hash or changed instructions is HIGH (the rug-pull pattern: a server that was approved and then changed
its tools) and stays HIGH until you review and `--approve`. A new tool is MEDIUM, a removed one LOW.

### Limits

- Regex checks find common poisoning shapes, not every one. A careful attacker can phrase an instruction that
  none of them catch; read new tool descriptions yourself.
- Connect mode sees what the server says today. A server can behave differently for other clients or later
  calls; the lock only notices changes in what `tools/list` returns.
- The lock lives in `.security/` in the project; anyone who can write there can re-pin.
- Resources, prompts and skills are not scanned yet.
