# AI agent security (7.0)

AI coding agents read untrusted text (repo files, web pages, tool and MCP output) and can run
commands on the developer's machine. That makes the agent itself an attack surface, separate
from the code it writes. This document lists the threats, what the package does about them in
each tool, and what stays manual.

## Real incidents this is based on (2025-2026)

| Incident | What happened | Our control |
|---|---|---|
| Rules File Backdoor (Pillar Security, 2025) | Hidden zero-width/bidi Unicode in Cursor and Copilot rules files made the agent add backdoors. | Gate flags `HIDDEN_UNICODE` in instruction files; injection watch warns on read. |
| Claude Code project-file CVEs (Check Point; CVE-2025-59536, CVE-2026-21852) | Repo `.claude/settings.json` hooks, auto-approved project MCP servers or `ANTHROPIC_BASE_URL` ran or leaked the API key before the trust prompt. Fixed in later versions. | Keep Claude Code updated (trust-dialog bypass CVE-2026-40068 fixed in 2.1.84); `enableAllProjectMcpServers: false`; gate flags `REPO_AGENT_HOOKS`, `MCP_AUTO_APPROVE`. |
| Cursor CurXecute / MCPoison (CVE-2025-54135, CVE-2025-54136) | Prompt injection wrote or silently changed MCP config and got code execution. Fixed in Cursor 1.3. | Update Cursor; gate flags `REPO_MCP_SERVERS`; policy: MCP config changes need review. |
| Codex CLI CVE-2025-61260 | Repo config (via `CODEX_HOME`) made MCP commands run silently. Fixed in 0.23.0. | Update Codex; gate flags `AGENT_HOME_OVERRIDE`. |
| Gemini CLI (Tracebit, 2025) | Injected README text chained a harmful command after an allowlisted one. | Guard checks the whole command string, not only its first word. |
| Amazon Q extension 1.84.0 (CVE-2025-8217) | A malicious prompt telling the agent to wipe local and cloud resources was merged into a release. | Policy: never weaken controls, ask before destructive or cloud admin actions. |
| Nx "s1ngularity" (GHSA-cxm3-wv7p-598c) | A malicious package used local AI CLIs to hunt for secrets, published them to public repos, and edited shell startup files. | Guard blocks secret files, `gh repo create --public`, writes to `.bashrc`/`.zshrc`/PowerShell profile; deny rules. |
| MCP tool poisoning (Invariant Labs, 2025) | Hidden instructions in a tool description exfiltrated chat history through another trusted MCP. | Policy: tool output is data; injection watch on `mcp__*` output; approve MCP servers one by one. |
| Slopsquatting (USENIX Security 2025) | AI suggests package names that do not exist; attackers register them. | Policy and `ask` rules: every new dependency needs a yes and a name/age check. |

Sources: see `docs/SOURCES.md`.

## What runs where

| Control | Claude Code | Cursor | Codex | Gemini CLI | Antigravity |
|---|---|---|---|---|---|
| Org rules (`AGENTS.md` / global CLAUDE.md block) | yes, auto | User Rules (paste) | `~/.codex/AGENTS.md` | `~/.gemini/AGENTS.md` + `context.fileName` | `~/.gemini/AGENTS.md` (read natively) |
| PreToolUse agent guard (secrets, pipe-to-shell, force push, startup files) | yes, every tool | shell, MCP and file reads through `scripts/adapters/cursor_hook.py`, installed by hand. Cursor's generic preToolUse hook is not wired to the guard yet, so Cursor's own file edits are not checked | shell, `apply_patch` and MCP through `scripts/adapters/codex_hook.py`, installed by hand ("ask" becomes deny: Codex hooks cannot ask yet), plus `templates/codex/rules/org.rules` | every tool through `scripts/adapters/gemini_hook.py` (`BeforeTool`), installed by hand ("ask" becomes deny: Gemini CLI hooks have no ask) | every tool through `scripts/adapters/antigravity_hook.py` (`PreToolUse`), installed by hand; asks work; what happens when the hook itself fails is untested |
| End-of-task "Run Security Test" offer | Stop hook + rule | rule only | Stop hook (`stop_gate.py`) + rule | rule only | rule only |
| Deny/ask permissions | yes (`config/agent-permissions.json`) | `.cursorignore` for `.env*`, approval prompts | `approval_policy`, execpolicy rules | tool approval prompts | permission settings |
| Per-edit heuristic scan | yes | no | no | no | no |
| Injection watch on Read/WebFetch/MCP output | yes (advisory) | no | no | no | no |
| Full gate `secgate.py --mode ci` | yes | yes (agent runs it) | yes (agent runs it) | yes (agent runs it) | yes (agent runs it) |
| OS sandbox | macOS, Linux, WSL2 only (not native Windows) | tool-dependent | `sandbox_mode = "workspace-write"` | tool-dependent | tool-dependent |

## Setup per tool

Guard hooks for Cursor, Codex, Gemini CLI and Antigravity are written by the installer. Run it from the
extracted `aisec` folder and name each tool (repeat `--agent` for several):

```powershell
py -I install-global.py --agent cursor --agent codex --agent gemini --agent antigravity
```

| `--agent` | File it writes | What it adds |
|---|---|---|
| `cursor` | `~/.cursor/hooks.json` | `cursor_hook.py` on `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, with `"failClosed": true` |
| `codex` | `~/.codex/hooks.json` (`$CODEX_HOME/hooks.json` when set) | `codex_hook.py` on `PreToolUse` and the stop gate on `Stop` |
| `gemini` | `~/.gemini/settings.json` | `gemini_hook.py` as a `BeforeTool` hook on every tool (on Windows the PowerShell form with a leading `&`) |
| `antigravity` | `~/.gemini/config/hooks.json` | the `org-ai-agent-guard` block running `antigravity_hook.py` on `PreToolUse` |

It fills in the Python that runs the installer and the runtime folder (forward slashes), backs up an existing
file to the runtime's `backups` folder, and merges: your other settings and hooks stay, and our earlier entries
are replaced, so running it again changes nothing. A file that is not valid JSON (comments included) or a
linked file is refused with a message and left untouched. Later runs of the installer, including auto-updates,
refresh the hooks it wrote, unless you removed them. `verify-global.py` lists the tools that have the hook
under `adapters`. Then do the per-tool step below (trust the hooks in Codex, `/hooks` to check). The manual way
is in the block at the end of this section.

- **Claude Code**: `install-windows.ps1` does everything. Admins who want rules users cannot switch
  off deploy `enterprise-managed-settings.example.json` to `C:\Program Files\ClaudeCode\managed-settings.json`
  (it sets `disableBypassPermissionsMode`, `enableAllProjectMcpServers: false`, `allowManagedHooksOnly`).
  Test on a pilot group first: `allowManagedHooksOnly` turns off every user and project hook.
- **Cursor**: paste `AGENTS.md` into Settings > Rules > User Rules; add `.env*`, `*.pem`, `*.key` to
  `.cursorignore` in each project; turn on Workspace Trust (`security.workspace.trust.enabled`);
  approve MCP servers one at a time. `.cursorignore` does not cover terminal or MCP tools.
  Guard hooks: `install-global.py --agent cursor` (the enterprise path `C:\ProgramData\Cursor\hooks.json` is
  manual, see below). Keep `"failClosed": true`: without it Cursor lets the action
  through when the hook crashes or times out. Cursor's `beforeReadFile` cannot ask, so an "ask" there is a deny.
- **Codex**: copy `AGENTS.md` to `~/.codex/AGENTS.md`, merge `templates/codex/config.toml` into
  `~/.codex/config.toml`, copy `templates/codex/rules/org.rules` to `~/.codex/rules/`. Guard and stop hooks:
  `install-global.py --agent codex`, then trust the hooks in `/hooks` (Codex skips untrusted hooks; managed `requirements.toml` hooks are trusted by policy).
  On Windows Codex uses `commandWindows` and runs it in the session shell (PowerShell, cmd or bash), so that line
  starts with an unquoted `<PYTHON>` that has no spaces: a quoted first word is a parse error in PowerShell and
  `&` is an error in cmd. The installer writes the 8.3 short path of Python there, and refuses the adapter with a
  message when Windows gives no space-free short path (then install Python to a folder without spaces). `pwsh -Command` also turns exit 2 into 1, which Codex counts as
  a failed hook and then runs the tool, so the adapter answers a deny with exit 0 and Codex's JSON
  `permissionDecision: "deny"` (finding V7L-02, checked against the Codex source, not yet in a live Codex run).
  Codex parses a hook "ask" but does not support it yet and would run the tool, so the adapter turns every
  ask into a deny with the reason; the developer runs such a command themselves.
- **Gemini CLI**: copy `AGENTS.md` to `~/.gemini/AGENTS.md` and merge `templates/gemini/settings.json`
  (`"context": {"fileName": ["AGENTS.md", "GEMINI.md"]}`) into `~/.gemini/settings.json`; or copy
  `templates/gemini/GEMINI.md` (it imports `AGENTS.md` with `@./AGENTS.md`). Check with `/memory show`.
  Docs: https://geminicli.com/docs/cli/gemini-md/ and https://geminicli.com/docs/reference/memport/
- **Antigravity**: copy `AGENTS.md` to `~/.gemini/AGENTS.md`; Antigravity reads it (and project
  `AGENTS.md`, `GEMINI.md`, `.agents/rules/*.md`) without a setting. Docs: https://antigravity.google/docs/rules/
- Guard hooks for Gemini CLI: `install-global.py --agent gemini` (merges into `~/.gemini/settings.json`). On
  Windows it writes `templates/gemini/settings.hooks.windows.json`, because Gemini CLI runs hooks in PowerShell
  there and the line needs a leading `&` (finding V7L-01). A hook line that fails before Python starts lets the
  tool run, so test one blocked action after installing. It runs `scripts/adapters/gemini_hook.py` as a `BeforeTool` hook on every
  tool (https://geminicli.com/docs/hooks/reference/). Gemini CLI lets a tool run when a hook exits with any code
  other than 0 or 2 or prints text that is not JSON, so the adapter only exits 0 (allow) or 2 (deny) and denies
  on every error. There is no "ask" decision, so an ask becomes a deny with the reason.
- Guard hooks for Antigravity: `install-global.py --agent antigravity` (writes `~/.gemini/config/hooks.json`,
  from `templates/antigravity/hooks.windows.json` with the 8.3 short path of Python on Windows; for one
  workspace only, `.agents/hooks.json` is manual), and check it with `/hooks`. It runs
  `scripts/adapters/antigravity_hook.py` as a `PreToolUse` hook (https://antigravity.google/docs/hooks/). Asks
  are sent as `force_ask`, so a cached "Always Allow" cannot skip them. The docs describe only the JSON decision,
  not exit codes or timeouts, so the adapter always prints an explicit decision; whether Antigravity blocks a
  call when the hook itself crashes or times out is untested. The docs do not name the shell either, so the
  Windows line starts with an unquoted, space-free `<PYTHON>`, which PowerShell, Windows PowerShell and cmd all
  run (tested in those shells, not yet in a live Antigravity session). Details: `templates/gemini/README.md`.

<details>
<summary>Install the guard hooks by hand instead</summary>

Back up the target file first. Copy the template, or merge it into an existing file (keep your other keys and
hooks), and replace `<PYTHON>` with the full path of the Python that installed SecureCode and `<APP>` with the
runtime folder (Windows `%LOCALAPPDATA%\OrgAISecureAppSec`), both with forward slashes.

| Tool | Template | Target |
|---|---|---|
| Cursor | `templates/cursor/hooks.json` | `~/.cursor/hooks.json`, or the enterprise path `C:\ProgramData\Cursor\hooks.json` |
| Codex | `templates/codex/hooks.json` | `~/.codex/hooks.json` |
| Gemini CLI | `templates/gemini/settings.hooks.json` | merge into `~/.gemini/settings.json` |
| Antigravity | `templates/antigravity/hooks.json` | `~/.gemini/config/hooks.json`, or `.agents/hooks.json` in one workspace |

</details>

## Owner mode and managed mode

The guard reads `config/guard-policy.json` from its own runtime folder (never from the project).

| Class | Examples | Owner mode (per-user default) | Managed mode |
|---|---|---|---|
| secret | read or send `.env`, keys, credentials | deny | deny |
| pipe-to-shell | `curl ... \| sh`, `iex (irm ...)` | deny | deny |
| agent config | hooks, skills, runtime, update keys, the policy file itself | deny (CLAUDE.md, rules, settings.json: ask) | same |
| destructive | force, mirror or delete push, `git reset --hard`, `git branch -D` | ask, showing the literal command | deny |
| exposure | public repo or gist, `npm publish`, `twine upload`, `cargo publish` ... | ask, showing the literal command | deny |
| install | `npm i x`, `pip install x`, `composer require x` ... | ask | ask |

A missing, unreadable or malformed policy, or a managed install on the machine (managed-settings.json or the
runtime under Program Files), means managed mode. Every ask is appended to `.security/guard-audit.jsonl` in the
project (time, mode, tool, the command with token-like values removed, the reason), which the agent may not edit.
`verify-global.py` prints the mode the installed guard really uses. Change it with
`py -I install-global.py --guard-mode owner|managed`.

### Auto mode, don't-ask mode and bypass mode (owner mode only)

An "ask" needs a person to answer it. When you run Claude Code in auto, don't-ask or bypass mode and walk away,
a question stops the whole job until you come back. The guard reads the permission mode that Claude Code puts in
the hook input and answers like this (managed mode never changes):

| Class | Default, plan, acceptEdits | auto, dontAsk | bypassPermissions |
|---|---|---|---|
| secret, pipe-to-shell, agent config | deny | deny | deny |
| destructive, exposure | ask | deny, with the reason | allowed |
| plain install: the verb first, then only known value-less flags (`-D`, `--save-dev`, `-U`, `-q` ...) and plain registry package names with at most a plain version (`npm i -D x@18`, `pip install "x>=2"`, `cargo add x`). Run-at-once forms such as `npx x`, `pnpm dlx x` and `npm init x` follow the same rule | ask | goes on to Claude's own permission system | allowed |
| odd install: any other install. A source or index option (also abbreviated or attached, also before the verb), a workspace or filter, a URL, git or file source, a GitHub shorthand, a `name@` that hides a source, an archive, an environment marker, `go get` (Go has no registry, every host is a source) | ask, as before | deny, with the reason | allowed |
| unknown: anything else the guard has no model of (a program it has no entry for, loops, names built at run time, inline code such as `python -c`, a file written then run, `sudo`, a program given by path other than the very Python, node, npm, npx, pip, pytest, git or uv that PATH gives) | ask | deny, with the reason | allowed |
| tool credential files | ask | deny, with the reason | allowed |
| global Claude settings and rules (`~/.claude/settings.json`, `CLAUDE.md`) | ask | deny | deny |
| the guard ran out of time | ask | deny | deny |

A missing, unknown or malformed permission mode counts as the first column. In bypass mode you own the result,
so the guard does not ask. Be clear about what that means: the guard then keeps only the direct hard denials
(secret files, a plain `curl | sh`, its own config, `settings.json`). A command wrapped in a loop or built at run
time is not followed by the guard and is allowed in bypass mode, so do not read bypass mode as a protected mode.

In auto and don't-ask mode "goes on to Claude's own permission system" is broader than the install row. It also
covers every command the guard simply has no objection to, because the guard returns no verdict for those and Claude
then decides. That includes installs that run with no package name (`npm install`, `pip install -r requirements.txt`,
`npm ci`), which read whatever `package.json` or `requirements.txt` says, so an agent that has edited those files first
gets no question from the guard. A typo-squatted package name is not caught by the guard in any mode. Both stay with
Claude's classifier and your own review.

Two false positives that asked in every mode are fixed: the Python that runs the guard when it is called by its full
path, and a plain quoted string statement in PowerShell (`"created"`). Both fixes apply in owner mode only; managed
mode keeps asking. The full-path check only looks at a local drive or POSIX path, never at a network (UNC) path, so
the guard does not reach out to a host the agent named.

The rules, the edit hook, the stop gate, "Run Security Test" and "Run Advisory QA" do not depend on this and are not
affected. Every ask that auto or bypass mode answered for you is written to `.security/guard-audit.jsonl` with the
decision `unattended-deferred` (left to Claude's own permission system), `unattended-refused` or `bypass-allowed`.

The audit file is a convenience log, not evidence. It lives in the project, and the guard only blocks the direct path to it: an
agent that can run commands in auto or bypass mode can still delete it with a glob or a pipeline, replace `.security` with a
link or a junction, or fill it past its size limit, and the guard then writes nothing. Do not rely on it to prove what an
unattended run did.

What changed for a person and for managed mode: nothing is looser. A differential run of the 7.0.0 guard against this
one found only tightenings, all of them commands that 7.0.0 let through without any question and that now ask or
are denied (managed mode too): installs that 7.0.0 did not classify (`uv tool install ...`, `pip install -r http://...`,
`pip install -e git+https://...`, an install with only a registry option), an install with an option or a workspace
before the verb (`pnpm --filter web add x`, `yarn workspace web add x`, `go -C sub get x`), `npx`, `dlx` and `npm exec`
with a registry, config, prefix or package option or a brace word that hides one (`npx --registry=http://e jest`,
`npx {-p,git+https://e/x} tsc`), `npx --call=...`, and a publish hidden behind an option and its value
(`cargo --manifest-path a/Cargo.toml publish`, `pnpm --filter web publish`). Everyday forms such as `npx --silent jest`,
`npm exec -- jest`, `pnpm -r exec jest` and `npm --silent run add foo` behave exactly as before.

Not covered, in any mode: a package manager or verb the guard has no install model for (`npm update`, `pnpm update`,
`pip download`, `pip wheel`, `composer create-project`, `poetry self add`, `yarn workspaces foreach add`),
installing a local folder or archive by path (`npm i ./x.tgz`, `pip install ./x.whl`), and project-level
`.claude/settings.json` and `.mcp.json` writes.

### Turning only the command guard on or off

If the guard gets in your way, you can switch off the command guard alone and keep everything else. In your own
terminal, from the runtime folder (`%LOCALAPPDATA%\OrgAISecureAppSec\scripts` on Windows):

```
py -I guard_switch.py status
py -I guard_switch.py off
py -I guard_switch.py on
```

Off switches off the `PreToolUse` command guard (`agent_guard.py`) and nothing else. The secure-coding rules, the check
after every edit, the stop gate, the secret shield, the injection watch, "Run Security Test", "Run Advisory QA", the
scanners and the signed updates stay on. `verify-global.py` shows `command guard OFF` while it is off.

- It is honoured in owner mode only. A managed install, a missing or broken policy file, a link, duplicate keys or an
  oversized file mean managed mode and the switch is ignored.
- Changing it needs a person at a terminal: the script refuses without one, also when another script imports it. While
  the guard is on it also denies any command that names the runtime's `guard_switch.py`, in every mode (bypass too), and
  it stops agents from editing the policy file. This stops accidents and simple prompt injection. It is not
  authentication: a terminal check can be faked, and a script the agent writes and runs itself (`python x.py`, which the
  guard cannot look inside, see OPEN-04) can edit the policy file or the settings directly. Treat the switch as a
  convenience for the owner, not as a barrier against code the agent runs.
- The setting lives in `config/guard-policy.json` and an update or repair keeps it, but only from a policy file that
  passes the guard's own checks. While it is off the guard writes no audit line.
- It switches the command guard in every agent that uses it: Claude Code, Cursor, Codex, Gemini CLI and Antigravity.

## Strict instruction-source mode

For sensitive projects, copy `templates/strict-project/claude_docs/` into the repo. The guard then
lets the agent read or write Markdown only in `CLAUDE.md`, `AGENTS.md` and `claude_docs/`; other docs
go in `claude_docs/IGNORED_FILES.md`. `cat README.md` in a shell is not caught; the written rule covers it.

## Optional hardening (off by default, because it breaks everyday work)

- `permissions.blockReadsOutsideWorkingDirectories: true` (Claude Code 2.1.257+).
- Denying `curl`/`wget`/`Invoke-WebRequest` entirely and allowing `WebFetch(domain:...)` only.
- Running untrusted repos in WSL2 or a devcontainer with `sandbox.enabled: true`,
  `failIfUnavailable: true`, `allowUnsandboxedCommands: false` and a `network.allowedDomains` list.

## Honest limits

Hooks and permission patterns reduce risk; they are not a security boundary. A script that opens
files itself, or a command written to dodge the patterns, can get past them. Real isolation needs a
sandbox, and the security team's review stays in place. The guard fails closed: if it cannot check
an action, it blocks it.

## Worth adopting next

- Anthropic's official `security-guidance` plugin (Apache-2.0) for a second, LLM-based review layer.
- `anthropics/claude-code-security-review` GitHub Action (MIT) on pull requests, next to Semgrep.
- A dependency age and existence check before installs (slopsquatting).
