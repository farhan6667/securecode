# AI agent security (V6.2)

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

| Control | Claude Code | Cursor | Codex |
|---|---|---|---|
| Org rules (`AGENTS.md` / global CLAUDE.md block) | yes, auto | User Rules (paste) | `~/.codex/AGENTS.md` |
| PreToolUse agent guard (secrets, pipe-to-shell, force push, startup files) | yes | not yet (different hook format) | use `templates/codex/rules/org.rules` |
| Deny/ask permissions | yes (`config/agent-permissions.json`) | `.cursorignore` for `.env*`, approval prompts | `approval_policy`, execpolicy rules |
| Per-edit heuristic scan | yes | no | no |
| Injection watch on Read/WebFetch/MCP output | yes (advisory) | no | no |
| Full gate `secgate.py --mode ci` | yes | yes (agent runs it) | yes (agent runs it) |
| OS sandbox | macOS, Linux, WSL2 only (not native Windows) | tool-dependent | `sandbox_mode = "workspace-write"` |

## Setup per tool

- **Claude Code**: `install-windows.ps1` does everything. Admins who want rules users cannot switch
  off deploy `enterprise-managed-settings.example.json` to `C:\Program Files\ClaudeCode\managed-settings.json`
  (it sets `disableBypassPermissionsMode`, `enableAllProjectMcpServers: false`, `allowManagedHooksOnly`).
  Test on a pilot group first: `allowManagedHooksOnly` turns off every user and project hook.
- **Cursor**: paste `AGENTS.md` into Settings > Rules > User Rules; add `.env*`, `*.pem`, `*.key` to
  `.cursorignore` in each project; turn on Workspace Trust (`security.workspace.trust.enabled`);
  approve MCP servers one at a time. `.cursorignore` does not cover terminal or MCP tools.
- **Codex**: copy `AGENTS.md` to `~/.codex/AGENTS.md`, merge `templates/codex/config.toml` into
  `~/.codex/config.toml`, copy `templates/codex/rules/org.rules` to `~/.codex/rules/`.

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
