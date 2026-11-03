# NexaForge SecureCode: organization deployment

Three layers. Only the second and third are things a developer cannot switch off.

| Layer | Who sets it up | Can the developer remove it? |
|---|---|---|
| 1. Per-user install (`install-windows.ps1` or the one-prompt install) | the developer | yes, it lives in their own profile |
| 2. Managed install (`install-managed.py`, admin) | IT / endpoint management | no: runtime is read-only, settings are admin-owned |
| 3. CI required check + security intake rule | repo admins and the security team | no: it runs on the server |

## 1. Per-user install
`powershell -ExecutionPolicy Bypass -File .\install-windows.ps1`, then `py verify-global.py`.
Installs the skill, `/security-gate`, `/advisory-qa`, `/sec-review`, the global CLAUDE.md block, the hooks
(agent guard, per-edit check, injection watch, stop gate), deny/ask permissions, and a daily signed
auto-update task. Cursor and Codex: load `AGENTS.md` (see `docs/AI-AGENT-SECURITY.md`).

## 2. Managed install (enforced)
1. Install Python for all users (under Program Files), plus Semgrep, Trivy and Gitleaks machine-wide.
2. As administrator: `py -I install-managed.py` (add `--lock` after a pilot to allow only org hooks).
3. It writes `%ProgramFiles%\ClaudeCode\managed-settings.json` (hooks, deny rules,
   `disableBypassPermissionsMode`, `enableAllProjectMcpServers: false`) and `%ProgramFiles%\ClaudeCode\CLAUDE.md`,
   and copies the runtime to `%ProgramFiles%\OrgAISecureAppSec` with read-only access for users.
4. Roll it out with Intune/GPO/SCCM as a script package. Test on 2 to 3 machines first.
5. Check the managed paths against the current Claude Code docs before rollout; they have moved before
   (`C:\ProgramData\ClaudeCode` is no longer read).

## 3. Server-side enforcement (the part that guarantees it)
- Set org variables `SECURECODE_REPO` (the central repo) and `SECURECODE_REF` (a release tag or commit SHA).
  The workflow fetches the gate from there, never from the pull request, so a PR cannot weaken it.
- Add `templates/ci/github/org-appsec-gate.yml` as an **org-level ruleset "Require workflows to pass"**
  pointing at the central repo's copy (or as a required status check per repo). With the org ruleset a
  pull request cannot edit or delete the workflow. No merge without PASS.
- Exceptions: in `ci` mode a project's own suppressions file is ignored. Approved exceptions live in the
  central repo under `exceptions/<owner>__<repo>.yaml` (see `exceptions/README.md`), reviewed via CODEOWNERS.
- Security testing requests must include the gate output (`.security/findings.json` or the PASS line).
  Requests without it are returned. This turns the gate into the entry ticket to pentest.

## Internal branding and manual update
To hand the package out under your own name, put your name in `config/brand.json` before you share it,
for example `{"product_name": "Acme SecureCode"}`. The installer banner, the install report, `verify-global.py`
and the daily task (`Acme SecureCode Update`) then use that name. Allowed: letters, digits, spaces and
`. - _ ( ) + ,`, at most 60 characters, starting and ending with a letter or digit. Anything else, or a
missing or broken file, falls back to "NexaForge SecureCode".

Updates keep coming from the NexaForge signed releases and never rename the product: the installer and the
updater never overwrite `config/brand.json` or `docs/ORG-FINDINGS.md` in
`%LOCALAPPDATA%\OrgAISecureAppSec`, and never delete files that exist only there. A fresh install copies
the package's `brand.json` only when none exists. If the name changes, a re-install creates the new task
and deletes the old one, but only a task this installer recorded (`update-task.json`) or the old
"NexaForge SecureCode Update" task, and only when it runs this app folder's `updater.py`.

Update by hand at any time:
```
py -I "%LOCALAPPDATA%\OrgAISecureAppSec\scripts\updater.py"
```
It prints one line, such as `Acme SecureCode: updated to 6.3.0`, `already up to date (6.2.0)`,
`signature invalid, nothing installed` or `no network or GitHub unreachable`. Details go to `update.log`.

## Auto-update
By default an install updates from the public repo `farhan6667/nexaforge-securecode` and accepts only
releases signed with the NexaForge release key (the public key ships in the package). No GitHub login is
needed. To stop it on Windows: `schtasks /Delete /TN "NexaForge SecureCode Update" /F` (or your brand
name followed by ` Update`).

An organization that wants to decide its own releases can run its own fork instead:

1. Create a private repo in the org's GitHub (for example `<org>/nexaforge-securecode`) and push this folder.
   Protect `main` (pull request + review), enable tag protection and **immutable releases**, keep
   Dependabot on, and give release rights to the security team only.
2. Create the release signing key once, offline, on the release officer's machine:
   `ssh-keygen -t ed25519 -C "NexaForge SecureCode release" -f org-appsec-release` (use a passphrase).
   Put the public key line in `config/allowed_signers` as `nexaforge-securecode-release ssh-ed25519 AAAA...`
   and the repo name in `config/update.json`. Commit both. Never commit the private key.
3. Each release: bump `VERSION` in `install-global.py` and `Version:` in `MANIFEST.txt`, then
   `py -I scripts/release/make_release.py --version X.Y.Z --key <private key>` and
   `gh release create vX.Y.Z dist/NexaForge_SecureCode.zip dist/NexaForge_SecureCode.zip.sig --repo <org>/nexaforge-securecode`.
4. Developers need read access to the repo and `gh auth login` once (or a read-only `GH_TOKEN`).
   The daily task "NexaForge SecureCode Update" then installs any newer, correctly signed release by itself
   and logs to `%LOCALAPPDATA%\OrgAISecureAppSec\update.log`. Unsigned, tampered or older releases are refused.
5. Managed machines: run the same release through endpoint management (`install-managed.py`) instead of
   the per-user task, so the read-only runtime stays admin-owned.

Why signing: an auto-updater that trusts the repo alone turns one leaked token into code running on every
developer's machine (this is how the 2025 Amazon Q extension and the 2026 Trivy compromises spread).
With signing, a leaked GitHub token is not enough; the attacker also needs the offline release key.

## Optional tools (used when installed, never required)

| Tool | What it adds | How the package uses it |
|---|---|---|
| Retire.js (Apache-2.0, `npm i -g retire`) | finds vulnerable client libraries by signature, also renamed or bundled copies | `secgate.py --mode full/ci` runs it if `retire` is on PATH; findings are `VULNERABLE_LIBRARY` |
| Psalm with taint analysis (MIT) and psalm-plugin-laravel (MIT) | data-flow checks for PHP (SQL, shell, file and HTML sinks) | runs with `--run-tests` when the project has `vendor/bin/psalm` (Psalm loads the project's own code, so it is treated like running its tests); taint issues are HIGH |
| nuclei (MIT) | template-based checks against a running staging site | `scripts/run-nuclei-authorized.py`, only with `SECURITY_DAST_ALLOW=true` and a staging URL; DoS, intrusive and fuzzing templates are excluded |
| `scripts/package_age.py` | refuses package versions younger than 14 days and names that don't exist | the agent rules ask the agent to run it before adding or upgrading a dependency |

Install them only after the usual review of the source and licence. A missing optional tool is a NOTE in the
report, not a failure.

## Per-language scanners: offline and air-gapped installs

`py -I scripts/securecode.py setup` installs the per-language engines (osv-scanner, Bandit, pip-audit, gosec,
govulncheck, ESLint security, Dependency-Check, SpotBugs with Find Security Bugs) after one explicit `--yes`.
Every pinned version and checksum is in `scripts/engines/engines.lock.json`.

For machines without internet access:

1. On a connected machine, download the files listed in `engines.lock.json` (the `url` of each download, the
   wheels named by `wheel_sha256`, the npm packages named under `packages`) and check each against the pinned
   hash. Put them in your internal artifact store.
2. Point the tools folder at a shared, read-only location with `NEXAFORGE_TOOLS_DIR` (an absolute path outside
   every project), and lay out each engine as `<engine>/<version>/...` exactly as `setup` does on a connected
   machine. The simplest route is to run `setup --yes` once on a connected build machine and copy that folder.
3. Route package managers to your mirrors: `SECGATE_NPM_REGISTRY` for npm (setup and `npm audit` in ci mode),
   `PIP_INDEX_URL` for pip, `GOPROXY` for Go. The hash checks still apply to what comes back.
4. Dependency-Check needs the NVD data. Mirror it with the Dependency-Check tooling, point
   `SECGATE_DEPCHECK_DATA` at that data folder and set `SECGATE_DEPCHECK_NOUPDATE=1`.
5. osv-scanner, govulncheck, npm audit and pip-audit query online advisory services and do not have a full
   offline mode in this release. In an air-gapped network they report "did not complete" as a NOTE, and Trivy
   (with an offline database) remains the dependency check. Say so in your risk register.

CodeQL is never installed by `setup`. Its CLI terms allow open source and academic research; private commercial
code needs a GitHub licence. If you hold one, install the CLI through your own process and set `SECGATE_CODEQL=1`.

**Pinning Semgrep rules.** The gate uses our own rules (`semgrep/`) plus the Semgrep registry packs. Registry
rules change over time and are under their own licence, so we don't copy them into this repo. For repeatable CI,
mirror the packs you use into a private repo you control and set `SEMGREP_CONFIGS` to those files.

**Anthropic security-guidance plugin.** Claude Code has an optional security review plugin from Anthropic. It
works alongside this package. Like any Claude review, the code it reviews is sent to Anthropic under your plan's
data terms, so whether to enable it for code that must stay in-house is a management decision.

## Governance
Findings, exceptions (owner, reason, expiry in `config/security-suppressions.yaml`), and remediation
deadlines go to the security team's tracker. Review `docs/THIRD-PARTY-REVIEW.md` before adding any tool or skill.
