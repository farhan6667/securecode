# Security policy

NexaForge SecureCode guards AI coding agents and checks code before handover, so a weakness in it
matters. Reports about the project's own code are welcome and taken seriously.

## What to report

- A way past the agent guard (`scripts/agent_guard.py`): a command, a path or a tool call that reads a
  secret file, writes to the agent's own settings, force-pushes or creates a public repo without being
  blocked or asked about.
- A way to make the gate (`scripts/secgate.py`) report PASS falsely, run code from the scanned project, or
  crash in a way that hides findings.
- A way to make the auto-updater (`scripts/updater.py`) install something that was not signed with the
  release key, an older version, or files outside its folder.
- Leaks of secrets or local paths in reports and logs.

Known limits are written down in [SECURITY-CONTEXT.md](SECURITY-CONTEXT.md) (for example, the guard is
pattern based and is not a sandbox). A new bypass of a documented limit is still worth reporting.

## How to report

Use a private report: [open a security advisory](https://github.com/farhan6667/securecode/security/advisories/new),
or email **nexaforge.services@gmail.com**. Please include the exact input, what happened, what you
expected and the version (`MANIFEST.txt`). Please don't open a public issue for a vulnerability.

This is a solo-maintained project. There is no paid bounty and no guaranteed response time, but every
report is read, acknowledged, and fixed with a regression test when it is confirmed. Reporters are
credited in the release notes unless they ask not to be.

## Verifying a release

Every release zip is signed with the project's offline ed25519 key. The public key is in
`config/allowed_signers` in this repo, and at `aisec/config/allowed_signers` inside the zip (every file in the
zip sits under the `aisec` folder). Save that file next to the zip as `allowed_signers`, then check the download:

```bash
ssh-keygen -Y verify -f allowed_signers -I nexaforge-securecode-release -n org-appsec-update -s NexaForge_SecureCode.zip.sig < NexaForge_SecureCode.zip
```

PowerShell does not accept `<`, so on Windows in PowerShell run the same line through cmd:

```powershell
cmd /c "ssh-keygen -Y verify -f allowed_signers -I nexaforge-securecode-release -n org-appsec-update -s NexaForge_SecureCode.zip.sig < NexaForge_SecureCode.zip"
```

It must print `Good signature`. After extracting, change into the `aisec` folder to install.

Key fingerprint: `SHA256:GD3ICyrDAvPG6KoSyV+r8q65KRJCelVusuXxuQeWaF4`
