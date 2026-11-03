# One-prompt install (Claude Code, Cursor, Codex)

Extract the zip, then paste this into your AI coding tool. Change the path to your folder.

```
Install NexaForge SecureCode from C:\Tools\aisec. You have my permission to set it up globally for my
user account.
1. Run install-windows.ps1 (on macOS/Linux the matching install script) and then verify-global.py
   from that folder. All checks must be true.
2. Install Semgrep, Trivy and Gitleaks if missing (Windows: winget --source winget for
   AquaSecurity.Trivy and Gitleaks.Gitleaks, pip install --user semgrep), and confirm each with --version.
3. If you are not Claude Code, load AGENTS.md from that folder as your own global rules
   (Codex: ~/.codex/AGENTS.md plus templates/codex; Cursor: User Rules and .cursorignore for .env files),
   following docs/AI-AGENT-SECURITY.md.
4. Tell me that a daily task now checks GitHub for newer signed releases and installs them, and how to
   turn it off (ENTERPRISE_DEPLOYMENT.md). The public repo needs no GitHub login; a private fork does.
5. Back up every file before changing it and never overwrite my existing settings or rules.
From now on follow these security rules in every project by default. When I write "Security Test Karo",
review the source code deeply, fix what you safely can, run the gate again and show me the verdict,
the findings table and the fixed code. When I write "Advisory QA Karo", give me the readiness advisory
first and change nothing until I agree. Finish with a short report: what was installed, versions,
checks passed, and anything I still need to do.
```

The agent will ask before installing packages; that is expected.
