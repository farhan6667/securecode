# One-prompt install (Claude Code, Cursor, Codex, Gemini CLI, Antigravity)

Paste the one line from the README into your AI coding tool, or paste the block below. Both name the same
steps: download, check the key fingerprint, verify the signature, extract, install, `doctor`, `setup`, verify,
restart.

```
Install NexaForge SecureCode for me. You have my permission to set it up for my user account.
Follow these steps in order and stop and tell me if any check fails.
1. Download: from https://github.com/farhan6667/nexaforge-securecode/releases/latest download
   NexaForge_SecureCode.zip and NexaForge_SecureCode.zip.sig into a new, empty folder. Run nothing from the zip yet.
2. Trust anchor: open https://github.com/farhan6667/nexaforge-securecode/blob/main/SECURITY.md and note the
   "Key fingerprint" (SHA256:...).
3. Check the key: read only config/allowed_signers from the zip. Save the part of its line that starts with
   ssh-ed25519 as key.pub and run: ssh-keygen -l -f key.pub
   The SHA256 value must equal the fingerprint from step 2. If it does not, stop.
4. Verify the signature: save config/allowed_signers next to the zip as allowed_signers and run:
   ssh-keygen -Y verify -f allowed_signers -I nexaforge-securecode-release -n org-appsec-update -s NexaForge_SecureCode.zip.sig < NexaForge_SecureCode.zip
   It must print "Good signature". If not, stop.
5. Ask me which folder to extract to (suggest C:\Tools\nexaforge-securecode on Windows or
   ~/tools/nexaforge-securecode on macOS and Linux) and extract the zip there.
6. Install from that folder. Windows: powershell -ExecutionPolicy Bypass -File .\install-windows.ps1
   macOS: ./install-macos.sh --update-timer   Linux: ./install-linux.sh --update-timer
7. Scanners: run py -I scripts/securecode.py doctor (python3 instead of py on macOS and Linux) and show me
   what this machine is missing. Then run py -I scripts/securecode.py setup, show me the plan (source, pinned
   version, checksum, licence, folder), ask me once, and only after my yes run
   py -I scripts/securecode.py setup --yes. Never install scanners another way.
8. Verify: py verify-global.py (python3 on macOS and Linux). Every check must be true.
9. If you are not Claude Code, load AGENTS.md from that folder as your own global rules and install your
   guard hook by hand, following docs/AI-AGENT-SECURITY.md (Codex: ~/.codex/AGENTS.md plus templates/codex;
   Cursor: User Rules, .cursorignore for .env files, templates/cursor/hooks.json; Gemini CLI: ~/.gemini/AGENTS.md,
   templates/gemini/settings.json and settings.hooks.json; Antigravity: ~/.gemini/AGENTS.md and
   templates/antigravity/hooks.json; on Windows use settings.hooks.windows.json, hooks.windows.json and the Codex
   commandWindows lines). Back up every file first.
10. Tell me to restart this AI tool, because rules and hooks load at start.
11. Explain auto-update: a daily task checks GitHub for newer signed releases and installs them by itself; an
    unsigned, tampered or older release is refused. Show me how to turn it off (ENTERPRISE_DEPLOYMENT.md). The
    public repo needs no GitHub login.
12. Explain owner mode: on my own machine the guard asks me before risky actions such as a force push, a public
    repo or a package install, and always refuses secret files and pipe-to-shell. A managed install refuses all
    of them.
Back up every file before changing it and never overwrite my existing settings or rules.
From now on follow these security rules in every project by default. When I write "Run Security Test",
review the source code deeply, fix what you safely can, run the gate again and show me the verdict,
the findings table and the fixed code. When I write "Run Advisory QA", give me the readiness advisory
first and change nothing until I agree. Finish with a short report: what was installed, versions,
checks passed, and anything I still need to do.
```

## Why the fingerprint is the trust anchor

The signature proves the zip was signed by the key in `config/allowed_signers`. But that key file arrives
inside the same download, so anyone able to swap the release could swap the zip, the `.sig` and the key
together, and the signature would still check out. The fingerprint published in `SECURITY.md` on the `main`
branch comes from a second place. When the key in the zip has that fingerprint, it is the project's real
release key, and the signature check means something. If you saved the fingerprint the first time you
installed, compare against that copy too: it still protects you if the repository itself were ever changed.

After the first install you never repeat this by hand: the updater checks every new release against the key
that is already installed on your machine.

The agent asks before installing anything; that is expected.
