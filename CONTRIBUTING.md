# Contributing to NexaForge SecureCode

Thanks for helping. Most of this was built and tested on Windows with Claude Code, so reports from other
setups are the most useful thing you can send.

## Ways to help

1. **A compatibility report.** Install it on your machine and stack (macOS, Linux, WSL, Cursor, Codex,
   Laravel, Next.js, Django, Android) and tell us what worked, what was a false positive and what it
   missed. There is an issue template for this.
2. **A missed finding.** If a pentest found something the gate and the review should have caught, open a
   feature request with a small made-up code sample.
3. **A guard bypass.** Please report it privately (see [SECURITY.md](SECURITY.md)). A fix with a
   regression test is very welcome after that.
4. **A fix, a test or a clearer sentence in the docs.** Start with a
   [good first issue](https://github.com/farhan6667/securecode/labels/good%20first%20issue).

## Setup (two minutes)

```bash
git clone https://github.com/farhan6667/securecode
cd securecode
python -m pip install "pytest==8.4.2" "PyYAML==6.0.3"
python -m pytest -q tests -p no:cacheprovider
```

The scripts only use the Python standard library (plus PyYAML for suppressions). Please keep it that way;
a new dependency needs a good reason and an exact pin.

## Rules for changes

- Every fixed bug gets a test that fails without the fix.
- Security checks fail closed in `ci` mode. Never weaken a check to make a test pass.
- Run the package's own gate before you open a pull request:
  `python -I scripts/secgate.py . --mode full --fail-on high` (needs Semgrep, Trivy and Gitleaks).
- Keep the hook scripts runnable with `python -I` (no imports from the working directory).
- Plain English in docs, short sentences.

Changes to the guard, the gate, the exceptions and `config/allowed_signers` are reviewed by the maintainer
(see `.github/CODEOWNERS`).
