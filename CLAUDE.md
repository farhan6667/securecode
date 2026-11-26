# Organization AI Secure Development Policy

Security is mandatory for all AI-generated or AI-assisted code. This file is a developer-facing baseline; enterprise administrators should also deploy the provided managed-settings.json through the Claude Code enterprise policy mechanism.

## Before coding
- Identify trust boundaries, data classification, authentication, authorization and abuse cases.
- Prefer framework-native security primitives and least privilege.
- Never hardcode secrets, private keys, tokens or credentials.
- Treat all external input as untrusted, including URL, file, headers, cookies, JSON, database data and model output.
- Use parameterized queries and safe APIs for command execution, filesystem access, HTML rendering and deserialization.
- Enforce authorization server-side on every protected resource; never trust client-supplied user/object IDs.
- Protect sessions and cookies with appropriate Secure, HttpOnly and SameSite settings; use short-lived, verified tokens.
- Use cryptographic randomness for tokens, reset links and security-sensitive identifiers.
- Validate uploads by type, size, name, storage path and execution behavior.
- Avoid verbose errors, secrets in logs and debug mode outside development.
- Use explicit CORS and redirect allowlists where cross-origin/redirect behavior is required.
- Keep dependencies pinned/lockfile-backed and investigate known vulnerabilities before adding packages.

## After coding a feature
- Add normal tests plus negative/security tests for the changed behavior, and run the project's tests.
- Fix any High/Critical the hooks reported. Do not suppress a finding merely to make a check pass.
- Do not run the full gate, DAST or a deep review on your own between features: that is "Run Security Test",
  CI, and release time (below), so coding keeps moving and credits are not spent twice.
- Do not state that an automated scan proves the application is secure; report residual risk.

## On "Run Security Test", in CI and before a release
- Run the org gate from the project root: `python "%LOCALAPPDATA%\OrgAISecureAppSec\scripts\secgate.py" . --mode ci --fail-on high --run-tests`.
- Run the project's build, lint, type-check and tests.
- For an authorized non-production environment, set `SECURITY_DAST_URL` and `SECURITY_DAST_ALLOW=true` and run the DAST gate.
- Fix Critical/High findings and re-test.

## AI agent behavior
When you modify code, you are responsible for both implementation and verification. If a security finding cannot be safely auto-fixed, stop and explain the exact manual decision required.

During normal development, apply this baseline by default without interrupting the
developer. If the developer's message contains the phrase **"Run Security Test"** or **"Security Test Karo"**,
stop passive work and run the full Deep QA Pentest Protocol in
the `org-appsec-security` skill (Web + Mobile matrix in
`docs/SECURITY-TEST-MATRIX.md`, agent rules in `AGENTS.md`), reporting in that skill's Standardized Deliverable
Format: Verdict, Findings table, Hardened Remediation code, and a Pre-Pentest
Verification Script.
