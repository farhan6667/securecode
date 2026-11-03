# Architecture (gate design since 6.0, current release 7.0.0)

Developer:
Claude Code → global AppSec skill/policy → fast PostToolUse heuristic guard

Full validation:
security-gate → Semgrep SAST + Trivy SCA/misconfig/secrets + Gitleaks + project tests/build → reports

Runtime:
authorized staging/ephemeral → ZAP baseline or authenticated active automation → API negative tests

Enforcement:
PR/CI → the gate `--mode ci` → fail-closed if required scanners are missing → merge/block

Important:
- Fast hook is not SAST.
- Full gate is the real scanner layer.
- Business logic and authorization require app-specific tests.
- CI is the enforcement boundary.
