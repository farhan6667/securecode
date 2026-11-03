#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'Checking optional AppSec tools...'
for t in python3 semgrep trivy gitleaks docker; do
  if command -v "$t" >/dev/null 2>&1; then echo "[OK] $t: $($t --version 2>/dev/null | head -1)"; else echo "[--] $t: not installed (optional)"; fi
done
cat <<'EOF'
Recommended enterprise stack:
  Semgrep  = SAST / framework-aware rules
  Trivy    = dependency, secret, misconfiguration and SBOM-related scanning
  Gitleaks = Git secret scanning
  OWASP ZAP= DAST in staging/ephemeral environments

Install these with your approved corporate package manager/container registry.
Do not pipe remote shell installers directly into a privileged shell.

Per-language scanners (pinned versions, checked SHA-256):
  python3 -I scripts/securecode.py doctor
  python3 -I scripts/securecode.py setup        # prints the plan; installs only with --yes
EOF
