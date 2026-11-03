#!/usr/bin/env bash
set -euo pipefail
python3 scripts/secgate.py . --mode ci --fail-on "${SECURITY_FAIL_ON:-high}" ${SECURITY_DAST_URL:+--dast-url "$SECURITY_DAST_URL"}
