#!/usr/bin/env bash
# Installs pinned Semgrep, Trivy and Gitleaks on a Linux x86_64 CI runner.
# The release archives are checked against SHA-256 values written in this file (not only the
# checksum file next to them), so a hijacked release or tag cannot swap the binary. This matters:
# in March 2026 the Trivy ecosystem was compromised (GHSA-69fq-xp46-6x23); floating action tags such
# as aquasecurity/trivy-action@master were rewritten to credential-stealing malware.
# To move to a new version, update the version AND its hash below in the same reviewed change.
set -euo pipefail
SEMGREP_VERSION="1.183.0"
TRIVY_VERSION="0.76.1"
TRIVY_SHA256="c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
GITLEAKS_VERSION="8.30.1"
GITLEAKS_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
BIN="${SCANNER_BIN:-$HOME/.local/bin}"
mkdir -p "$BIN"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

python3 -m pip install --disable-pip-version-check "semgrep==${SEMGREP_VERSION}"

fetch_pinned() { # url archive sha256 binary
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$2" "$1/$2"
  echo "$3  $tmp/$2" | sha256sum -c -
  tar -xzf "$tmp/$2" -C "$tmp" "$4"
  install -m 0755 "$tmp/$4" "$BIN/$4"
}

fetch_pinned "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
  "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "$TRIVY_SHA256" trivy
fetch_pinned "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}" \
  "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "$GITLEAKS_SHA256" gitleaks

if [ -n "${GITHUB_PATH:-}" ]; then echo "$BIN" >> "$GITHUB_PATH"; fi
"$BIN/trivy" --version | head -1
"$BIN/gitleaks" version
semgrep --version
