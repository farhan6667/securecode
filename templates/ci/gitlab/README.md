Use the bundled `templates/ci/gitlab/org-appsec-gate.yml` as a starting template.
Your CI runner/image must provide pinned versions of Semgrep, Trivy and Gitleaks.
SecureCode deliberately does not download security binaries from arbitrary URLs inside the gate.
