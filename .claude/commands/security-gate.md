---
description: Run the organization AppSec gate for the current project, review findings, fix safe issues, and re-test.
---
Run the installed Org AI AppSec gate from the current repository. Use the global `org-appsec-security` skill. Treat this invocation the same as the "Run Security Test" trigger: run the full Deep QA Pentest Protocol (Web + Mobile matrix) and report in the Standardized Deliverable Format (Verdict, Findings table, Remediation, Pre-Pentest Verification Script). Start with the full local gate (`--run-tests` already runs the project tests; do not run them a second time). For authorized non-production staging only, run DAST/API tests when `SECURITY_DAST_ALLOW=true` and a staging URL is explicitly provided. Do not attack production. Do not hide or downgrade findings.
