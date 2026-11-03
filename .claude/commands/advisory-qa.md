---
description: Advisory QA - pentest readiness review of the current project without changing code first.
---
Use the global `org-appsec-security` skill in Mode C ("Advisory QA Karo"). Map every entry point, run the
org gate in `ci` mode, do the deep source code review from `SOURCE-CODE-REVIEW.md` (IDOR/BOLA, access
control, injection, XSS, uploads, auth, rate limits, headers, outdated libraries, secrets), and give the
Advisory QA report: verdict, coverage, findings table, fixes in priority order, the OWASP Top 10 status
table and a plain readiness call. Do not change code until I agree; then offer to fix everything safe to fix.
