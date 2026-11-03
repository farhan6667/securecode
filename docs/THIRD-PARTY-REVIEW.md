# Third-party component review (checked 2026-11-02)

Nothing below was installed or merged blindly. For each repository we checked the licence, last
activity, latest release, published security advisories, and what it would add. Agent "skills" are
instructions that every developer's AI would follow, so they get the strictest bar: an unreviewed
skill is a prompt-injection channel into the whole organization.

Decision key: **Integrated** (in the package now), **Approved, optional** (allowed, not required),
**Reference** (used as a source for our own checklists, nothing copied), **Rejected** (not used).

| # | Repository | Licence | Last push | Latest release | Advisories | Decision | Why |
|---|---|---|---|---|---|---|---|
| 1 | trailofbits/skills | CC-BY-SA-4.0 | 2026-10-28 | none | 0 | Reference | Strong audit skills, but share-alike licence: copying text would force our docs to CC-BY-SA. Ideas only. |
| 2 | semgrep/skills | not stated | 2026-07-28 | none | 0 | Reference | No clear licence; Semgrep itself is already integrated. |
| 3 | BehiSecc/VibeSec-Skill | Apache-2.0 | 2026-02-17 | none | 0 | Reference | Good vibe-coding checklist; its topics are covered in SOURCE-CODE-REVIEW.md. No release to pin. |
| 4 | agamm/claude-code-owasp | MIT | 2026-09-25 | none | 0 | Reference | OWASP Top 10 / ASVS guidance; used to cross-check our checklist. No release to pin. |
| 5 | anthropics/claude-code-security-review | MIT | 2026-02-11 | none | 0 | Approved, optional | Official LLM review on pull requests. Sends the diff to Anthropic and needs an API key secret: management decision. Pin to a commit SHA. |
| 6 | secureIO-GmbH/security-skills | MIT | 2026-03-27 | none | 0 | Rejected | 4 stars, too little adoption or review history to trust as agent instructions. |
| 7 | howardhsieh/agent-security-skills | Apache-2.0 | 2026-10-12 | v0.2.2 | 0 | Rejected | 2 stars; same reason. Our agent guard and AGENTS.md cover this area. |
| 8 | semgrep/semgrep | LGPL-2.1 | 2026-11-02 | v1.183.0 | 0 | Integrated | SAST engine in the gate, pinned 1.183.0. |
| 9 | semgrep/semgrep-rules | Semgrep Rules Licence | 2026-10-27 | none | 0 | Integrated | Used through registry packs `p/default`, `p/owasp-top-ten`, `p/secrets` (internal use is allowed by its licence). |
| 10 | aquasecurity/trivy | Apache-2.0 | 2026-11-02 | v0.76.1 | 5 | Integrated, hardened | Dependency/misconfig/secret scan. **March 2026 supply-chain compromise (GHSA-69fq-xp46-6x23)**: v0.69.4 and trivy-action/setup-trivy tags were malicious. We pin 0.76.1 with a SHA-256 in the script, and do not use trivy-action. Other advisories fixed in current versions. |
| 11 | gitleaks/gitleaks | MIT | 2026-10-28 | v8.30.1 | 0 | Integrated | Secret scan, pinned 8.30.1 with SHA-256. |
| 12 | google/osv-scanner | Apache-2.0 | 2026-11-01 | v2.7.0 | 0 | Approved, optional | Second opinion on lockfile CVEs; overlaps Trivy. |
| 13 | bridgecrewio/checkov | Apache-2.0 | 2026-11-02 | 3.4.0 | 0 | Approved, optional | For teams with Terraform/Kubernetes; Trivy misconfig covers basics. |
| 14 | anchore/grype | Apache-2.0 | 2026-10-30 | v0.121.0 | 1 | Not needed | Overlaps Trivy; had a credential-disclosure advisory (GHSA-6gxw-85q2-q646, fixed). |
| 15 | OWASP/ASVS | CC-BY-SA-4.0 | 2026-10-29 | 2026-10-26 | 0 | Reference | Verification standard behind our checklist; nothing copied. |
| 16 | OWASP/wstg | CC-BY-SA-4.0 | 2026-11-01 | v4.2 | 0 | Reference | Pentest methodology for the security team. |
| 17 | zaproxy/zaproxy | Apache-2.0 | 2026-11-02 | v2.17.0 | 0 | Integrated | DAST templates, image pinned to 2.17.0, authorized staging only. |
| 18 | OWASP/Top10 | not stated | 2026-09-24 | none | 0 | Reference | Category structure of SOURCE-CODE-REVIEW.md. |
| 19 | OWASP/API-Security | not stated | 2026-09-22 | none | 0 | Reference | API section of SOURCE-CODE-REVIEW.md. |
| 20 | securityfortech/awesome-security-skills | none | 2026-03-29 | none | 0 | Rejected | A link list without licence; nothing to integrate. |
| 21 | zhuyansen/awesome-claude-code-review | not stated | 2026-11-01 | none | 0 | Rejected | 1 star link list. |

## Rules for adding anything later

1. Licence allows our use; share-alike content is referenced, not copied.
2. Active maintenance and a release or commit we can pin (SHA, version plus SHA-256, or image digest).
3. Read the published advisories; never use floating tags (`@master`, `latest`, `stable`).
4. Agent skills and rules files: read every line before adoption, run the gate's `HIDDEN_UNICODE` and
   `INSTRUCTION_INJECTION` checks on them, and ship them only through the signed update.
5. Record the decision in this file with the date.
