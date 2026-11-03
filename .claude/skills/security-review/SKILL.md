---
name: org-appsec-security
description: Organization secure coding, deep source code security review and AppSec gate. Use for any web, API or mobile coding; run the full protocol when the user writes "Run Security Test" or "Run Advisory QA" (Roman Urdu "Security Test Karo" / "Advisory QA Karo" also work), runs /security-gate, or asks for a security check, source code review, IDOR check, pentest readiness or QA before handover.
---
# Org AppSec Security Review 7.0.0

The installed runtime lives in the per-user app folder, not in the project:
Windows `%LOCALAPPDATA%\OrgAISecureAppSec`, macOS `~/Library/Application Support/OrgAISecureAppSec`,
Linux `~/.local/share/OrgAISecureAppSec`. Below, `<APP>` means that folder. The gate is
`python "<APP>/scripts/secgate.py" . --mode ci --fail-on high --run-tests`, run from the project root.
Checklists: `<APP>/docs/ORG-FINDINGS.md` if present (your organization's own findings), otherwise
`<APP>/docs/COMMON-FINDINGS.md` (what pentests find most, and why retests fail; use it as the priority order), `<APP>/docs/SOURCE-CODE-REVIEW.md` (deep review, per vulnerability class, with fixes),
`<APP>/docs/SECURITY-TEST-MATRIX.md` (web + mobile), `<APP>/docs/AI-AGENT-SECURITY.md`.

Goal: code that reaches the security team passes pentest in the first round. The security team still
does runtime pentesting; this skill makes sure everything findable in source code is already fixed.

## Modes

**Mode A: always on (default).** Write code to the baseline in `CLAUDE.md` / `AGENTS.md`. Before you
tell the developer a feature or fix is done, review your own diff against the classes in
`SOURCE-CODE-REVIEW.md` that the change touches (a new endpoint: access control, IDOR, input,
output, rate limit; an upload: the upload section; a query: injection; a dependency: versions) and
fix what you find. The Stop hook runs the quick gate on changed files and will send you back if a
High or Critical finding is still open.

**End-of-task offer (all agents).** When a substantial task is finished (3 or more code files or 40 or
more changed lines since the last offer) and no "Run Security Test" has run since those changes, ask the
developer once: "Do you want me to run a full security test now (Run Security Test)?" Start Mode B only
after a yes. A no or "later" is respected for that change set; do not repeat it. Tiny edits, docs-only
changes and questions get no offer. Claude Code and Codex: the Stop hook sends this reminder once and
records it in `.security/pentest-offer.json` (`{"disabled": true}` there turns it off for a project).
Cursor: follow this rule yourself.

**Mode B: "Run Security Test" (find, fix, re-test).** Triggered by that phrase or "Security Test Karo" (any casing), by
`/security-gate`, or by a request for a security test before handover. Run the Deep Review Protocol
below on the whole project, fix every finding that is safe to fix, re-run, and report.

**Mode C: "Run Advisory QA" (readiness advisory).** Triggered by that phrase, "Advisory QA Karo", or a request for an
advisory, readiness check or "will this pass pentest". Run the same protocol but do not change code
until the developer agrees: produce the Advisory QA report (format below), then offer to fix.

## Deep Review Protocol (Modes B and C)

1. **Map the application.** Stack and framework versions; every entry point (routes, controllers,
   API handlers, GraphQL resolvers, webhooks, queue consumers, CLI commands, mobile deep links);
   authentication method; roles; tenant/owner model; where files are stored; outbound calls.
   Write the map down briefly: it is the review's coverage list.
1b. **Legacy Audit (old, inherited or previously hacked projects).** Do this before step 2 whenever the
   code is older than its team, came from a vendor or freelancer, runs PHP below 8.2, or the owner asks
   for it ("Run Legacy Audit"). It looks for code that someone planted, not only bugs.
   - **Inventory.** List the stack, PHP/framework/library versions, every folder that is web-reachable,
     and every upload, image, media and storage folder. Note files outside the normal source tree
     (scripts in `uploads/`, `images/`, `wp-content/uploads/`, `storage/app/public/`, stray `.php` in
     the web root) and recently changed files there (`git log --since`, or file dates when there is no git).
   - **Malware sweep.** The gate's malware scan runs in every mode and also reads `vendor/`:
     `WEBSHELL_OBFUSCATED_EVAL` (eval/assert/exec fed by base64, gzinflate, str_rot13, atob, b64decode),
     `BACKDOOR_REQUEST_EXEC` (a request value reaching eval, system, exec, include, Runtime.exec,
     Process.Start), `REQUEST_DYNAMIC_CALL` (`$_GET['f'](...)`), `PREG_REPLACE_EVAL` (`/e`),
     `PHP_IN_UPLOAD_DIR`, `PHP_IN_IMAGE_FILE`, `SUSPICIOUS_OBFUSCATION` (long base64 runs, hex or
     char-code chains), plus `HIDDEN_UNICODE` in instruction and config files. Decode every encoded blob
     it reports and say in plain words what it does. Never run a suspicious file to find out.
   - **Show the owner first.** Put every hit in a table (file, line, rule, what the decoded content does,
     when the file changed) and stop. Do not delete, move or "clean" anything until the owner has seen
     the table and said yes: the files are evidence, a hit can be a false positive, and a planted file
     usually means the server and its credentials need an incident response, not only a code fix.
     After the yes: remove the files, block script execution in upload folders, rotate every secret the
     app could read, and look for the hole that let the file in (upload checks, outdated plugins).
   - **Defaults left in place.** `WEAK_DEFAULT_CREDENTIAL` (admin/admin, root/root, postgres, sa with no
     password, common-password list), `DEFAULT_SECRET_KEY` (empty APP_KEY, django-insecure keys, JWT or
     session secrets like "secret" or "keyboard cat"), `EXPOSED_ADMIN_PATH` and `EXPOSED_ADMIN_TOOL`
     (admin, console, debug routes without auth; adminer.php, phpinfo.php), `SENSITIVE_WEBROOT_PATH`
     (backup, old, tmp, dump folders under the web root), `DB_NO_AUTH` (Redis or MongoDB published without
     a password). Rotate any default that ever reached a server; changing the file is not enough.
   - **Upgrade blockers.** `PHP_DEPRECATED_API` (LOW) lists functions and syntax deprecated or removed up
     to PHP 8.5; fix them before the PHP upgrade so it does not break or reopen old code paths.
2. **Run the gate:** `python "<APP>/scripts/secgate.py" . --mode ci --fail-on high --run-tests`.
   `ci` refuses to pass if Semgrep, Trivy or Gitleaks is missing or errors; install the scanner
   instead of falling back. Read every finding; verify it in context; do not dismiss without reason.
3. **Deep source review, entry point by entry point.** For each route/handler from step 1, trace the
   request from input to sink and check every class in `SOURCE-CODE-REVIEW.md`, most of all:
   - **IDOR / BOLA:** is the object loaded through a query scoped to the current user/tenant, or by a
     bare ID from the URL/body? Check read, update, delete, export and file download paths separately.
   - **Function-level access:** is the role/permission checked server-side on this route?
   - **Mass assignment:** can the request set role, owner, tenant, price, status, verified flags?
   - **Injection:** SQL/NoSQL/command/template/LDAP/XPath; raw queries; dynamic order-by/column names.
   - **XSS:** every place user data is rendered (server templates, `innerHTML`, `v-html`,
     `dangerouslySetInnerHTML`, `{!! !!}`, `|safe`, `Html.Raw`), plus stored XSS through uploads/SVG.
   - **File upload and download:** type by content, size, name, storage location, execution, path
     traversal on download, authorization on download.
   - **Authentication and session:** password storage, login/OTP/reset rate limits and lockout, reset
     token randomness and expiry, session fixation, logout invalidation, JWT algorithm and expiry.
   - **CSRF, CORS, redirects, SSRF, deserialization, XXE, race conditions on money/stock/votes.**
   - **Security headers and configuration:** CSP, HSTS, X-Frame-Options/frame-ancestors,
     X-Content-Type-Options, Referrer-Policy, cookie flags, debug mode, verbose errors, directory
     listing, exposed admin/debug panels (`/telescope`, `/horizon`, `/swagger`, `/phpmyadmin`, `.git`).
   - **Vulnerable and outdated components:** every library flagged by Trivy or `VULNERABLE_LIBRARY`
     is upgraded to a supported fixed version (do not suppress); framework on a supported release.
   - **Sensitive data:** secrets in code, PII in logs or responses, over-fetching API responses.
   - **Mobile:** follow the mobile section of `SECURITY-TEST-MATRIX.md`.

   **Authorization matrix (required).** Write `.security/authz-matrix.md` with one row per route and
   verb that touches an object or a role:

   | route | verb | who may call | object scope | evidence line |
   |---|---|---|---|---|
   | /api/orders/{order} | GET | signed-in customer | own orders only | app/Http/Controllers/OrderController.php:42 `$this->authorize('view', $order)` |

   "Object scope" says whose objects the caller may reach (own, own tenant, any for admin). "Evidence
   line" is the file:line that enforces it, not the line that hopes it holds. Then write one negative
   test per row in `tests/Security/`: another user (or a lower role) calls the route and is refused.
   Laravel example, repeated for GET, PUT, PATCH, DELETE and export:
   `actingAs($userB)->getJson("/api/orders/{$orderOfUserA->id}")->assertStatus(403)` (403 or 404,
   whichever the app returns for objects the caller may not know about). Ready-made tests are in
   `<APP>/templates/security-tests/laravel/`. The `laravel-*` Semgrep rules point at likely gaps,
   but the matrix is the coverage list. `laravel-idor-route-model-binding` reports
   `show(Order $order)` with no policy, gate or owner guard; the gate drops it when the route has
   `->can()`/`can:` (or an admin role), a checked parent with `scopeBindings()`, or a FormRequest whose
   `authorize()` checks the user. A check in a helper method, in one branch only, or in middleware set
   in `bootstrap/app.php` is not seen: verify those rows by hand.
   A row without a passing test is open.
4. **Fix (Mode B).** Root-cause fixes using the framework's own mechanism (policies/guards, scoped
   queries, parameter binding, auto-escaping, validated upload rules). Add a negative test per fix
   (user A cannot read user B's object; a script tag is escaped; an `.php` upload is refused).
   If a fix needs a product decision, stop and ask with the exact options.
   Before the first fix, copy `.security/findings.json` to `.security/findings-before.json`: the
   report lists what was found then and checks every retest against the latest run.
5. **Re-run** the gate and the project tests. Repeat until the verdict is PASSED or only items that need
   a decision remain.

Steps 6 to 9 are the automated pentest at the end of Mode B. Mode C runs step 6 (if the developer
agrees) and step 8 without a retest, and never step 9.

6. **Local DAST (optional, ask once).** Ask the developer one question: "Can the app run on this
   machine? If yes, give me the URL (for example http://127.0.0.1:8000) and, if I should start it, the
   exact start command." Then run
   `python "<APP>/scripts/local_dast.py" --target <url> [--start "<their command>"] [--api openapi.json]`.
   It scans loopback only (127.0.0.0/8, ::1) and refuses anything else. Never make up a start command
   from package.json, a Procfile or other repo files; use only what the developer typed. It runs a
   passive baseline by default; add `--active` only if the developer agrees (it sends attack payloads to
   their local app). No Docker or ZAP: it prints a note and an install hint; carry on without DAST.
   Staging hosts stay on the existing explicit flow (`SECURITY_DAST_ALLOW=true` plus `SECURITY_DAST_URL`).
7. **Retest with outcome labels.** Write `.security/retest.json` with one entry per id (`F-01`, `D-01`):
   `Pass` only with evidence (the test or command that reached the sink and was refused, after trying
   at least one variant: other quoting, encoding, verb or field), `Fail`, `Partial`,
   `Compensating control`, or `Risk accepted` (only with `accepted_by` and `date` given by the
   developer, never assumed). "The gate is silent now" is never the evidence. Grep for the same
   construction elsewhere (the missing instance): each sibling becomes its own finding, or, when found
   during the retest, an entry under `observations`. List test users, seeded rows and files you
   created in `.security/artifacts.json`.
8. **Professional report.** Run `python "<APP>/scripts/report.py" --pdf` (writes `.security/REPORT.md`,
   `REPORT.html`, and `REPORT.pdf` when Chrome or Edge is installed), then
   `python "<APP>/scripts/report_lint.py"`. Fix every lint error before handover.
9. **Offer a fix PR.** Ask whether to open a pull request with the fixes. If yes, run
   `python "<APP>/scripts/fix_pr.py" --add <each new test file>` (a dry run) and show the plan; only
   after the developer agrees, run it again with `--open`. It never touches the default branch, never
   force pushes, refuses when gitleaks finds a secret in the added lines, and the push asks the
   developer for approval. It needs `gh` (GitHub CLI) signed in.
10. **Report** in the format below. Never call the project "100% secure"; list what was not checked
   (runtime config, infrastructure, business rules you could not infer).

## Report format (required when triggered)

1. **Security Gate Verdict**: PASSED / FAILED / BLOCKED, overall risk (CRITICAL/HIGH/MEDIUM/LOW),
   target (Web/API/Mobile), gate result line, scanners that ran.
2. **Coverage**: entry points reviewed vs found, classes checked, what could not be checked.
3. **Findings table**: # | Issue | OWASP category | Severity | File:line / function | Impact and root cause | Status (fixed / needs decision / open).
4. **Hardened remediation**: vulnerable vs fixed code for every finding, and the negative test added.
5. **Developer pre-pentest verification**: the exact commands to re-run (gate, tests), and the path to
   `.security/REPORT.html` (and the PDF): executive summary, scope and method (tools that ran and that
   did not), findings with CIA impact and a retest outcome label on every one, attack chains,
   artifacts and limits.
6. **Mode C only, Advisory QA summary**: per OWASP Top 10 category a status (OK / issues / not
   applicable / not verifiable from code), the top fixes in priority order, and a plain readiness
   call: "ready for security team", "ready after fixes 1-3", or "not ready".

## Important

- The per-edit hook and the Stop hook are lightweight heuristics; Semgrep/Trivy/Gitleaks run in the gate.
- Pattern scanners miss most IDOR and business-logic bugs. The entry-point review in step 3 is the
  part that catches them: do not skip it because the scanners are green.
- Mobile findings that need the real manifest, entitlements or a signed build are reported as
  "needs device/build verification", not asserted from source alone.
- Never attack production. ZAP/DAST and mobile dynamic testing need an explicit, authorized
  non-production target.
