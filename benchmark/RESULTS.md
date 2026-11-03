# Benchmark results

Every number here comes from a command you can run yourself. Nothing is estimated.

## Read this first

The lab is small and we wrote it ourselves, and we also wrote the rules. So a high score on it shows
that the checks work as designed. It does not show how much a real pentest will find. The real test is
running it against apps we did not write (see "Not run yet" below), and reports from people who use it
on their own projects.

## Own Laravel lab (`benchmark/laravel-lab.json`, 18 planted issues)

Run on 2026-11-03, Windows 11, Python 3.14, Semgrep 1.183.0, Trivy 0.76.1, Gitleaks 8.30.1.

| Command | Found |
|---|---|
| `py -I benchmark/run_lab.py --mode quick` (built-in checks only, no scanners) | 11 of 18 |
| `py -I benchmark/run_lab.py --mode full` (adds Semgrep with the Laravel authz rules, Trivy, Gitleaks) | 17 of 18 |

The one miss in full mode is on purpose: L18 is an IDOR through route model binding
(`show(Invoice $invoice)` with no `authorize` call). A pattern rule cannot tell whether the binding is
scoped to the user. The deep review in the skill handles it a different way: it maps every route in
`.security/authz-matrix.md` and writes a cross-user test for each row ("a row without a passing test is
open").

Full table from the full-mode run:

| id | planted issue | result | rule |
|---|---|---|---|
| L1 | IDOR: show() loads any order by id | found | laravel-idor-unscoped-lookup |
| L2 | IDOR plus mass assignment in update() | found | laravel-idor-unscoped-lookup |
| L3 | IDOR in destroy() through where('id', ...) | found | laravel-idor-unscoped-lookup |
| L4 | SQL injection in search() | found | SQL_CONCAT |
| L5 | Mass assignment in ProfileController::store | found | laravel-mass-assignment |
| L6 | guarded = [] on User | found | laravel-mass-assignment |
| L7 | API routes without auth middleware | found | laravel-api-route-without-auth |
| L8 | Delete over GET | found | STATE_CHANGE_OVER_GET |
| L9 | No global security headers middleware | found | MISSING_SECURITY_HEADERS |
| L10 | Session cookie without Secure | found | INSECURE_COOKIE_FLAG |
| L11 | Seeded admin with a weak password | found | WEAK_DEFAULT_CREDENTIAL |
| L12 | Outdated jQuery 2.2.4 (file and CDN) | found | VULNERABLE_LIBRARY |
| L13 | Source map in the web root | found | WEBROOT_EXPOSURE |
| L14 | Directory listing on | found | DIRECTORY_LISTING |
| L15 | CDN script without SRI | found | CDN_WITHOUT_SRI |
| L16 | Unescaped Blade output {!! !!} | found | XSS_RAW_TEMPLATE |
| L17 | PHP 7.4 and Laravel 8 out of support | found | UNSUPPORTED_PLATFORM |
| L18 | IDOR through route model binding | missed | (known gap, see above) |

`tests/test_benchmark_lab.py` keeps the quick-mode floor at 11, so a weaker rule fails CI.

## Not run yet

These public practice apps are good next targets. They have not been run, because the machine used for
this release has no Docker or PHP. Results will be added here with the exact command when they exist.

| Target | Stack | Why |
|---|---|---|
| OWASP Juice Shop | Node, Angular | many known findings, including broken access control |
| VAmPI | Python, Flask API | OWASP API Top 10 issues, BOLA |
| crAPI | microservices API | realistic BOLA and mass assignment |

If you run one of them, please open a compatibility report with the command and the output.
