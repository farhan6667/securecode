# Benchmark results

Every number here comes from a command you can run yourself. Nothing is estimated.

## Read this first

The lab is small and we wrote it ourselves, and we also wrote the rules. So a high score on it shows
that the checks work as designed. It does not show how much a real pentest will find. The real test is
running it against apps we did not write (see "Not run yet" below), and reports from people who use it
on their own projects.

## Own Laravel lab (`benchmark/laravel-lab.json`, 18 planted issues)

Run on 2026-11-03, Windows 11, Python 3.14, Semgrep 1.183.0, Trivy 0.76.1, Gitleaks 8.30.1.

| Command | Found | Clean files reported |
|---|---|---|
| `py -I benchmark/run_lab.py --mode quick --lab laravel` (built-in checks only, no scanners) | 11 of 18 | 0 of 4 |
| `py -I benchmark/run_lab.py --mode full --lab laravel` (adds Semgrep with the Laravel authz rules, Trivy, Gitleaks) | 18 of 18 | 0 of 4 |

L18, an IDOR through route model binding (`show(Invoice $invoice)` with no `authorize` call), used to be
the one miss. Since OPEN-01 was closed, `laravel-idor-route-model-binding` reports a controller method
that takes a bound model and has no policy call, gate, `can()` check or owner guard on it. The checks
that live outside the controller are read by the gate itself (`laravel_binding_context` in
`scripts/secgate.py`): `->can()` or `can:` middleware and admin roles on the route, `scopeBindings()`
with a checked parent, and a FormRequest whose `authorize()` checks the user.

The lab now has four clean files, and none is reported: a controller with `$this->authorize()`, a
FormRequest with an owner check in `authorize()`, an admin controller whose route has `->can()`, and a
controller with an `abort_unless($order->user_id === $request->user()->id, 404)` guard.

False positives outside the lab, measured the same day on a small, realistic Laravel app we wrote for
this (`tests/fixtures/laravel-authz/realistic-app`: a resource controller with `authorizeResource()`, an
admin resource behind `can:access-admin`, an API controller with policies and owner guards, nested
`scopeBindings()` routes, a public blog, comments with a FormRequest): Semgrep alone reports 8 bindings,
all of them covered by a route or a FormRequest, and the gate drops all 8, so 0 are left. In a separate
skeptical pass with 7 tricky safe and 6 tricky vulnerable controllers, one safe method was still reported
(the owner check sits in a private helper method) and one vulnerable method was missed (the policy call
runs in only one branch of an `if`). Both are listed as limits below.

Limits of the route model binding check, all review-only: checks in helper methods or in only one
branch, policies decided at run time, global scopes, `Route::bind()`, middleware registered in
`bootstrap/app.php` or `Kernel.php`, `->except()` in controller middleware, two controllers with the
same short class name, and models imported from a namespace without a `Models` segment. The
authorization matrix and cross-user tests in the skill stay the coverage list for these.

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
| L18 | IDOR through route model binding (show(Invoice $invoice) without authorize) | found | laravel-idor-route-model-binding |

`tests/test_benchmark_lab.py` keeps the quick-mode floor at 11 and the full-mode result at 18 of 18 when
Semgrep is installed, with no clean file reported in either mode, so a weaker or noisier rule fails CI.

## 7.0 labs: Spring Boot, legacy audit, pentest findings

Run on 2026-11-03 with the same tools (re-run after the 7.0 integration fixes, same numbers except the clean
Spring file). Each lab also lists "clean" files: safe code that must not be
reported (for the legacy lab, no malware rule may fire on normal Laravel, Spring, Express and WordPress
files). A finding on a clean file is counted as a false positive.

| Lab | Planted | Quick mode | Full mode | Clean files reported |
|---|---|---|---|---|
| `spring-lab.json` (Java and Spring Boot rules, database config, default values) | 20 | 6 | 20 | 0 of 1 (see below) |
| `legacy-lab.json` (webshells, backdoors, obfuscation, PHP upgrade blockers, default passwords, admin tools) | 17 | 17 | 17 | 0 of 7 |
| `web-lab.json` (input validation, owner pentest-skill items, database checks, default secrets) | 22 | 22 | 22 | 0 of 4 |

Commands: `py -I benchmark/run_lab.py --mode quick` and `py -I benchmark/run_lab.py --mode full` (all
labs; add `--lab spring` for one). The Java rules are Semgrep rules, so the Spring lab needs full mode;
quick mode only sees `SQL_CONCAT`, the database checks and the default-value checks there.

The clean Spring controller has `setParameter("n", "%" + note + "%")` on the same line as a parameterized
JPQL query. The line-based `SQL_CONCAT` heuristic used to report it; since 7.0 (V7I-05) it ignores
concatenation inside the arguments of binding calls (`setParameter`, `bind`, `bindValue`, `addValue` and
similar), so no clean file is reported. Concatenation outside those arguments is still reported (S4).
The floor test now requires 0 clean files reported.

The legacy lab samples are short, synthetic and inert (the encoded strings decode to words like
INERT). None is copied from a real webshell. The web lab's W9 to W11 reproduce the retest lesson from
the owner's pentest skills: a "fix" that rejects one quote character is reported as `DENYLIST_FIX`,
the query behind it is still reported, and so is the sibling query in the reset controller.

In full mode some rows also list Semgrep registry rules (for example `spring-csrf-disabled`,
`spring-actuator-fully-enabled`) next to ours; the row counts as found if any listed rule matches.

### Spring lab, full mode

| id | planted issue | result | rule |
|---|---|---|---|
| S1 | IDOR: show() loads any order by id | found | spring-idor-unscoped-lookup |
| S2 | Mass assignment: request body entity saved directly | found | spring-mass-assignment-entity-binding |
| S3 | @RequestBody without @Valid | found | spring-requestbody-without-valid |
| S4 | JPQL built by string concatenation | found | SQL_CONCAT, java-sqli-string-concat |
| S5 | SpEL expression from a request parameter | found | java-spel-injection |
| S6 | JNDI lookup name from a request parameter | found | java-jndi-injection |
| S7 | permitAll on /admin/** | found | spring-permitall-sensitive-path |
| S8 | CSRF disabled in a form-login app | found | spring-csrf-disabled, spring-csrf-disabled-with-session |
| S9 | XXE: DocumentBuilderFactory without disallow-doctype-decl | found | java-xxe-documentbuilderfactory |
| S10 | ObjectInputStream on a cookie value | found | java-unsafe-deserialization-objectinputstream |
| S11 | Jackson default typing | found | java-jackson-default-typing |
| S12 | Trust-all X509TrustManager | found | java-trust-all-certificates |
| S13 | MD5 password hash | found | java-weak-password-hash |
| S14 | java.util.Random reset token | found | java-insecure-random-token |
| S15 | Actuator exposes every endpoint | found | spring-actuator-exposed-properties, spring-actuator-fully-enabled |
| S16 | Database user root | found | DB_ROOT_USER |
| S17 | Database connection without TLS | found | DB_NO_TLS |
| S18 | Guessable datasource password admin123 | found | WEAK_DEFAULT_CREDENTIAL |
| S19 | jwt.secret=secret | found | DEFAULT_SECRET_KEY |
| S20 | /admin controller opened by permitAll | found | EXPOSED_ADMIN_PATH |

### Legacy lab, full mode

| id | planted issue | result | rule |
|---|---|---|---|
| G1 | Obfuscated eval(gzinflate(base64_decode())) injected into an include | found | WEBSHELL_OBFUSCATED_EVAL |
| G2 | Webshell in the uploads folder | found | PHP_IN_UPLOAD_DIR |
| G3 | eval of a request value | found | BACKDOOR_REQUEST_EXEC |
| G4 | system() on $_GET | found | BACKDOOR_REQUEST_EXEC |
| G5 | Request chooses the function: $_GET['f'](...) | found | REQUEST_DYNAMIC_CALL |
| G6 | preg_replace with /e | found | PREG_REPLACE_EVAL |
| G7 | PHP code inside an image | found | PHP_IN_IMAGE_FILE |
| G8 | eval(atob()) in front-end JS | found | WEBSHELL_OBFUSCATED_EVAL |
| G9 | Node exec with req.query | found | BACKDOOR_REQUEST_EXEC |
| G10 | JSP Runtime.exec on a request parameter | found | BACKDOOR_REQUEST_EXEC |
| G11 | ASPX Process.Start with Request.QueryString | found | BACKDOOR_REQUEST_EXEC |
| G12 | Python exec(b64decode()) | found | WEBSHELL_OBFUSCATED_EVAL |
| G13 | Long base64 blob in code | found | SUSPICIOUS_OBFUSCATION |
| G14 | Removed mysql_* API and deprecated utf8_encode | found | PHP_DEPRECATED_API |
| G15 | Database password 'root' in config.php | found | WEAK_DEFAULT_CREDENTIAL |
| G16 | Forgotten adminer.php | found | EXPOSED_ADMIN_TOOL |
| G17 | backup folder inside the web root | found | SENSITIVE_WEBROOT_PATH |

### Web lab, full mode

| id | planted issue | result | rule |
|---|---|---|---|
| W1 | Laravel controller reads input with no validation | found | MISSING_INPUT_VALIDATION |
| W2 | Express handler uses req.body with no validator | found | MISSING_INPUT_VALIDATION |
| W3 | debug=1 returns config and env (owner skills L19) | found | DEBUG_FLAG_FROM_REQUEST |
| W4 | Reset code route with no throttle (L20) | found | AUTH_ROUTE_NO_THROTTLE |
| W5 | 4-digit reset code | found | SHORT_NUMERIC_CODE |
| W6 | CSRF token is base64 of the user role (L21) | found | TOKEN_FROM_USER_DATA |
| W7 | Admin API token under a VITE_ prefix (L22) | found | PUBLIC_ENV_SECRET |
| W8 | Production source maps | found | SOURCEMAP_IN_PROD |
| W9 | Deny-list fix in front of a concatenated query | found | DENYLIST_FIX |
| W10 | The fake-fixed login query is still SQL injection | found | SQL_CONCAT |
| W11 | Sibling: the reset query built the same way | found | SQL_CONCAT |
| W12 | Express login route with no rate limit | found | AUTH_ROUTE_NO_THROTTLE |
| W13 | Card number column | found | DB_SENSITIVE_COLUMN |
| W14 | GRANT ALL to any host | found | DB_GRANT_ALL |
| W15 | MySQL container with empty password | found | DB_EMPTY_PASSWORD |
| W16 | MySQL bound to every interface | found | DB_BIND_ALL |
| W17 | utf8_encode, deprecated in PHP 8.2 | found | PHP_DEPRECATED_API |
| W18 | Postgres with the default password 'postgres' | found | WEAK_DEFAULT_CREDENTIAL |
| W19 | Redis without a password, port published | found | DB_NO_AUTH |
| W20 | Empty Laravel APP_KEY | found | DEFAULT_SECRET_KEY |
| W21 | /admin route without auth middleware | found | EXPOSED_ADMIN_PATH |
| W22 | Express session secret 'keyboard cat' | found | DEFAULT_SECRET_KEY |

`tests/test_benchmark_lab.py` keeps these floors: Laravel 11+ in quick mode and 18 of 18 in full mode, Spring 6+ in quick and
20 of 20 in full mode when Semgrep is installed, legacy and web all found, and no clean file reported in any lab.

## Not run yet

These public practice apps are good next targets. They have not been run, because the machine used for
this release has no Docker or PHP. Results will be added here with the exact command when they exist.

| Target | Stack | Why |
|---|---|---|
| OWASP Juice Shop | Node, Angular | many known findings, including broken access control |
| VAmPI | Python, Flask API | OWASP API Top 10 issues, BOLA |
| crAPI | microservices API | realistic BOLA and mass assignment |

If you run one of them, please open a compatibility report with the command and the output.
