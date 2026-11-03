# Standards coverage

This page maps three public lists to what NexaForge SecureCode checks today. It is meant to be read
by people deciding how much to trust the gate, so it errs on the side of saying less.

Lists used (all checked on 2026-11-03):

- OWASP Top 10:2025, https://owasp.org/Top10/2025/
- CWE Top 25 Most Dangerous Software Weaknesses, 2025 edition (the latest MITRE lists),
  https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- OWASP API Security Top 10 2023, https://api-security.owasp.org/editions/2023/en/0x11-t10

## What the words mean

| Status | Meaning |
|---|---|
| **Caught** | At least one gate rule reports the common form of this weakness, the rule has positive and negative tests in `tests/`, and a planted bug in a benchmark lab is found by it. It does not mean every variant is found. |
| **Partial** | Some forms are caught as above, or a rule exists but has no dedicated test yet, or only Semgrep registry rules (`p/default`, `p/owasp-top-ten`) cover it and we have not measured them. |
| **Review only** | No rule. The "Run Security Test" protocol asks the agent to check it by reading the code (`docs/SOURCE-CODE-REVIEW.md`), which depends on the agent doing it well. |
| **Not yet** | Neither a rule nor a specific review step. |

Lab ids (L, S, G, W) point to `benchmark/laravel-lab.json`, `spring-lab.json`, `legacy-lab.json` and
`web-lab.json`; `benchmark/RESULTS.md` has the scores. Static rules can only see code: anything that
depends on how the app is deployed or what the business rules are still needs the runtime pentest.

## OWASP Top 10:2025

| Category | Status | What catches it | Not covered |
|---|---|---|---|
| A01:2025 Broken Access Control | Partial | Bare-id lookups without an owner check: `laravel-idor-unscoped-lookup` (L1 to L3), `spring-idor-unscoped-lookup` (S1). Mass assignment: `laravel-mass-assignment` (L5, L6), `spring-mass-assignment-entity-binding` (S2). Routes without auth: `laravel-api-route-without-auth` (L7), `spring-permitall-sensitive-path` (S7). CSRF: `STATE_CHANGE_OVER_GET` (L8), `spring-csrf-disabled-with-session` (S8). | IDOR through route model binding (L18 is a known miss), role checks inside business logic, multi-tenant scoping. These are review only (authorization matrix plus cross-user tests). |
| A02:2025 Security Misconfiguration | Partial | `MISSING_SECURITY_HEADERS` (L9), `DIRECTORY_LISTING` (L14), `WEBROOT_EXPOSURE` (L13), `INSECURE_COOKIE_FLAG` (L10), `spring-actuator-exposed-*` (S15), `DEBUG_FLAG_FROM_REQUEST` (W3), `SOURCEMAP_IN_PROD` (W8), XML parsers without XXE hardening `java-xxe-*` (S9), database settings `DB_BIND_ALL`, `DB_TRUST_AUTH`, `DB_EMPTY_PASSWORD`, `DB_NO_TLS` (W15, W16, S17). | `DEBUG_EXPOSURE` and `CORS_WILDCARD` have no dedicated test. Server and cloud configuration that is not in the repo. |
| A03:2025 Software Supply Chain Failures | Partial | `VULNERABLE_LIBRARY` for copied front-end libraries (L12), `UNSUPPORTED_PLATFORM` for PHP and Laravel versions (L17), Trivy for lockfile dependencies, `PHP_DEPRECATED_API` for upgrade blockers (G14, W17), the agent and MCP config checks. | Build pipeline integrity, provenance of every package, CI runner hardening. |
| A04:2025 Cryptographic Failures | Partial | `INSECURE_CRYPTO` (tests), `java-weak-password-hash` (S13), `java-insecure-random-token` (S14), `java-trust-all-certificates` / `-hostnames` (S12), `TOKEN_FROM_USER_DATA` (W6), `OLD_TLS_PROTOCOL` (tests), `DB_NO_TLS` (S17). | `INSECURE_RANDOM` and `DISABLE_TLS_VERIFY` have no dedicated test. Key management, ECB mode, hardcoded keys outside Gitleaks patterns. |
| A05:2025 Injection | Partial | SQL: `SQL_CONCAT` (L4, W10, W11), `java-sqli-string-concat` (S4). OS command and code: `COMMAND_INJECTION` (tests), `BACKDOOR_REQUEST_EXEC` (G3, G4, G9 to G11), `java-spel-injection` (S5), `java-jndi-injection` (S6). XSS in templates: `XSS_RAW_TEMPLATE` (L16). | `XSS_SINK`, `REACT_RAW_HTML` and `PATH_TRAVERSAL_SINK` have no dedicated test. NoSQL, LDAP, XPath and template injection (SSTI) rely on registry rules only. |
| A06:2025 Insecure Design | Partial | `DENYLIST_FIX` (W9), `SHORT_NUMERIC_CODE` (W5), `AUTH_ROUTE_NO_THROTTLE` (W4, W12). | Business logic, race conditions, client-side trust decisions beyond public env names. Mostly review only. |
| A07:2025 Authentication Failures | Partial | `AUTH_ROUTE_NO_THROTTLE` (W4, W12), `WEAK_DEFAULT_CREDENTIAL` (L11, S18, G15, W18), `DEFAULT_SECRET_KEY` (S19, W20, W22), `SHORT_NUMERIC_CODE`, `TOKEN_FROM_USER_DATA`, `TOKEN_TOO_SHORT` (tests), `java-weak-password-hash` (S13). | Session fixation, logout and token expiry, JWT handling (`JWT_DECODE_NO_VERIFY` has no dedicated test), MFA logic. |
| A08:2025 Software or Data Integrity Failures | Partial | Java deserialization: `java-unsafe-deserialization-objectinputstream` (S10), `java-xstream-without-allowlist`, `java-jackson-default-typing` (S11). `CDN_WITHOUT_SRI` (L15). Planted code: the legacy audit rules (G1 to G13). | PHP `unserialize`, Python `pickle` and .NET `BinaryFormatter` rely on registry rules only. |
| A09:2025 Security Logging and Alerting Failures | Review only | `SENSITIVE_LOG` exists but has no dedicated test. | Whether security events are logged and alerted at all. |
| A10:2025 Mishandling of Exceptional Conditions | Partial | `DEBUG_FLAG_FROM_REQUEST` (W3) for stack traces and config dumps switched on by the caller. | Fail-open error paths, swallowed exceptions, verbose production errors (`DEBUG_EXPOSURE` has no dedicated test). Review only. |

## CWE Top 25 (2025)

| Rank | CWE | Status | What catches it |
|---|---|---|---|
| 1 | CWE-79 Cross-site Scripting | Partial | `XSS_RAW_TEMPLATE` (L16) for raw template output (Blade `{!! !!}`, `|safe`, `<%-`, `v-html`). DOM sinks (`XSS_SINK`, `REACT_RAW_HTML`) have no dedicated test. |
| 2 | CWE-89 SQL Injection | Caught | `SQL_CONCAT` (L4, W10, W11), `java-sqli-string-concat` (S4). Line based: queries built over several lines in PHP or JS can be missed. |
| 3 | CWE-352 Cross-Site Request Forgery | Caught | `STATE_CHANGE_OVER_GET` (L8), `spring-csrf-disabled-with-session` (S8). Laravel `VerifyCsrfToken::$except` lists are review only. |
| 4 | CWE-862 Missing Authorization | Partial | `laravel-api-route-without-auth` (L7), `laravel-web-group-without-auth`, `spring-permitall-sensitive-path` (S7), `EXPOSED_ADMIN_PATH` for admin and console routes in Laravel, Express and Spring (S20, W21). Checks inside handlers are review only. |
| 5 | CWE-787 Out-of-bounds Write | Not yet | No C or C++ rules. Out of scope for the web stacks this tool targets. |
| 6 | CWE-22 Path Traversal | Partial | `PATH_TRAVERSAL_SINK` (no dedicated test), registry rules. |
| 7 | CWE-416 Use After Free | Not yet | No C or C++ rules. |
| 8 | CWE-125 Out-of-bounds Read | Not yet | No C or C++ rules. |
| 9 | CWE-78 OS Command Injection | Caught | `COMMAND_INJECTION` (tests), `BACKDOOR_REQUEST_EXEC` (G4, G9, G10, G11). |
| 10 | CWE-94 Code Injection | Caught | `BACKDOOR_REQUEST_EXEC` with eval/include (G3), `WEBSHELL_OBFUSCATED_EVAL` (G1, G8, G12), `REQUEST_DYNAMIC_CALL` (G5), `PREG_REPLACE_EVAL` (G6), `java-spel-injection` (S5). |
| 11 | CWE-120 Classic Buffer Overflow | Not yet | No C or C++ rules. |
| 12 | CWE-434 Unrestricted Upload of Dangerous File | Partial | `PHP_IN_UPLOAD_DIR` (G2) and `PHP_IN_IMAGE_FILE` (G7) find the result of a bad upload, not the upload handler. Upload validation is review only. |
| 13 | CWE-476 NULL Pointer Dereference | Not yet | Not a security rule target here. |
| 14 | CWE-121 Stack-based Buffer Overflow | Not yet | No C or C++ rules. |
| 15 | CWE-502 Deserialization of Untrusted Data | Partial | Caught for Java: `java-unsafe-deserialization-objectinputstream` (S10), `java-jackson-default-typing` (S11), `java-xstream-without-allowlist` (fixtures). PHP, Python and .NET rely on registry rules. |
| 16 | CWE-122 Heap-based Buffer Overflow | Not yet | No C or C++ rules. |
| 17 | CWE-863 Incorrect Authorization | Review only | Authorization matrix and cross-user tests in the "Run Security Test" protocol. |
| 18 | CWE-20 Improper Input Validation | Caught | `MISSING_INPUT_VALIDATION` for Laravel controllers and Express handlers (W1, W2), `spring-requestbody-without-valid` (S3). Django, FastAPI and ASP.NET are not covered yet. |
| 19 | CWE-284 Improper Access Control | Partial | Same rules as CWE-862 and CWE-639. |
| 20 | CWE-200 Exposure of Sensitive Information | Caught | `spring-actuator-exposed-*` (S15), `DEBUG_FLAG_FROM_REQUEST` (W3), `WEBROOT_EXPOSURE` (L13), `SOURCEMAP_IN_PROD` (W8), `PUBLIC_ENV_SECRET` (W7). |
| 21 | CWE-306 Missing Authentication for Critical Function | Partial | `laravel-api-route-without-auth` (L7) for Laravel API routes. Other frameworks are review only. |
| 22 | CWE-918 Server-Side Request Forgery | Partial | Registry rules only, not measured. Review step in A10 of `SOURCE-CODE-REVIEW.md`. |
| 23 | CWE-77 Command Injection | Caught | As CWE-78. |
| 24 | CWE-639 Authorization Bypass Through User-Controlled Key | Caught | `laravel-idor-unscoped-lookup` (L1 to L3), `spring-idor-unscoped-lookup` (S1) for lookups by a bare id. Route model binding (L18) is a known miss. |
| 25 | CWE-770 Allocation of Resources Without Limits or Throttling | Partial | `AUTH_ROUTE_NO_THROTTLE` (W4, W12) for login, OTP, reset and verify routes only. |

## OWASP API Security Top 10 2023

| Item | Status | What catches it |
|---|---|---|
| API1:2023 Broken Object Level Authorization | Partial | The IDOR rules for Laravel and Spring (L1 to L3, S1). Route model binding (L18) and GraphQL resolvers are review only. |
| API2:2023 Broken Authentication | Partial | `AUTH_ROUTE_NO_THROTTLE`, `TOKEN_FROM_USER_DATA`, `SHORT_NUMERIC_CODE`, `TOKEN_TOO_SHORT`, `WEAK_DEFAULT_CREDENTIAL`. |
| API3:2023 Broken Object Property Level Authorization | Partial | Write side: the mass assignment rules (L5, L6, S2). Read side (returning too many fields) is review only. |
| API4:2023 Unrestricted Resource Consumption | Partial | `AUTH_ROUTE_NO_THROTTLE` only. General rate limits, page size caps and upload sizes are review only. |
| API5:2023 Broken Function Level Authorization | Partial | `laravel-api-route-without-auth`, `laravel-web-group-without-auth`, `spring-permitall-sensitive-path`. Role checks are review only. |
| API6:2023 Unrestricted Access to Sensitive Business Flows | Review only | |
| API7:2023 Server Side Request Forgery | Partial | Registry rules only, not measured. |
| API8:2023 Security Misconfiguration | Partial | As A02:2025 above. |
| API9:2023 Improper Inventory Management | Not yet | The route map in step 1 of the review protocol is the closest thing. |
| API10:2023 Unsafe Consumption of APIs | Review only | |

## Other CWEs the gate targets

| CWE | Status | What catches it |
|---|---|---|
| CWE-798 Use of Hard-coded Credentials | Partial | `WEAK_DEFAULT_CREDENTIAL` and `DEFAULT_SECRET_KEY` for guessable or placeholder values (S18, S19, G15, W18, W20, W22), `HARDCODED_SECRET`, `LIVE_API_KEY` and Gitleaks for real-looking secrets. A strong secret committed to the repo is found only when Gitleaks or `HARDCODED_SECRET` knows its shape. |
| CWE-521 Weak Password Requirements | Partial | `WEAK_DEFAULT_CREDENTIAL` reports guessable passwords from a short bundled list (about 50 entries) and passwords equal to the user name, in code, config, seeders, compose files and connection strings. Password policy rules in the app (minimum length, breached-password checks) are review only. |
| CWE-1392 Use of Default Credentials | Caught | `WEAK_DEFAULT_CREDENTIAL` (S18, G15, W18: `admin123`, `root`/`root`, `postgres`), `DB_ROOT_USER` (S16), SQL Server `sa` with an empty password, `DB_EMPTY_PASSWORD` (W15), `DB_NO_AUTH` for Redis and MongoDB published without a password (W19). |
| CWE-552 Files or Directories Accessible to External Parties | Caught | `SENSITIVE_WEBROOT_PATH` (G17: backup, old, bak, test, tmp, dump folders in the web root), `EXPOSED_ADMIN_TOOL` (G16: adminer.php, phpinfo.php, phpMyAdmin), `WEBROOT_EXPOSURE` (L13), `EXPOSED_ADMIN_PATH` for admin, console, debug and test routes without auth (S20, W21). |

Placeholders such as `${DB_PASSWORD}`, `<password>`, `your-password-here` and env lookups are not
reported. Values on the weak lists win over the placeholder test, so `your-256-bit-secret` (copied
from the jwt.io example and often deployed) is still reported.

## Keeping this page honest

A row moves to "Caught" only in the same change that adds the rule, its positive and negative tests,
and a planted bug in a lab. If a rule is weakened or a lab score drops, the row moves back. The lab
floors in `tests/test_benchmark_lab.py` fail CI when a score drops.
