# Standards coverage

This page maps four public lists to what NexaForge SecureCode checks today. It is meant to be read
by people deciding how much to trust the gate, so it errs on the side of saying less.

Lists used (all checked on 2026-11-03):

- OWASP Top 10:2025, https://owasp.org/Top10/2025/
- CWE Top 25 Most Dangerous Software Weaknesses, 2025 edition (the latest MITRE lists),
  https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
- OWASP API Security Top 10 2023, https://api-security.owasp.org/editions/2023/en/0x11-t10
- OWASP Application Security Verification Standard (ASVS) 5.0, chapters V1 to V17,
  https://github.com/OWASP/ASVS/tree/master/5.0/en

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
| A01:2025 Broken Access Control | Partial | Bare-id lookups without an owner check: `laravel-idor-unscoped-lookup` (L1 to L3), `spring-idor-unscoped-lookup` (S1). Route model binding without a policy, gate or owner guard: `laravel-idor-route-model-binding` (L18), with route `->can()`/`can:`, `scopeBindings()` and FormRequest `authorize()` read from the project by the gate. Mass assignment: `laravel-mass-assignment` (L5, L6), `spring-mass-assignment-entity-binding` (S2). Routes without auth: `laravel-api-route-without-auth` (L7), `spring-permitall-sensitive-path` (S7). CSRF: `STATE_CHANGE_OVER_GET` (L8), `spring-csrf-disabled-with-session` (S8). | Role checks inside business logic, multi-tenant scoping, checks in helper methods or only in one branch, policies decided at run time, global scopes, middleware set in bootstrap/app.php or Kernel.php. These are review only (authorization matrix plus cross-user tests). |
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
| 1 | CWE-79 Cross-site Scripting | Partial | `XSS_RAW_TEMPLATE` (L16) for raw template output (Blade `{!! !!}`, `|safe`, `<%-`) and `VUE_RAW_HTML` for Vue `v-html` (tests). DOM sinks (`XSS_SINK`, `REACT_RAW_HTML`) have no dedicated test. |
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
| 24 | CWE-639 Authorization Bypass Through User-Controlled Key | Caught | `laravel-idor-unscoped-lookup` (L1 to L3), `spring-idor-unscoped-lookup` (S1) for lookups by a bare id, `laravel-idor-route-model-binding` (L18) for route model binding with no policy, gate or owner guard. |
| 25 | CWE-770 Allocation of Resources Without Limits or Throttling | Partial | `AUTH_ROUTE_NO_THROTTLE` (W4, W12) for login, OTP, reset and verify routes only. |

## OWASP API Security Top 10 2023

| Item | Status | What catches it |
|---|---|---|
| API1:2023 Broken Object Level Authorization | Partial | The IDOR rules for Laravel and Spring (L1 to L3, S1), and Laravel route model binding (`laravel-idor-route-model-binding`, L18). GraphQL resolvers, Spring path variables bound to entities, and the limits listed under A01 are review only. |
| API2:2023 Broken Authentication | Partial | `AUTH_ROUTE_NO_THROTTLE`, `TOKEN_FROM_USER_DATA`, `SHORT_NUMERIC_CODE`, `TOKEN_TOO_SHORT`, `WEAK_DEFAULT_CREDENTIAL`. |
| API3:2023 Broken Object Property Level Authorization | Partial | Write side: the mass assignment rules (L5, L6, S2). Read side (returning too many fields) is review only. |
| API4:2023 Unrestricted Resource Consumption | Partial | `AUTH_ROUTE_NO_THROTTLE` only. General rate limits, page size caps and upload sizes are review only. |
| API5:2023 Broken Function Level Authorization | Partial | `laravel-api-route-without-auth`, `laravel-web-group-without-auth`, `spring-permitall-sensitive-path`. Role checks are review only. |
| API6:2023 Unrestricted Access to Sensitive Business Flows | Review only | |
| API7:2023 Server Side Request Forgery | Partial | Registry rules only, not measured. |
| API8:2023 Security Misconfiguration | Partial | As A02:2025 above. |
| API9:2023 Improper Inventory Management | Not yet | The route map in step 1 of the review protocol is the closest thing. |
| API10:2023 Unsafe Consumption of APIs | Review only | |

## OWASP ASVS 5.0

This table is guidance for reviewers, not a certification. ASVS is a verification standard: most of its
requirements are about design, configuration and behaviour that a static rule cannot see, so running the
gate does not make an application ASVS compliant at any level, and we do not claim that it does. One row
per chapter; a chapter is "Partial" when some of its requirements have a rule, never because all do.

| Chapter | Status | What covers part of it | Not covered |
|---|---|---|---|
| V1 Encoding and Sanitization | Partial | Injection: `SQL_CONCAT`, `java-sqli-string-concat`, `COMMAND_INJECTION`, `java-spel-injection`, `java-jndi-injection`. Raw template output: `XSS_RAW_TEMPLATE`, `VUE_RAW_HTML`. DOM sinks: `XSS_SINK`, `REACT_RAW_HTML` (no dedicated test). XML parsers: `java-xxe-documentbuilderfactory`, `java-xxe-saxparserfactory`, `java-xxe-xmlinputfactory`. Java deserialization: `java-unsafe-deserialization-objectinputstream`, `java-jackson-default-typing`. Review: A03 and A08 in `SOURCE-CODE-REVIEW.md`. | Whether encoding fits each output context, HTML sanitizers for rich text, NoSQL, LDAP, XPath, template injection, CSV and formula injection, and deserialization outside Java (registry rules only, not measured). |
| V2 Validation and Business Logic | Partial | `MISSING_INPUT_VALIDATION` (Laravel, Express), `spring-requestbody-without-valid`, `DENYLIST_FIX`, `AUTH_ROUTE_NO_THROTTLE` for anti-automation on auth routes. Review: A04 in `SOURCE-CODE-REVIEW.md`. | Whether the validation rules are right, business flow order, limits per user, race conditions and replay. Review only. |
| V3 Web Frontend Security | Partial | `MISSING_SECURITY_HEADERS`, `INSECURE_COOKIE_FLAG`, `CDN_WITHOUT_SRI`, `STATE_CHANGE_OVER_GET`, `spring-csrf-disabled-with-session`, `CORS_WILDCARD` and `OPEN_REDIRECT` (no dedicated test), `SOURCEMAP_IN_PROD`. | The quality of a Content Security Policy, cross-origin isolation headers, `postMessage` handling, browser storage of sensitive data, and headers set by a proxy outside the repo. |
| V4 API and Web Service | Partial | `laravel-api-route-without-auth`, `laravel-mass-assignment`, `spring-mass-assignment-entity-binding`, `CORS_WILDCARD`. Review: the API section of `SOURCE-CODE-REVIEW.md`. | HTTP message parsing and request smuggling, GraphQL depth and cost limits, WebSocket origin and auth checks. |
| V5 File Handling | Partial | `PATH_TRAVERSAL_SINK` (no dedicated test). `PHP_IN_UPLOAD_DIR` and `PHP_IN_IMAGE_FILE` find the result of a bad upload, not the handler. Review: "File upload and download" in `SOURCE-CODE-REVIEW.md`. | Upload size, type and content checks, archive bombs, storage outside the web root, safe download names. Review only. |
| V6 Authentication | Partial | `AUTH_ROUTE_NO_THROTTLE`, `WEAK_DEFAULT_CREDENTIAL`, `java-weak-password-hash`, `SHORT_NUMERIC_CODE`. Review: A07 in `SOURCE-CODE-REVIEW.md`. | Password policy, MFA, account recovery, user enumeration, credential stuffing defences beyond throttling. Review only. |
| V7 Session Management | Partial | Token generation: `TOKEN_FROM_USER_DATA`, `TOKEN_TOO_SHORT`, `INSECURE_RANDOM` (no dedicated test). Cookie flags are counted under V3. Review: A07 in `SOURCE-CODE-REVIEW.md` (fixation, logout). | Session timeouts, termination on logout and password change, re-authentication before sensitive actions. Review only. |
| V8 Authorization | Partial | `laravel-idor-unscoped-lookup`, `laravel-idor-route-model-binding`, `spring-idor-unscoped-lookup`, `laravel-web-group-without-auth`, `spring-permitall-sensitive-path`, `EXPOSED_ADMIN_PATH`. Field level: the mass assignment rules. Review: the authorization matrix and cross-user tests. | Role and attribute checks in business logic, multi-tenant scoping, checks decided at run time. See A01 above. |
| V9 Self-contained Tokens | Partial | `JWT_DECODE_NO_VERIFY` (no dedicated test), `DEFAULT_SECRET_KEY` for known example signing secrets. Review: the JWT step in A07 of `SOURCE-CODE-REVIEW.md`. | Algorithm allowlists, `alg: none`, audience and issuer checks, expiry, key sources and rotation. Review only. |
| V10 OAuth and OIDC | Not yet | No rule and no specific review step. | Redirect URI matching, `state` and PKCE, token storage, client authentication, ID token validation. |
| V11 Cryptography | Partial | `INSECURE_CRYPTO`, `java-weak-password-hash`, `java-insecure-random-token`, `TOKEN_TOO_SHORT`, `INSECURE_RANDOM` (no dedicated test), `DEFAULT_SECRET_KEY`. Review: A02 in `SOURCE-CODE-REVIEW.md`. | Key management, cryptographic inventory, cipher modes such as ECB, IV and nonce reuse, post-quantum planning. |
| V12 Secure Communication | Partial | `OLD_TLS_PROTOCOL`, `DB_NO_TLS`, `java-trust-all-certificates`, `java-trust-all-hostnames`, `org-python-requests-verify-false`, `DISABLE_TLS_VERIFY` (no dedicated test). | TLS settings of the real server and load balancer, HSTS preload, mutual TLS between services. Runtime pentest. |
| V13 Configuration | Partial | `DEBUG_FLAG_FROM_REQUEST`, `DEBUG_EXPOSURE` (no dedicated test), `spring-actuator-exposed-properties`, `spring-actuator-exposed-yaml`, `DIRECTORY_LISTING`, `WEBROOT_EXPOSURE`, `SENSITIVE_WEBROOT_PATH`, `EXPOSED_ADMIN_TOOL`, `HARDCODED_SECRET`, `LIVE_API_KEY`, `PUBLIC_ENV_SECRET`, `DB_BIND_ALL`, `DB_NO_AUTH`, Gitleaks. Review: A05 in `SOURCE-CODE-REVIEW.md`. | Use of a secrets vault, least privilege for service accounts, configuration that lives outside the repo. |
| V14 Data Protection | Partial | `PUBLIC_ENV_SECRET`, `SOURCEMAP_IN_PROD`, `SENSITIVE_LOG` (no dedicated test). | Data classification, cache headers on sensitive responses, retention and deletion, sensitive data in URLs. Review only. |
| V15 Secure Coding and Architecture | Partial | `VULNERABLE_LIBRARY`, `UNSUPPORTED_PLATFORM`, `PHP_DEPRECATED_API`, Trivy for lockfiles, the mass assignment rules. Review: A06 in `SOURCE-CODE-REVIEW.md`. | Architecture documentation, SBOM, prototype pollution, type juggling, concurrency and thread safety. |
| V16 Security Logging and Error Handling | Partial | `DEBUG_FLAG_FROM_REQUEST` for stack traces switched on by the caller, `SENSITIVE_LOG` (no dedicated test). Review: A09 in `SOURCE-CODE-REVIEW.md`. | Whether security events are logged and alerted, log integrity and forging, fail-open error paths. Mostly review only. |
| V17 WebRTC | Not yet | No rule and no review step. | All of it (TURN servers, media encryption, signaling). Out of scope for the stacks this tool targets. |

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
