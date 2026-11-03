# What pentests of AI-built web apps keep finding (and how to pass the first time)

The agent uses this list as its priority order in "Security Test Karo" and "Advisory QA Karo", and checks
every item before handover. It reflects what security teams commonly report on business web apps
(PHP/Laravel, WordPress, Node, .NET) and Android apps. If your organization installed its own
`docs/ORG-FINDINGS.md` next to this file, that list takes priority.

## Repeat findings, roughly most frequent first

| # | Finding | What to do in the code | Gate rule |
|---|---|---|---|
| 1 | Outdated client-side libraries (jQuery 1.x/2.x/3.3, Bootstrap 3/4, jQuery UI 1.11/1.12, GSAP/TweenMax 1-2 in slider themes, jQuery Validation, Moment, DataTables 1.10, Highcharts 7, TinyMCE 4, AngularJS, bootstrap-tagsinput) | Upgrade every copy, including those inside themes, admin templates and plugins. Minimum: jQuery 3.7.x, Bootstrap 5.3.x. Delete unused files instead of commenting them out. | `VULNERABLE_LIBRARY` (HIGH) |
| 2 | Information disclosure: debug on, stack traces, file paths or SQL in errors, 500 instead of 404 | `APP_DEBUG=false`, a custom error handler with generic pages, 404 for unknown routes and IDs. | `DEBUG_EXPOSURE`, review |
| 3 | Weak TLS (CBC ciphers, TLS 1.0/1.1), HSTS missing or conflicting | TLS 1.2/1.3 only, AEAD ciphers, one HSTS header. Keep the server config in the repo so it can be checked. | `OLD_TLS_PROTOCOL`, review |
| 4 | Missing security headers, clickjackable login | One headers middleware on **every** route, admin and login included. SRI on every CDN script. | `MISSING_SECURITY_HEADERS`, `CDN_WITHOUT_SRI` |
| 5 | Dev and build files in the web root (source maps, `.git`, `composer.json`, `vite.config.js`, `.DS_Store`, `debug.log`, backups) | Only built assets go to `public/`; no source maps in production; block dotfiles in the server. | `WEBROOT_EXPOSURE` |
| 6 | Exposed admin panels and open ports (`/phpmyadmin`, `/cpanel`, database ports, FTP) | Not reachable from the internet; VPN or IP allowlist. List it for the server team. | review (infra) |
| 7 | Cookies without `Secure` / `HttpOnly` | Secure and HttpOnly on every cookie, SameSite lax or strict. Fix the cookie itself. | `INSECURE_COOKIE_FLAG` |
| 8 | Outdated server or platform (PHP 7.x, old Laravel, old web server, WordPress core) | Supported PHP (8.2+), supported framework release, updates before handover. | `UNSUPPORTED_PLATFORM`, Trivy |
| 9 | XSS, reflected and stored (often in admin-managed fields) | Escape by default, sanitize rich text, never raw-output user or admin input, CSP. | Semgrep, `XSS_SINK`, review |
| 10 | No rate limit / brute force / OTP abuse / CAPTCHA bypass | Throttle login, OTP, reset, contact and payment forms; verify CAPTCHA server-side; single-use OTPs. | review |
| 11 | Directory listing | `Options -Indexes` / `autoindex off`. | `DIRECTORY_LISTING` |
| 12 | CSRF through state changes over GET | Deletes and updates use POST/PATCH/DELETE with the CSRF token. | `STATE_CHANGE_OVER_GET` |
| 13 | Broken access control / IDOR (usually the Critical ones) | Scope every query to the user/tenant, policies on every route, cross-user negative tests. | review (SOURCE-CODE-REVIEW A01) |
| 14 | Hardcoded or over-exposed secrets (payment credentials, unrestricted Google keys) | Secrets on the server only; restrict client keys; never return keys to normal users. | Gitleaks, `LIVE_API_KEY`, `GOOGLE_API_KEY_IN_CODE` |
| 15 | SQL injection (often time-based blind in search parameters) | Bindings only; allowlist sort columns. | Semgrep, `SQL_CONCAT`, review |
| 16 | Less common but serious: SSRF via webhook URLs, unauthenticated webhooks, open redirects / OIDC `redirect_uri`, CORS, polyglot image uploads, PII in GET | See SOURCE-CODE-REVIEW A10, A08 and uploads. | review |

Android: exported activities or WebViews that load any URL, hardcoded payment or API secrets in the APK,
cleartext personal data in SharedPreferences, credentials or full HTTP bodies in Logcat, cleartext traffic,
internal IPs in the app, client-side payment hashes with a hardcoded salt, `rawQuery` concatenation.
Gate rules: `ANDROID_EXPORTED_COMPONENT`, `ANDROID_DEBUGGABLE`, `ANDROID_CLEARTEXT`, `ANDROID_BACKUP`,
`LIVE_API_KEY`, `SENSITIVE_LOG`, `SQL_CONCAT`; the rest is in the mobile matrix.

## Why projects fail the retest, and what the agent must not do

- **"Fixed" but still there.** Re-run the same check after the fix and include the evidence in the handover.
- **Commenting a library out.** Delete it or upgrade it; the file is still downloadable.
- **Headers on one page.** Apply the middleware globally; check an admin URL and the login page too.
- **"The theme does not allow an upgrade."** Upgrade the library inside the theme, or replace the component.
- **Fixing the symptom.** A missing cookie flag is fixed on the cookie, not by adding other headers.
- **"Server-side, not ours."** If the repo ships the server config, fix it there; otherwise list it for the server team.
- **Default admin credentials in the testing request.** Seed a random password, force a change on first login,
  and share test accounts through the agreed channel, never in plain text.
