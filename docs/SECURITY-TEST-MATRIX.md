# Security Test Matrix

For every security-sensitive feature, ask Claude to cover:

## Web

- Authentication: missing/invalid/expired credentials, session fixation, token validation.
- Authorization: horizontal IDOR/BOLA and vertical privilege escalation.
- Injection: SQL/NoSQL/LDAP/command/template where applicable.
- Browser: XSS (reflected/stored/DOM), CSRF, CORS, clickjacking, security headers.
- Server: SSRF, path traversal, file upload, deserialization, host header issues.
- Secrets: credentials in source, logs, CI and artifacts.
- Dependencies: known CVEs, malicious/typosquat risk, lockfile drift.
- API: undocumented endpoints, excessive data exposure, rate limits, method abuse.
- Business logic: replay, race conditions, workflow bypass, price/role/ownership manipulation.
- Resilience: malformed input, large input, repeated requests, timeout/error behavior.

## Mobile (Android & iOS)

Triggered the same way as the Web matrix, by the "Run Security Test" phrase, scoped
to mobile when a mobile project (Gradle/Android manifest, Xcode project/Info.plist) is
detected, or when `--target mobile` is passed.

- **Component & IPC security:** exported Activities/Services/Content Providers/Broadcast
  Receivers without permission enforcement; deep-link validation and intent-spoofing
  vectors; unvalidated intents from other apps.
- **Insecure data storage & transport:** cleartext data in SharedPreferences,
  NSUserDefaults, or an unencrypted SQLite database; missing or bypassable SSL/TLS
  certificate pinning; insecure cleartext-HTTP network-security-config allowlists.
- **Build/runtime hardening:** `android:debuggable="true"` or equivalent debug flags left
  enabled in production manifests/build configs; missing code obfuscation where required
  by policy.
- **Client-side secrets & logging:** hardcoded credentials/API keys in source or bundled
  assets; tokens or PII written to Logcat/NSLog/console in release builds; improper
  root/jailbreak detection that can be trivially bypassed and is relied on as a security
  control rather than defense-in-depth.

Mobile findings that require the actual manifest, entitlements, or signed build to
confirm (e.g. whether pinning is actually enforced at runtime) must be reported as
"needs device/build verification," not asserted as confirmed from source alone.
