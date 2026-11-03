# Deep source code review checklist (7.0.0)

Used by the agent in "Run Security Test" and "Run Advisory QA", and for self-review before saying
a feature is done. Organized by OWASP Top 10 2021 and API Security Top 10 2023. For each class:
what to look for, the fix, and the negative test to add. Examples cover the stacks we see most
(Laravel/PHP, Node/Express, ASP.NET Core, Django/Python, React/Vue); apply the same idea elsewhere.

How to review: list every entry point (routes, controllers, API handlers, webhooks, jobs, deep
links), then for each one trace input to sink. Scanners find patterns; this trace finds IDOR,
missing checks and logic bugs, which make up most real pentest findings.

---

## A01 Broken access control (IDOR / BOLA, function-level, mass assignment)

**Look for**
- An object loaded by an ID from the URL, query, body or header without scoping it to the current
  user or tenant: `Model::find($id)`, `findOrFail($request->id)`, `Order.findById(req.params.id)`,
  `_db.Orders.Find(id)`, `Order.objects.get(pk=pk)`.
- The same check missing on the *other* verbs: read is scoped but update, delete, export, download,
  "duplicate", "share" or bulk endpoints are not.
- Role or permission checked only in the UI or the route list, not on the handler.
- Request data bound straight into a model: `$model->update($request->all())`, `Object.assign(user, req.body)`,
  `[Bind]` missing / `TryUpdateModelAsync` with all fields, `ModelForm` with `fields = "__all__"`.
- Sequential or guessable IDs on sensitive objects (invoices, documents, certificates).
- Directory listing or direct file URLs to private uploads.

**Fix**
- Load through the owner scope: `auth()->user()->orders()->findOrFail($id)` or a policy
  (`$this->authorize('view', $order)`); `Order.findOne({ _id: id, owner: req.user.id })`;
  `_db.Orders.Where(o => o.Id == id && o.OwnerId == userId)`; `get_object_or_404(Order, pk=pk, owner=request.user)`.
- Tenant tables: scope by tenant **and** account, resolved from the authenticated user, never from the body.
- Middleware/attribute for roles on every admin route (`can:`, `[Authorize(Roles=...)]`, `@permission_required`).
- Allowlist fields: `$request->validated()` with `$fillable`, DTOs, `[Bind("Name,Email")]`, explicit serializer fields.
- Return 404 (not 403) for objects the user may not know exist, if the product allows.

**Test**: user A requests user B's object on every verb (GET/PUT/PATCH/DELETE/export) and gets 403/404;
a normal user calls an admin route and gets 403; a request that sends `role=admin` or `owner_id` is ignored.

## A02 Cryptographic failures

**Look for**: MD5/SHA1 for passwords, homemade encryption, ECB, hardcoded keys/IVs, `Math.random()`/`rand()`
for tokens, HTTP links, TLS verification off, sensitive data stored unencrypted.
**Fix**: `Hash::make` / bcrypt / argon2 / ASP.NET Identity hasher / Django hashers; framework encryption with
keys from env/secret store; `random_bytes`, `crypto.randomBytes`, `RandomNumberGenerator`, `secrets`; HTTPS + HSTS.
**Test**: stored password is not reversible; reset tokens are 128-bit+ random and expire.

## A03 Injection (SQL, NoSQL, command, template, LDAP) and XSS

**Look for**
- SQL built with strings: `DB::raw("... $x")`, `whereRaw("id = $id")`, `` `SELECT ... ${id}` ``,
  `FromSqlRaw($"... {id}")`, `cursor.execute(f"... {x}")`, dynamic `ORDER BY`/column names from input.
- NoSQL operator injection: `find(req.body)`, `{ $where: ... }`.
- Commands: `exec`, `shell_exec`, `system`, `child_process.exec`, `Process.Start` with joined strings, `shell=True`.
- Template injection: user input as the template itself (`render_template_string`, `Blade::render($input)`).
- XSS sinks: `{!! $x !!}`, `|safe`, `Html.Raw`, `innerHTML`, `v-html`, `dangerouslySetInnerHTML`,
  `document.write`, jQuery `.html()`/`.append()` with user data, `href="javascript:..."`, SVG/HTML uploads served inline.
**Fix**: bindings (`where('id', $id)`, `?` placeholders, `FromSqlInterpolated`, parameterized cursor); allowlist for
order/column names; argument arrays (`execFile`, `subprocess.run([...])`); auto-escaping (`{{ }}`, default Razor);
sanitize rich text with a maintained sanitizer (HTMLPurifier, DOMPurify); `Content-Disposition: attachment` for uploads; CSP.
**Test**: `' OR 1=1--` and `<script>alert(1)</script>` in every new input are stored/returned harmlessly.

## A04 Insecure design (business logic)

**Look for**: no rate limit or lockout on login, OTP, password reset, signup, coupon or contact forms; OTP
reusable or not tied to the user; price/quantity/discount taken from the client; race conditions on balance,
stock, votes or one-time actions; workflow steps skippable by calling a later endpoint directly.
**Fix**: throttle middleware (`throttle:5,1`, `express-rate-limit`, ASP.NET rate limiting, django-ratelimit);
server-side prices; DB transactions with row locks or unique constraints; state checks on every step.
**Test**: 6th failed login in a minute is refused; replaying an OTP fails; two parallel redeem calls succeed once.

## A05 Security misconfiguration

**Look for**: `APP_DEBUG=true`, `DEBUG=True`, developer exception page in production, stack traces in
responses, default credentials, directory listing, exposed `/telescope`, `/horizon`, `/_debugbar`, `/swagger`,
`/phpmyadmin`, `/.git`, `/.env`, `phpinfo()`, backup files in the web root, permissive CORS (`*` with credentials),
missing security headers, cookies without `Secure`/`HttpOnly`/`SameSite`, verbose server banners.
**Fix**: production config from env; admin/debug tools behind auth or disabled; headers middleware:
`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options: DENY` (or `frame-ancestors`),
`X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`;
explicit CORS allowlist; secure cookie settings (`SESSION_SECURE_COOKIE=true`, `SameSite=Lax/Strict`).
**Test**: a header test asserts each header on a normal response; `/.env` and debug routes return 404.

## A06 Vulnerable and outdated components

**Look for**: Trivy findings on lockfiles; `VULNERABLE_LIBRARY` findings for jQuery, jQuery UI, Bootstrap,
AngularJS, Moment, Lodash, Handlebars copied into `public/`, `assets/`, `wwwroot/` or loaded from a CDN;
framework or runtime versions out of support (old Laravel, PHP, Node, .NET, Django); abandoned packages;
CDN scripts without Subresource Integrity.
**Fix**: upgrade to a supported release that contains the fix (the finding names it); replace vendored copies
with the package manager version; add `integrity` + `crossorigin` to CDN tags; remove unused libraries.
Do not suppress these findings to get a pass: an outdated library is the most common repeat finding.
**Test**: the gate shows no High/Critical Trivy result and no `VULNERABLE_LIBRARY`.

## A07 Identification and authentication failures

**Look for**: weak password rules, no MFA option for admins, user enumeration in login/reset messages,
session not regenerated at login (fixation), logout that does not invalidate the session or token,
JWT `alg: none`/unchecked signature/no expiry/secret in code, long-lived tokens in `localStorage`, remember-me
tokens that never expire, OTP sent in the response.
**Fix**: framework auth; `session()->regenerate()`; same message for unknown user and wrong password;
JWT verify with a fixed algorithm and short expiry plus refresh rotation; tokens in HttpOnly cookies.
**Test**: session id changes after login; a logged-out token is rejected; an expired JWT is rejected.

## A08 Software and data integrity failures

**Look for**: unsafe deserialization (`unserialize`, `pickle`, `BinaryFormatter`, `yaml.load`), unsigned
webhooks or signature compared with `==`, auto-updates or plugins from unverified sources, CI that runs
untrusted PR code with secrets.
**Fix**: JSON with schema validation; HMAC signature check on the raw body with constant-time compare
(`hash_equals`, `crypto.timingSafeEqual`, `CryptographicOperations.FixedTimeEquals`, `hmac.compare_digest`);
reject empty secrets; pinned dependencies with a lockfile.
**Test**: a webhook with a wrong or missing signature returns 401/403.

## A09 Logging and monitoring failures

**Look for**: passwords, tokens, OTPs, full card numbers or full phone numbers in logs; no log for failed logins,
permission denials or admin actions; logs that accept raw user input with newlines (log forging).
**Fix**: log IDs not secrets; mask PII; structured logging; audit log for auth and admin events.

## A10 Server-side request forgery (SSRF)

**Look for**: the server fetching a URL the user controls (webhooks, URL preview, import from URL, PDF/image
fetchers) without an allowlist; redirects followed blindly; access to `169.254.169.254`, `localhost`, internal hosts.
**Fix**: allowlist of hosts/schemes; resolve DNS and block private ranges; disable redirects or re-check them.

---

## File upload and download

**Look for**: type checked by extension or client MIME only; executable types allowed (`.php`, `.phtml`, `.aspx`,
`.jsp`, `.svg`, `.html`); original file name used on disk; files stored under the web root; no size limit;
image processing on untrusted files without limits; download endpoint that takes a path or name from the request
(path traversal) or skips the owner check (IDOR).
**Fix**: validate by content (`mimes`/`mimetypes` + `File::types`, `file-type`, magic bytes), size limit, generated
names, storage outside the web root (`storage/app/private`, blob storage), serve through an authorized controller
with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`; strip metadata from images if needed.
**Test**: uploading `shell.php`, `x.svg` with script, a renamed `.php.jpg`, and a 50 MB file are all refused;
`../../.env` as a download name is refused; user B cannot download user A's file.

## API-specific (OWASP API Top 10 2023)

- API1 BOLA and API3 broken object property level authorization: see A01; also responses that return more
  fields than the client needs (password hash, internal flags, other users' data). Use resources/DTOs.
- API2 broken authentication: see A07; API keys in URLs; keys without scopes or IP allowlists.
- API4 unrestricted resource consumption: no pagination limits, no rate limits, unbounded file or batch sizes.
- API5 broken function level authorization: admin endpoints reachable by normal tokens.
- API6 sensitive business flows: bulk signup, coupon or OTP abuse without limits.
- API8 misconfiguration and API9 inventory: old API versions still live, undocumented debug endpoints.
- API10 unsafe consumption of APIs: third-party responses used without validation.

## Before handover: the agent's own checklist

- [ ] Every entry point listed and reviewed; every object load scoped to the user/tenant.
- [ ] Every new endpoint has auth + permission checks and a cross-user negative test.
- [ ] No raw SQL/commands built from input; all output auto-escaped; rich text sanitized.
- [ ] Uploads validated by content, stored privately, downloaded through an authorized endpoint.
- [ ] Rate limits on login, OTP, reset, signup and other abuse-prone endpoints.
- [ ] Security headers and secure cookie flags set; debug off; admin/debug tools not public.
- [ ] No High/Critical Trivy result, no `VULNERABLE_LIBRARY`; framework on a supported version.
- [ ] No secrets or PII in code, logs, responses or commits.
- [ ] Gate in `ci` mode: `RESULT: PASS`.
