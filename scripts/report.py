#!/usr/bin/env python3
"""Turn the gate's findings (plus optional local DAST and retest results) into a professional pentest report.

Writes .security/REPORT.md and a self-contained, print-ready .security/REPORT.html (A4, no external assets).
With --pdf it also prints REPORT.pdf through a locally installed Chromium or Edge in headless mode, if one is
found; otherwise it says to open REPORT.html and print it.

Every value that comes from a finding is treated as attacker-controlled text: control and bidirectional
characters are made visible, Markdown and HTML are escaped, and secret values are redacted before anything
is written. The report never claims the application is secure; it lists what ran, what did not, and the limits.

Inputs (all optional except the first, paths relative to the project root):
  .security/findings.json         written by secgate.py (--findings)
  .security/findings-before.json  the first gate run, before fixes (--before); when given, the findings table
                                  lists what was found then, and the current run is used to check retests
  .security/dast-findings.json    written by local_dast.py (--dast)
  .security/retest.json           retest outcomes per finding id (--retest), format below
  .security/artifacts.json        test users, seeded rows and files created during the test (--artifacts)

retest.json:
  {"results": [{"id": "F-01", "outcome": "Pass", "evidence": "tests/Security/OrderTest.php::test_other_user_403",
                "variant": "also tried PUT and DELETE", "note": "", "accepted_by": "", "date": ""}],
   "observations": [{"title": "...", "location": "...", "note": "..."}]}
"""
from __future__ import annotations

import argparse, datetime, hashlib, html, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run with python -I

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
OUTCOMES = ["Pass", "Fail", "Partial", "Compensating control", "Risk accepted", "Not retested"]
MAX_INPUT_BYTES = 50_000_000
MAX_FINDINGS = 2000
RAW_FINDINGS_MAX = 20_000               # entries read before the sort and the cut to MAX_FINDINGS
EVIDENCE_MIN = 8                        # shorter than this is not evidence ("x", "ok", "done")
TEXT_FIELD_MAX = 20_000                 # characters of one field the redaction patterns ever see
EXCERPT_LEN = 160

# The classes a deep review has to account for before a project is handed to the security team. The reviewer
# records each one in .security/coverage.json as examined (with evidence), not applicable (with a reason) or
# not examined (with a reason). A class that is missing from the file counts as not examined.
COVERAGE_CLASSES = [
    ("access-control", "Function-level access control (roles and permissions on every route)"),
    ("idor", "Object-level access (IDOR/BOLA), cross-user and cross-tenant"),
    ("mass-assignment", "Mass assignment and over-posting"),
    ("injection", "Injection (SQL, NoSQL, command, template, LDAP, second-order)"),
    ("xss", "Cross-site scripting (reflected, stored, DOM)"),
    ("file-handling", "File upload, download and path traversal"),
    # no "name: value" shapes in these labels: the report's own redaction reads "tokens: cookies" as a secret
    ("authentication", "Login and account recovery (password storage, reset, OTP and 2FA, lockout)"),
    ("session-tokens", "Sessions, cookies and JWT (expiry, logout)"),
    ("sso-oauth", "OAuth, OIDC, SAML and other sign-in flows"),
    ("csrf", "CSRF and state changes"),
    ("cors-redirects", "CORS and open redirects"),
    ("ssrf", "Server-side request forgery"),
    ("deserialization-xxe", "Deserialization and XML external entities"),
    ("business-logic", "Business logic, multi-step abuse and race conditions"),
    ("rate-limiting", "Rate limits and abuse protection on sensitive routes"),
    ("headers-config", "Security headers, debug mode and exposed admin or debug paths"),
    ("sensitive-data", "Secrets, personal data in logs and responses, error messages"),
    ("cryptography", "Cryptography and randomness"),
    ("components", "Vulnerable and outdated components, software supply chain"),
    ("error-handling", "Exceptional conditions (checks that fail open, swallowed errors, logging)"),
    ("api-specific", "API specifics (GraphQL, WebSockets, webhooks, pagination and limits)"),
    ("ai-agents", "AI features, agents and MCP"),
    ("mobile", "Mobile client (storage, transport, deep links, WebView)"),
    ("infrastructure", "Containers, CI and infrastructure as code in the repository"),
]
COVERAGE_STATUSES = ["examined", "not applicable", "not examined"]
READINESS = ["READY FOR PENTEST REVIEW", "CONDITIONALLY READY", "NOT READY"]

# --- sanitising -------------------------------------------------------------------------------------------

# C0/C1 controls, zero-width and bidirectional formatting characters, BOM, line/paragraph separators and the
# Unicode tag block. They are shown as [U+XXXX] so a reviewer can see something was hidden there.
INVISIBLE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069"
                       "\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]")


def visible(s) -> str:
    s = "" if s is None else str(s)
    s = s.encode("utf-8", "replace").decode("utf-8")       # a lone surrogate can not be written to a file or a console
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return INVISIBLE.sub(lambda m: f"[U+{ord(m.group(0)):04X}]", s)


# Secret patterns, in the spirit of gitleaks --redact: the value is replaced, the context stays readable.
_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]{0,30}PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]{0,30}PRIVATE KEY(?: BLOCK)?-----|$)", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b"), "[REDACTED]"),
    (re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b"), "[REDACTED]"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED]"),
    # the lookbehind, not \b: a word boundary sits after every "-", so "eyJ-eyJ-..." restarted the match at each one
    # and 200 KB of it took a minute and a half
    (re.compile(r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "[REDACTED JWT]"),
    # scheme://user:password@host keeps the user, hides the password
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,20}://[^\s:/@'\"]{0,100}:)(?!\[REDACTED\]@)[^\s@'\"]{1,200}@"), r"\1[REDACTED]@"),
    # key = "value", key: value, KEY=value for names that hold secrets
    (re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|"
                r"client[_\-]?secret|auth|bearer|credential|session[_\-]?id)[\w\-]{0,20}[\"']?\s*(?:=>|[:=])\s*)"
                # not the scheme word of "Authorization: Bearer <token>": taking it as the value hid the word and kept
                # the token, and the two patterns below that know the shape never saw it
                r"([\"'`]?)(?!(?:bearer|basic|token)\s)([^\s\"'`,;]{4,})\2"), r"\1\2[REDACTED]\2"),
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=\-]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=\-]{16,}"), r"\1[REDACTED]"),
    # 7.2 (added at the end: _STRONG below takes the first ten by position)
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{10,}"), "https://hooks.slack.com/services/[REDACTED]"),
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), "[REDACTED]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bya29\.[A-Za-z0-9_\-]{20,}"), "[REDACTED]"),
    (re.compile(r"\bpypi-[A-Za-z0-9_\-]{20,}"), "[REDACTED]"),
    (re.compile(r"(?i)\b(basic\s+)[A-Za-z0-9+/=]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(aws_secret_access_key|x-api-key|x-auth-token)(\s*[:=]\s*)[^\s\"',;]{8,}"), r"\1\2[REDACTED]"),
    # a quoted value may hold a comma, a semicolon or a space, where the unquoted pattern above stops
    (re.compile(r"(?i)((?:password|passwd|pwd|passphrase|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|"
                r"client[_\-]?secret|credential|db_pass|accountkey)[\w\-]{0,20}[\"']?\s*(?:=>|[:=])\s*)([\"'`])(?!\[REDACTED)[^\"'`\n]{4,}\2"),
     r"\1\2[REDACTED]\2"),
    (re.compile(r"\b(?:hf|dop_v1|shpat|shpss)_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    # secrets as they appear in commands and headers pasted as evidence or into a runbook
    # the value may be quoted: curl -u "admin:pw", --password 'pw', -b "PHPSESSID=..."
    (re.compile(r"(?i)((?:^|\s)(?:-u|--user)[= ]\s*[\"']?[^\s:'\"]{1,80}:)[^\s'\"]{3,}"), r"\1[REDACTED]"),
    # --password X, and -pX written together (mysql, sshpass). A separate "-p X" is left alone: it is mkdir -p build.
    (re.compile(r"((?:^|\s)(?:--password|--pass)[= ]\s*[\"']?|(?:^|\s)-p(?=[^\s=\"']))(?!\[REDACTED)[^\s'\"]{3,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:docker\s+login|sshpass|mysql|mysqldump|psql|mongosh|redis-cli|sqlcmd)\b[^\n|;&]{0,200}?\s-[pPa]\s+[\"']?)"
                r"(?!\[REDACTED)[^\s'\"]{3,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b((?:set-)?cookie\s*:\s*|(?:^|\s)(?:-b|--cookie)[= ]\s*[\"']?)[^\s;'\"=]{1,80}=[^\s;'\"]{4,}"), r"\1[REDACTED]"),
    (re.compile(r"\b([A-Z][A-Z0-9_]{0,40}(?:KEY|PASS|PASSWORD|PASSWD|SECRET|TOKEN)\s*=\s*)(?!\[REDACTED)[^\s'\"]{6,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(sig|signature|accountkey|sharedaccesskey)=[A-Za-z0-9%+/=]{16,}"), r"\1=[REDACTED]"),
]


def redact(s) -> str:
    s = "" if s is None else str(s)
    for rx, repl in _SECRET_PATTERNS:
        s = rx.sub(repl, s)
    return s


# For deciding that text CONTAINS a secret (lint, PR diffs) only the high-confidence patterns count, plus a
# quoted literal assigned to a secret-looking name. The broad key=value redaction above would flag ordinary code
# such as `password = request.form["password"]`, which is fine for redaction but not for blocking.
_STRONG = _SECRET_PATTERNS[:10] + [
    (re.compile(r"(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|client[_\-]?secret)[\w\-]{0,20}"
                r"[\"']?\s*(?:=>|[:=])\s*[\"'`](?!\[REDACTED)(?![\w\-]*(?:example|changeme|placeholder|your[_\-]|xxx|\*\*\*))"
                r"[^\s\"'`]{8,}[\"'`]"), ""),
]


def has_secret(s) -> bool:
    s = "" if s is None else str(s)
    return any(rx.search(s) for rx, _ in _STRONG)


def clean(s, limit: int | None = None) -> str:
    """Redact, make invisible characters visible and cut to length. Not yet escaped for any output format."""
    s = "" if s is None else str(s)
    s = visible(redact(s[:TEXT_FIELD_MAX])).strip()        # cut before the patterns run, never after
    if has_secret(s):                   # the redaction missed a shape the detector knows: show nothing of it
        s = "[withheld: looked like a secret]"
    if limit and len(s) > limit:
        s = s[:limit].rstrip() + "..."
    return s


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~>])")


def md(s, limit: int | None = None) -> str:
    """Safe text for a Markdown table cell or paragraph: no pipes, no links, no raw HTML, no headings."""
    s = clean(s, limit)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = _MD_SPECIAL.sub(r"\\\1", s)
    s = re.sub(r"^(\s*)([-=]{3,})", r"\1\\\2", s)
    return s or "-"


def h(s, limit: int | None = None) -> str:
    return html.escape(clean(s, limit), quote=True) or "-"


# --- loading -----------------------------------------------------------------------------------------------

def load_json(path: Path | None, default):
    if not path:
        return default
    try:
        if not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
            return default
        return decode_json(path.read_bytes())
    except (OSError, ValueError, RecursionError, OverflowError, MemoryError):
        return default


def unusable(path: Path | None, need_list: str | None = None) -> bool:
    """True when a result file is there but can not be used: not JSON, not an object, or without the list it must
    hold. A file like that is never "no findings": the report says it could not be read and is not ready."""
    if not path:
        return False
    try:
        if not os.path.lexists(path):
            return False
    except OSError:
        return True
    v = load_json(path, None)
    if not isinstance(v, dict):
        return True
    if need_list is not None and need_list.endswith("?"):       # optional key: when it is there it must be a list
        return need_list[:-1] in v and not isinstance(v[need_list[:-1]], list)
    return need_list is not None and not isinstance(v.get(need_list), list)


SEV_WORDS = {"ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM", "MODERATE": "MEDIUM", "NOTE": "LOW", "MINOR": "LOW",
             "INFORMATIONAL": "INFO", "INFORMATION": "INFO", "NONE": "INFO", "UNKNOWN": "MEDIUM"}


def decode_json(raw: bytes):
    """Result files as tools and editors really save them: UTF-8 with or without a byte order mark, or UTF-16."""
    def once(pairs):                    # {"findings": [<High>], "findings": []} must not read as "no findings"
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("a key is repeated")
        return dict(pairs)
    return json.loads(decode_text(raw), object_pairs_hook=once)


def decode_text(raw: bytes) -> str:
    return raw.decode("utf-16", "replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", "replace")


def odd_entries(data, key: str = "findings") -> int:
    """How many entries of a findings or results list are not objects. One line of text where a finding should be
    ("R-03: HIGH IDOR in /api/admin") was dropped without a word."""
    v = data.get(key) if isinstance(data, dict) else None
    return sum(1 for x in v[:RAW_FINDINGS_MAX] if not isinstance(x, dict)) if isinstance(v, list) else 0


def norm_finding(f, unknown_sev: str = "HIGH") -> dict | None:
    if not isinstance(f, dict):
        return None
    sev = f.get("severity")
    sev = sev.strip().upper() if isinstance(sev, str) else ""
    if sev not in SEV_ORDER:
        m = re.match(r"(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", sev)        # "High (Medium)" from a DAST tool is High
        # other tools' words for the same levels; anything else (no label, a number, "BLOCKER") is taken as HIGH.
        # Reading it as informational let an open finding with a label this report did not know pass as nothing.
        sev = m.group(1) if m else SEV_WORDS.get(sev, "HIGH")
    try:
        line = int(f.get("line") or 0)
    except (TypeError, ValueError, OverflowError):
        line = 0
    line = line if 0 <= line < 10_000_000 else 0
    return {"rule": str(f.get("rule") or "UNKNOWN")[:200], "severity": sev, "file": str(f.get("file") or "")[:500],
            "line": max(0, line), "message": str(f.get("message") or "")[:4000], "code": str(f.get("code") or "")[:2000],
            "engine": str(f.get("engine") or "")[:60], "cia": f.get("cia"), "url": str(f.get("url") or "")[:500],
            "solution": str(f.get("solution") or "")[:2000], "cwe": str(f.get("cwe") or "")[:20]}


def findings_of(report) -> list[dict]:
    """The findings of a gate or DAST result, most severe first, at most MAX_FINDINGS. The cut is made after the
    sort: cutting first let two thousand informational entries push a critical one out of the report."""
    raw = report.get("findings", []) if isinstance(report, dict) else []
    out = [n for n in (norm_finding(f) for f in (raw if isinstance(raw, list) else [])[:RAW_FINDINGS_MAX]) if n]
    out.sort(key=lambda f: SEV_ORDER.index(f["severity"]))
    return out[:MAX_FINDINGS]


def raw_count(report) -> int:
    raw = report.get("findings", []) if isinstance(report, dict) else []
    return len(raw) if isinstance(raw, list) else 0


def rel_path(p: str, root: Path) -> str:
    """The path as the report shows it, relative to the project when it is inside it. String work only: the path
    comes from a result file, and resolving it would touch the file system (and for \\\\host\\share the network)."""
    if not p:
        return ""
    try:
        base = os.path.normcase(os.path.normpath(str(root)))
        full = os.path.normpath(p if os.path.isabs(p) else os.path.join(str(root), p))
        if os.path.normcase(full).startswith(base + os.sep):
            return full[len(base) + 1:].replace("\\", "/")
    except (ValueError, TypeError):
        pass
    return p.replace("\\", "/")


def fingerprint(f: dict, root: Path) -> str:
    """Stable across line shifts: rule, file and the normalised code line (or the URL for DAST)."""
    code = re.sub(r"\s+", " ", f.get("code") or "").strip()
    basis = "|".join([f["rule"], rel_path(f["file"], root), code or f.get("url") or str(f["line"])])
    if f.get("engine") == "review":     # a reviewer's title and evidence are free text: the line tells two findings apart
        basis += f"|{f['line']}|{f.get('url') or ''}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:12]


def assign_ids(findings: list[dict], prefix: str, root: Path) -> list[dict]:
    ordered = sorted(findings, key=lambda f: (SEV_ORDER.index(f["severity"]), rel_path(f["file"], root), f["line"], f["rule"]))
    for i, f in enumerate(ordered, 1):
        f["id"] = f"{prefix}-{i:02d}"
        f["fp"] = fingerprint(f, root)
    return ordered


# --- classification ----------------------------------------------------------------------------------------

# (keyword in rule or message, class, CIA, root-cause fix). First match wins; checked against the rule id first.
CLASSES = [
    (r"hidden_unicode|instruction_injection|mcp|agent", "agent", "C,I",
     "Remove the hidden text or unsafe agent setting and review the file like code."),
    (r"secret|credential|private_key|api_key|aws_access|live_api|token|password|gitleaks|generic-api-key", "leak", "C",
     "Remove the secret from the code and history, rotate it now, and load it from the server's secret store or environment."),
    (r"idor|bola|authz|authori[sz]|access.?control|unscoped|without.?auth|missing.?auth|role", "access", "C,I",
     "Load the object through a query scoped to the signed-in user or tenant and check the policy on the server for every verb."),
    (r"mass.?assign|over.?post|request->all|fillable", "access", "I",
     "Bind only an explicit allowlist of fields; never pass the whole request body to the model."),
    (r"sql|nosql|injection|command|shell|exec|ssti|template.?inj|deserial|pickle|unserialize|xxe", "inject", "C,I,A",
     "Use parameterised queries or argument arrays (no shell), fixed templates and safe parsers, so input is never treated as code."),
    (r"xss|innerhtml|raw_html|raw_template|v-html|cross.?site.?script|document\.write", "inject", "C,I",
     "Encode output for its context with the framework's auto-escaping; render user content as text, never as HTML."),
    (r"path.?trav|traversal|lfi|file.?inclusion", "inject", "C,I",
     "Resolve the path, confine it to the allowed folder (realpath check, no links), and map user input to ids, not paths."),
    (r"ssrf|server.?side.?request", "inject", "C,I",
     "Fetch only allowlisted hosts after resolving and pinning the address; block private, link-local and metadata ranges."),
    (r"open.?redirect|redirect", "redirect", "I",
     "Redirect only to relative paths or an allowlist of hosts."),
    (r"csrf|state_change_over_get|samesite", "access", "I",
     "Use POST/PUT/DELETE with the framework's CSRF token for every state change."),
    (r"throttle|rate.?limit|brute", "throttle", "C,A",
     "Add a server-side rate limit and lockout to the route (per account and per IP)."),
    (r"debug|stack.?trace|verbose|error.?disclos|information.?disclos|x-powered-by|server.?leak|version.?disclos|sourcemap|sensitive_log",
     "leak", "C", "Turn debug output off in production, return generic errors, and keep details in server logs only."),
    (r"cors", "leak", "C", "Allow only the exact trusted origins; never reflect the Origin header with credentials."),
    (r"crypto|md5|sha1|random|weak.?hash|cipher", "crypto", "C,I",
     "Use a vetted algorithm (bcrypt/argon2 for passwords, a CSPRNG for tokens, AES-GCM for data)."),
    (r"tls|ssl|verify|certificate", "crypto", "C,I", "Keep certificate verification on and use TLS 1.2 or later only."),
    (r"cookie", "session", "C,I", "Set Secure, HttpOnly and SameSite on session and auth cookies."),
    (r"header|csp|hsts|frame|content-type-options|clickjack|anti-clickjacking", "config", "C,I",
     "Send the security headers (CSP, HSTS, frame-ancestors, nosniff, Referrer-Policy) from one middleware for every response."),
    (r"vulnerable_library|cve-|outdated|end.?of.?life|trivy", "component", "C,I,A",
     "Upgrade the component to a supported, fixed version; do not suppress the finding."),
    (r"redos|regex|dos|resource", "dos", "A", "Bound input size and use linear-time matching or a timeout."),
    (r"test_failure", "quality", "I", "Fix the failing test or build before handover."),
]


# ZAP and other DAST alerts carry a CWE; it is a better guide than the alert's wording.
CWE_CLASS = {"79": "xss", "89": "sql", "78": "command", "94": "sql", "352": "csrf", "601": "open_redirect",
             "22": "path_traversal", "918": "ssrf", "200": "information_disclosure", "209": "error_disclosure",
             "497": "information_disclosure", "215": "debug", "540": "information_disclosure", "615": "information_disclosure",
             "614": "cookie", "1004": "cookie", "1275": "cookie", "319": "tls", "693": "header", "1021": "header",
             "16": "header", "525": "header", "345": "header", "829": "vulnerable_library", "1104": "vulnerable_library",
             "284": "access_control", "285": "authz", "639": "idor", "287": "authz", "798": "credential"}


def classify(f: dict) -> tuple[str, str, str]:
    rule = f["rule"].lower()
    cwe = re.sub(r"\D", "", f.get("cwe") or "")
    if cwe in CWE_CLASS:
        rule = CWE_CLASS[cwe]
    for rx, cls, cia, fix in CLASSES:
        if re.search(rx, rule):
            return cls, cia, fix
    text = (f["message"] or "").lower()
    for rx, cls, cia, fix in CLASSES:
        if re.search(rx, text):
            return cls, cia, fix
    return "other", "C,I", "Fix the root cause described in the finding, then add a test that fails without the fix."


def cia_of(f: dict) -> str:
    v = f.get("cia")
    if isinstance(v, str) and re.fullmatch(r"[CIA](,[CIA]){0,2}", v.strip().upper()):
        return v.strip().upper()
    return classify(f)[1]


def is_secret_finding(f: dict) -> bool:
    return f["engine"] == "gitleaks" or classify(f)[0] == "leak" and re.search(
        r"secret|credential|key|token|password|gitleaks", f["rule"].lower()) is not None


def title_of(f: dict) -> str:
    rule = f["rule"]
    name = rule.split(".")[-1] if rule.count(".") >= 2 else rule      # semgrep ids are long dotted paths
    name = re.sub(r"[_\-]+", " ", name).strip()
    first = re.split(r"(?<=[.!?])\s", (f["message"] or "").strip(), maxsplit=1)[0]
    if f["engine"] == "zap" and first:
        return first.rstrip(".")
    return name.capitalize() if name.isupper() else name


def location_of(f: dict, root: Path) -> str:
    if f.get("url") and f.get("engine") != "review":
        return f["url"]
    p = rel_path(f["file"], root)
    if f.get("engine") == "review":             # a review finding names the code and, when known, the route
        place = f"{p}:{f['line']}" if p and f["line"] else p
        return " ".join(x for x in (place, f"({f['url']})" if f.get("url") else "") if x) or "(project)"
    return f"{p}:{f['line']}" if p and f["line"] else (p or "(project)")


def evidence_of(f: dict) -> str:
    if is_secret_finding(f):
        return "[excerpt withheld: secret finding, see the scanner report on the developer's machine]"
    return f["code"] or ""


def route_key(f: dict, root: Path) -> str:
    """The place two findings must share to be chained: the URL path for DAST, otherwise the file."""
    if f.get("url") and f.get("engine") != "review":
        m = re.match(r"(?i)^[a-z]+://[^/]+(/[^?#]*)?", f["url"])
        return "route:" + ((m.group(1) if m else "") or "/").rstrip("/").lower()
    return "file:" + rel_path(f["file"], root).lower()


# --- retest ------------------------------------------------------------------------------------------------

def apply_retests(found: list[dict], retest, current_fps: set[str] | None, stable_ids: bool = True) -> tuple[list[dict], list[str]]:
    """Attach an outcome label to every finding. Returns the observations and a list of report notes."""
    notes: list[str] = []
    results = retest.get("results", []) if isinstance(retest, dict) else []
    by_id, by_fp = {}, {}
    for r in (results if isinstance(results, list) else [])[:RAW_FINDINGS_MAX]:
        if isinstance(r, dict):
            if isinstance(r.get("id"), str) and r["id"]:
                by_id[r["id"]] = r
            if isinstance(r.get("fingerprint"), str) and r["fingerprint"]:
                by_fp[r["fingerprint"]] = r
    shared = {}
    for f in found:
        shared[f["fp"]] = shared.get(f["fp"], 0) + 1
    for f in found:
        # An id is a position in a sorted list, so it is trusted only where it can not move: not for a finding that
        # appeared after the first run or whose id the report made up, and not when the entry names another
        # fingerprint. A fingerprint that two findings share closes neither: one Pass must not close two findings.
        # A DAST id moves too: there is one DAST file, and a rerun after a fix renumbers what is left, which gave the
        # next finding the Pass of the fixed one.
        # And with no first-run file every scanner id is a position in the latest run: an acceptance written for F-01
        # passed to whatever became F-01 next.
        by_print = bool(f.get("auto_id") or f.get("late") or f["id"].startswith("D-") or (not stable_ids and f["id"].startswith("F-")))
        r = None if by_print else by_id.get(f["id"])
        if r is not None and isinstance(r.get("fingerprint"), str) and r["fingerprint"] and r["fingerprint"] != f["fp"]:
            r = None
        if r is None and shared[f["fp"]] == 1:
            r = by_fp.get(f["fp"])
        if r is None and by_print and f["id"] in by_id and by_id[f["id"]].get("fingerprint") != f["fp"]:
            # say so, or an honest entry is ignored without a word and the project stays NOT READY for no visible reason
            notes.append(f"{f['id']}: the retest entry was not used. This finding is matched by its fingerprint, because "
                         f"its number can change between runs: add \"fingerprint\": \"{f['fp']}\" to the entry")
        r = r or {}
        if shared[f["fp"]] > 1 and r.get("fingerprint") == f["fp"] and r.get("id") != f["id"]:
            r = {}
        if not r and by_print and shared[f["fp"]] > 1 and (f["fp"] in by_fp or f["id"] in by_id):
            notes.append(f"{f['id']}: the retest entry was not used. {shared[f['fp']]} findings share this fingerprint "
                         "(same rule, file and code), so one entry can not say which one it means; fix them together "
                         "or tell them apart in the code")
        outcome = str(r.get("outcome") or "Not retested").strip()[:60]
        match = next((o for o in OUTCOMES if o.lower() == outcome.lower()), None)
        evidence = r.get("evidence")
        evidence = evidence.strip()[:2000] if isinstance(evidence, str) else ""

        def short(k, n=2000):           # every field is cut on the way in: a 20 MB note cost half a minute later
            v = r.get(k)
            return v[:n] if isinstance(v, str) else ""
        f["retest"] = {"outcome": match or "Not retested", "evidence": evidence, "variant": short("variant"),
                       "note": short("note"), "accepted_by": " ".join(short("accepted_by", 200).split()),
                       "date": short("date", 20).strip()}
        rt = f["retest"]
        if match is None and r:
            rt["note"] = f"unknown outcome label '{outcome}' ignored. " + rt["note"]
            notes.append(f"{f['id']}: unknown outcome label replaced with Not retested")
        if rt["outcome"] == "Pass" and len(evidence) < EVIDENCE_MIN:
            rt["outcome"] = "Not retested"
            rt["note"] = "a Pass needs evidence (the test or command that reached the sink and was refused). " + rt["note"]
            notes.append(f"{f['id']}: Pass without evidence was recorded as Not retested")
        if rt["outcome"] in ("Risk accepted", "Compensating control") and \
                not (rt["accepted_by"].strip() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", rt["date"])):
            what = rt["outcome"]
            rt["outcome"] = "Not retested"
            rt["note"] = f"{what} needs a named person and a date (YYYY-MM-DD). " + rt["note"]
            notes.append(f"{f['id']}: {what} without a name and date was recorded as Not retested")
        if rt["outcome"] == "Compensating control" and len(evidence) < EVIDENCE_MIN:
            rt["outcome"] = "Not retested"
            rt["note"] = "a compensating control needs evidence (where the control is and the test that shows it works). " + rt["note"]
            notes.append(f"{f['id']}: Compensating control without evidence was recorded as Not retested")
        if rt["outcome"] == "Pass" and current_fps is not None and f["fp"] in current_fps:
            rt["outcome"] = "Fail"
            rt["note"] = "the latest gate run still reports the same construction at this place. " + rt["note"]
            notes.append(f"{f['id']}: marked Pass but still reported by the latest gate run, recorded as Fail")
    obs = retest.get("observations", []) if isinstance(retest, dict) else []
    return [o for o in (obs if isinstance(obs, list) else []) if isinstance(o, dict)][:200], notes


# --- attack chains -----------------------------------------------------------------------------------------

CHAIN_PAIRS = {
    ("leak", "access"): "information it exposes can help an attacker reach objects or actions that the access check misses",
    ("leak", "inject"): "information it exposes (versions, paths, errors, keys) makes the injection easier to aim",
    ("access", "inject"): "an attacker who can reach the route without the right permission can then feed it the injected input",
    ("throttle", "access"): "with no rate limit, guessing ids, codes or passwords on this route is cheap",
    ("throttle", "leak"): "with no rate limit, exposed details can be collected at scale",
    ("session", "inject"): "cookies without HttpOnly make script injection lead straight to session theft",
    ("crypto", "access"): "predictable tokens or weak hashes make the access check easier to get past",
    ("redirect", "leak"): "an open redirect on the same route can send exposed tokens or users to an attacker's site",
}


def bump(sev: str) -> str:
    i = SEV_ORDER.index(sev)
    return SEV_ORDER[max(0, i - 1)] if sev in ("HIGH", "MEDIUM", "LOW") else sev


def attack_chains(found: list[dict], root: Path) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for f in found:
        if f["severity"] == "INFO" or f["retest"]["outcome"] == "Pass":
            continue
        groups.setdefault(route_key(f, root), []).append(f)
    chains = []
    for key, items in groups.items():
        by_cls: dict[str, dict] = {}
        for f in items:
            by_cls.setdefault(classify(f)[0], f)
        for (a, b), why in CHAIN_PAIRS.items():
            if a in by_cls and b in by_cls:
                fa, fb = by_cls[a], by_cls[b]
                worst = min(fa["severity"], fb["severity"], key=SEV_ORDER.index)
                chains.append({"ids": [fa["id"], fb["id"]], "place": key.split(":", 1)[1] or "/", "severity": bump(worst),
                               "path": f"{fa['id']} then {fb['id']}: {why}."})
    return chains


# --- verdict -----------------------------------------------------------------------------------------------

OPEN_OUTCOMES = {"Fail", "Partial", "Not retested"}


def verdict(found: list[dict], tool_status: dict, dast: dict) -> tuple[str, str]:
    required = [t for t in ("semgrep", "trivy", "gitleaks") if t in tool_status]
    missing = [t for t in required if not tool_status.get(t)]
    errors = tool_status.get("errors") or {}
    if errors or missing or not required:
        why = "the scan is incomplete: " + (", ".join(f"{t} did not run" for t in missing) or
                                           ("scanner errors" if errors else "no scanner status was recorded"))
        return "BLOCKED", why
    open_hi = [f for f in found if f["severity"] in ("CRITICAL", "HIGH") and f["retest"]["outcome"] in OPEN_OUTCOMES]
    if open_hi:
        return "FAILED", f"{len(open_hi)} critical or high finding(s) are still open"
    return "PASSED", "no critical or high finding is open in what was tested"


def review_findings_of(data, root: Path) -> list[dict]:
    """Findings the reviewer found by reading the code (.security/review-findings.json). They get R- ids, take part
    in the retest and count for the verdict like any scanner finding. An id the reviewer chose (R-01) is kept when
    it is well formed and not used twice, so retest.json can name it before the report exists."""
    raw = data.get("findings", []) if isinstance(data, dict) else []
    out, used = [], set()
    for item in (raw if isinstance(raw, list) else [])[:RAW_FINDINGS_MAX]:
        if not isinstance(item, dict):
            continue
        d = dict(item)
        cls = str(d.get("class") or "").strip()[:60]
        title = str(d.get("title") or "").strip()[:160]
        d["rule"] = "REVIEW " + (title or cls or "finding")
        d["code"] = d.get("code") or d.get("evidence") or ""
        d["url"] = d.get("url") or d.get("route") or ""
        d["engine"] = "review"
        if not d.get("message"):
            d["message"] = title
        n = norm_finding(d, "HIGH")
        if not n:
            continue
        n["cls"] = cls
        rid = str(item.get("id") or "").strip()
        n["want_id"] = rid if re.fullmatch(r"R-\d{2,4}", rid) and rid not in used else ""
        used.add(n["want_id"])
        out.append(n)
    ordered = sorted(out, key=lambda f: (SEV_ORDER.index(f["severity"]), rel_path(f["file"], root), f["line"], f["rule"]))[:MAX_FINDINGS]
    taken = {f["want_id"] for f in ordered if f["want_id"]}
    i = 0
    for f in ordered:
        if f["want_id"]:
            f["id"] = f["want_id"]
        else:
            i += 1
            while f"R-{i:02d}" in taken:
                i += 1
            f["id"] = f"R-{i:02d}"
            taken.add(f["id"])
            f["auto_id"] = True         # a number the report made up: a retest must name it by fingerprint, not by a guess
        f["fp"] = fingerprint(f, root)
    return ordered


def coverage_of(data) -> dict:
    """The coverage table: one row per class in COVERAGE_CLASSES. A status the file does not give, an unknown
    status, "examined" with no evidence, or "not applicable" with no reason is recorded as not examined."""
    classes = data.get("classes") if isinstance(data, dict) else None
    classes = classes if isinstance(classes, dict) else {}
    rows = []
    for key, label in COVERAGE_CLASSES:
        c = classes.get(key)
        c = c if isinstance(c, dict) else {}
        def text(v):                    # only a real string counts: 1, true or a list is not evidence
            return v.strip()[:600] if isinstance(v, str) else ""
        status = c.get("status")
        status = status.strip().lower() if isinstance(status, str) else ""
        evidence, reason = text(c.get("evidence")), text(c.get("reason"))
        note = ""
        if status not in COVERAGE_STATUSES:
            note = "no valid status recorded" if c else "not recorded"
            status = "not examined"
        elif status == "examined" and len(evidence) < EVIDENCE_MIN:
            status, note = "not examined", "examined needs evidence (file:line, a test or a request)"
        elif status == "not applicable" and len(reason) < EVIDENCE_MIN:
            status, note = "not examined", "not applicable needs a reason"
        rows.append({"key": key, "label": label, "status": status, "evidence": evidence if status == "examined" else "",
                     "reason": note or reason})
    surface = data.get("surface") if isinstance(data, dict) and isinstance(data.get("surface"), dict) else {}

    def num(v):
        return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10_000_000 else None
    found, reviewed = num(surface.get("entry_points_found")), num(surface.get("entry_points_reviewed"))
    # a number that is there but is not a plain count ("all", 3.0, -1) is a blocker, not a missing detail
    bad = [k for k in ("entry_points_found", "entry_points_reviewed") if k in surface and num(surface.get(k)) is None]
    return {"recorded": isinstance(data, dict) and bool(classes), "rows": rows, "found": found, "reviewed": reviewed,
            "bad_surface": bad, "open": [r["label"] for r in rows if r["status"] == "not examined"]}


def readiness(v: str, found: list[dict], cov: dict, dast: dict, has_matrix: bool, retested: bool,
              truncated: int = 0) -> tuple[str, list[str]]:
    """Whether the project can go to the security team for review. The gate verdict says what the scanners saw;
    this adds what a pentester asks next: was every class looked at, is every finding closed with proof, and what
    was left to a person's decision. It is a statement about the review, not about the application."""
    blockers, conditions = [], []
    if v != "PASSED":
        blockers.append(f"the gate verdict is {v}")
    if not cov["recorded"]:
        blockers.append("no review coverage was recorded (.security/coverage.json)")
    elif cov["open"]:
        blockers.append(f"{len(cov['open'])} review class(es) were not examined")
    if cov.get("bad_surface"):
        blockers.append("the entry point counts in coverage.json are not plain numbers")
    elif cov["found"] is not None and cov["reviewed"] is None:
        blockers.append(f"{cov['found']} entry points were found but the number reviewed was not recorded")
    elif cov["found"] is not None and cov["reviewed"] < cov["found"]:
        blockers.append(f"only {cov['reviewed']} of {cov['found']} entry points were reviewed")
    elif cov["found"] == 0 and cov["recorded"]:
        blockers.append("coverage.json says the project has no entry points")
    if truncated:
        blockers.append(f"{truncated} finding(s) did not fit in the report; it lists the most severe {MAX_FINDINGS}")
    open_med = [f for f in found if f["severity"] == "MEDIUM" and f["retest"]["outcome"] in OPEN_OUTCOMES]
    if open_med:
        blockers.append(f"{len(open_med)} medium finding(s) are open with no fix, accepted risk or compensating control")
    if found and not retested:
        blockers.append("findings were reported but no retest was recorded")
    held_hi = [f for f in found if f["severity"] in ("CRITICAL", "HIGH") and
               f["retest"]["outcome"] in ("Risk accepted", "Compensating control")]
    if held_hi:
        blockers.append(f"{len(held_hi)} critical or high finding(s) were not fixed but accepted or covered by a "
                        "compensating control; that decision belongs to the security team")
    open_low = [f for f in found if f["severity"] in ("LOW", "INFO") and f["retest"]["outcome"] in OPEN_OUTCOMES]
    if open_low:
        conditions.append(f"{len(open_low)} low or informational finding(s) are open")
    held = [f for f in found if f["retest"]["outcome"] in ("Risk accepted", "Compensating control", "Partial")
            and f not in held_hi]
    if held:
        conditions.append(f"{len(held)} finding(s) rest on an accepted risk, a compensating control or a partial fix "
                          "that the security team has to confirm")
    if dast.get("status") != "ran":
        conditions.append("no scan of the running application was made")
    if not has_matrix:
        conditions.append("no authorization matrix was written (.security/authz-matrix.md)")
    if cov["recorded"] and cov["found"] is None:
        conditions.append("the number of entry points found and reviewed was not recorded")
    if blockers:
        return "NOT READY", blockers + conditions
    if conditions:
        return "CONDITIONALLY READY", conditions
    return "READY FOR PENTEST REVIEW", ["every class was examined or marked not applicable, and no finding is open"]


def overall_risk(found: list[dict]) -> str:
    live = [f["severity"] for f in found if f["retest"]["outcome"] in OPEN_OUTCOMES]
    return min(live, key=SEV_ORDER.index) if live else "LOW"


# --- building the report model -----------------------------------------------------------------------------

def build(root: Path, findings_path: Path, before_path: Path | None, dast_path: Path | None,
          retest_path: Path | None, artifacts_path: Path | None, review_path: Path | None = None,
          coverage_path: Path | None = None) -> dict:
    current = load_json(findings_path, None)
    before = load_json(before_path, None) if before_path else None
    base = before if isinstance(before, dict) else current
    if not isinstance(base, dict):
        base = {"mode": "unknown", "tool_status": {}, "findings": []}
    # Whether the scan was complete is a fact about the latest gate run, never about an older copy of it.
    # If the latest run can not be read there is no latest run: no scanner status, so the verdict is BLOCKED.
    tool_status = current.get("tool_status") if isinstance(current, dict) and isinstance(current.get("tool_status"), dict) else {}
    if not isinstance(tool_status.get("errors"), dict) and tool_status.get("errors"):
        tool_status = dict(tool_status, errors={"scan": visible(str(tool_status["errors"]))[:200]})
    if not isinstance(tool_status.get("notes"), list):
        tool_status = dict(tool_status, notes=[])
    # A DAST file that says a scan ran must hold its list of findings under the one name local_dast.py writes; under
    # "alerts" or "Findings" a High in it was read as nothing.
    d0 = load_json(dast_path, None) if dast_path else None
    dast_need = "findings" if isinstance(d0, dict) and d0.get("status") == "ran" else "findings?"
    unread = [n for n, pth, need in (("findings.json", findings_path, "findings"), ("findings-before.json", before_path, "findings"),
                                     ("dast-findings.json", dast_path, dast_need), ("review-findings.json", review_path, "findings"),
                                     ("coverage.json", coverage_path, None), ("retest.json", retest_path, "results?")) if unusable(pth, need)]
    found = assign_ids(findings_of(base), "F", root)
    late: list[str] = []
    raised: list[str] = []
    if isinstance(before, dict) and isinstance(current, dict):
        # A finding of the latest run that the first run did not list is a finding like any other, and open. Listing it
        # only as an observation let an emptied or forged findings-before.json hide everything the scanners report now.
        known = {f["fp"] for f in found}
        now_all = findings_of(current)
        # The same line can be rated higher by the latest run (other context, another rule set). The fingerprint has no
        # severity in it, so the first run's lower rating used to stand and a Critical was listed as Low.
        worst = {}
        for f in now_all:
            fp = fingerprint(f, root)
            if fp not in worst or SEV_ORDER.index(f["severity"]) < SEV_ORDER.index(worst[fp]):
                worst[fp] = f["severity"]
        for f in found:
            if f["fp"] in worst and SEV_ORDER.index(worst[f["fp"]]) < SEV_ORDER.index(f["severity"]):
                raised.append(f"{f['id']}: rated {f['severity']} in the first run and {worst[f['fp']]} in the latest; the higher one is used")
                f["severity"] = worst[f["fp"]]
        extra = [f for f in now_all if fingerprint(f, root) not in known]
        for i, f in enumerate(assign_ids(extra, "F", root)[:MAX_FINDINGS], len(found) + 1):
            f["id"] = f"F-{i:02d}"
            f["late"] = True
            late.append(f["id"])
        found += [f for f in extra if f.get("id") in late]
    dast = load_json(dast_path, {}) if dast_path else {}
    dast = dast if isinstance(dast, dict) else {}
    dfound = assign_ids(findings_of(dast), "D", root)
    review_data = load_json(review_path, {}) if review_path else {}
    rfound = review_findings_of(review_data, root)
    allf = found + dfound + rfound
    truncated = sum(max(0, raw_count(x) - MAX_FINDINGS) for x in (base, dast, review_data)) + \
        (max(0, raw_count(current) - MAX_FINDINGS) if current is not base else 0)
    # A Pass is always checked against the latest gate run, with or without a findings-before.json.
    current_fps = {fingerprint(f, root) for f in findings_of(current)} if isinstance(current, dict) else None
    retest = load_json(retest_path, {}) if retest_path else {}
    observations, notes = apply_retests(allf, retest, current_fps, stable_ids=isinstance(before, dict))
    if late:
        notes.append(f"{', '.join(late[:20])}{' and more' if len(late) > 20 else ''}: reported by the latest gate run "
                     "but not in the first one")
    notes += raised[:50]
    for name, data in (("findings.json", current), ("findings-before.json", before), ("dast-findings.json", dast),
                       ("review-findings.json", review_data), ("retest.json", retest)):
        n = odd_entries(data, "results" if name == "retest.json" else "findings")
        if n and name not in unread:
            unread.append(name)
            notes.append(f"{name} holds {n} entr{'y' if n == 1 else 'ies'} that are not objects (a line of text where a "
                         "finding should be); nothing may be left out, so the file counts as unreadable")
    artifacts = load_json(artifacts_path, []) if artifacts_path else []
    if isinstance(artifacts, dict):
        artifacts = artifacts.get("artifacts", [])
    artifacts = [a for a in (artifacts if isinstance(artifacts, list) else []) if isinstance(a, dict)][:200]
    v, why = verdict(allf, tool_status, dast)
    if unread and v == "PASSED":
        v, why = "BLOCKED", "result files could not be read: " + ", ".join(unread)
    for n in unread:
        notes.append(f"{n} is there but could not be read as the JSON it must hold (save it as UTF-8, an object); "
                     "nothing in it was used")
    cov = coverage_of(load_json(coverage_path, None) if coverage_path else None)
    matrix = root / ".security" / "authz-matrix.md"
    try:
        mst = os.lstat(matrix)
        has_matrix = os.path.isfile(matrix) and not matrix.is_symlink() and not (getattr(mst, "st_file_attributes", 0) & 0x400) \
            and mst.st_size > 40
    except OSError:
        has_matrix = False
    # "ran" with no target is a label, not a scan
    scanned = dict(dast) if dast.get("status") == "ran" and isinstance(dast.get("target"), str) and dast["target"].strip() else {}
    results = retest.get("results") if isinstance(retest, dict) else None
    ready, ready_why = readiness(v, allf, cov, scanned, has_matrix, isinstance(results, list) and bool(results), truncated)
    # Coverage and readiness are opt-in: they are shown only when a team keeps a .security/coverage.json. By default
    # the agent writes no such file (it costs tokens on every test) and the report is the plain one, made by this script.
    return {"coverage": cov, "coverage_on": bool(coverage_path), "readiness": ready, "readiness_why": ready_why,
            "root": root, "date": datetime.date.today().isoformat(), "mode": str(base.get("mode", "unknown")),
            "tool_status": tool_status, "findings": allf, "dast": dast, "observations": observations,
            "notes": notes, "artifacts": artifacts, "chains": attack_chains(allf, root), "verdict": v, "why": why,
            "risk": overall_risk(allf), "retested": bool(retest), "project": root.name,
            "outputs": sorted(p.name for p in (root / ".security").glob("*") if p.is_file()) if (root / ".security").is_dir() else []}


def counts(findings: list[dict]) -> dict:
    return {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}


def tools_table(m: dict) -> list[tuple[str, str, str]]:
    """(tool, ran / did not run, detail) rows."""
    ts = m["tool_status"]; rows = []
    for t in ("semgrep", "trivy", "gitleaks"):
        if t in ts:
            err = (ts.get("errors") or {}).get(t)
            rows.append((t, "ran" if ts.get(t) else "did not run", err or ("completed" if ts.get(t) else "not installed or failed")))
        else:
            rows.append((t, "did not run", "not part of this gate mode"))
    rows.append(("built-in checks (heuristics, library, config, agent config)", "ran", f"gate mode {m['mode']}"))
    tests = ts.get("project_tests")
    if isinstance(tests, list) and tests:
        for t in tests[:20]:
            if isinstance(t, dict):
                rows.append(("project tests", "ran", f"{t.get('command', '')} (exit {t.get('exit', '?')})"))
    else:
        rows.append(("project tests", "did not run", "the gate was not run with --run-tests, or no test command was found"))
    d = m["dast"]
    if d.get("status") == "ran":
        rows.append(("OWASP ZAP (local DAST)", "ran", f"{d.get('scan', 'baseline')} scan of {d.get('target', '')} via {d.get('tool', '')}"))
    else:
        rows.append(("OWASP ZAP (local DAST)", "did not run", d.get("note") or "not requested"))
    for n in (ts.get("notes") or [])[:30]:
        rows.append(("note", "-", str(n)))
    return rows


LIMITS = [
    "This is an automated review of source code, dependencies and (when it ran) a passive scan of the running app. "
    "It is not a full manual penetration test and does not prove the absence of vulnerabilities.",
    "Business logic, multi-step abuse, race conditions and most access-control bugs need the entry-point review and "
    "the negative tests in the authorization matrix; scanners alone miss them.",
    "Server and infrastructure settings outside the repository (TLS ciphers, open ports, WAF, cloud IAM) were not tested.",
    "Attack chains are suggested by a simple heuristic (two finding types at the same file or route) and need a "
    "person to confirm them.",
    "A retest covers only the findings listed in this report. Anything new found during the retest is listed under "
    "observations and was not retested.",
]

# --- Markdown ----------------------------------------------------------------------------------------------


def render_md(m: dict) -> str:
    root = m["root"]; f_all = m["findings"]; c = counts(f_all)
    out = [f"# Security test report: {md(m['project'], 80)}", "",
           f"Date: {m['date']}. Generated by NexaForge SecureCode `report.py` from the gate and test results.", ""]
    out += ["## Executive summary", ""]
    total = len(f_all)
    out.append(f"**Verdict: {m['verdict']}** ({md(m['why'])}). Overall open risk: **{m['risk']}**.")
    out.append("")
    out.append(f"The automated review found {total} issue(s): {c['CRITICAL']} critical, {c['HIGH']} high, "
               f"{c['MEDIUM']} medium, {c['LOW']} low and {c['INFO']} informational.")
    if m["retested"]:
        oc = {o: sum(1 for f in f_all if f["retest"]["outcome"] == o) for o in OUTCOMES}
        out.append("After fixes, the retest gave: " + ", ".join(f"{n} {o.lower()}" for o, n in oc.items() if n) + ".")
    else:
        out.append("No retest results were supplied, so every finding is shown as Not retested.")
    if m["chains"]:
        out.append(f"{len(m['chains'])} possible attack chain(s) combine findings at the same place; see Attack chains.")
    out.append("The verdict covers only what was tested; the Limits section lists what was not.")
    if m["coverage_on"]:
        out += ["", f"**Handover readiness: {m['readiness']}.** " + "; ".join(md(x, 200) for x in m["readiness_why"]) + ".",
                "Readiness describes the review that was done. The security team's own test decides approval."]
    out += ["", "## Scope and method", "",
            f"Target: the project folder `{md(m['project'], 80)}`. Gate mode: `{md(m['mode'], 20)}`.", "",
            "| Tool | Status | Detail |", "|---|---|---|"]
    for t, s, d in tools_table(m):
        out.append(f"| {md(t)} | {md(s)} | {md(d, 300)} |")
    cov = m["coverage"]
    if m["coverage_on"]:
        out += ["", "## Coverage", ""]
        if cov["found"] is not None:
            out.append(f"Entry points found: {cov['found']}. Reviewed: {cov['reviewed'] if cov['reviewed'] is not None else 'not recorded'}.")
            out.append("")
        if not cov["recorded"]:
            out += ["No review coverage was recorded (`.security/coverage.json`), so every class below counts as not examined.", ""]
        out += ["| Class | Status | Evidence or reason |", "|---|---|---|"]
        for r in cov["rows"]:
            out.append(f"| {md(r['label'])} | {r['status']} | {md(r['evidence'] or r['reason'], 300)} |")
    out += ["", "## Findings", "",
            "Each finding is rated on its own. CIA shows what it can break: Confidentiality, Integrity, Availability.", "",
            "| ID | Title | Severity | CIA | Location | Evidence | Fix (root cause first) | Retest |",
            "|---|---|---|---|---|---|---|---|"]
    for f in f_all:
        fix = f["solution"] or classify(f)[2]
        out.append(f"| {f['id']} | {md(title_of(f), 120)} | {f['severity']} | {cia_of(f)} | {md(location_of(f, root), 160)} | "
                   f"{md(evidence_of(f), EXCERPT_LEN)} | {md(fix, 300)} | {f['retest']['outcome']} |")
    if not f_all:
        out.append("| - | No findings were reported by the tools that ran | - | - | - | - | - | Not retested |")
    out += ["", "### Finding details", ""]
    for f in f_all:
        out.append(f"- **{f['id']}** ({f['severity']}, {md(f['rule'], 120)}, fingerprint `{f['fp']}`): {md(f['message'], 600)}")
    out += ["", "## Attack chains", ""]
    if m["chains"]:
        out += ["| Findings | Place | Combined severity | Path |", "|---|---|---|---|"]
        for ch in m["chains"]:
            out.append(f"| {', '.join(ch['ids'])} | {md(ch['place'], 120)} | {ch['severity']} | {md(ch['path'], 300)} |")
    else:
        out.append("No two open findings of chainable types share a file or route.")
    out += ["", "## Retest", ""]
    if m["retested"]:
        out += ["| ID | Outcome | Evidence | Variant tried | Note |", "|---|---|---|---|---|"]
        for f in f_all:
            r = f["retest"]
            note = r["note"]
            if r["outcome"] == "Risk accepted":
                note = f"accepted by {r['accepted_by']} on {r['date']}. {note}"
            out.append(f"| {f['id']} | {r['outcome']} | {md(r['evidence'], 200)} | {md(r['variant'], 200)} | {md(note, 300)} |")
    else:
        out.append("No retest was recorded. Outcome labels: Pass, Fail, Partial, Compensating control, Risk accepted, Not retested.")
    for n in m["notes"]:
        out.append(f"- {md(n, 300)}")
    out += ["", "### Observations (not part of the retest)", ""]
    if m["observations"]:
        for i, o in enumerate(m["observations"], 1):
            # numbered like a finding detail line: what follows is the reviewer's own words, quoted, not the report's
            out.append(f"- **O-{i:02d}** ({md(o.get('title'), 160)} at {md(o.get('location'), 160)}): {md(o.get('note'), 300)}")
    else:
        out.append("None.")
    out += ["", "## Artifacts", "",
            "Test users, seeded rows, files and tests created during testing, so nobody later mistakes them for an intruder's work.", ""]
    if m["artifacts"]:
        out += ["| Item | Purpose | Remove after test |", "|---|---|---|"]
        for a in m["artifacts"]:
            out.append(f"| {md(a.get('item'), 160)} | {md(a.get('purpose'), 200)} | {md(a.get('remove', 'yes'), 40)} |")
    else:
        out.append("No artifacts were recorded (list them in `.security/artifacts.json` when test users or files are created).")
    if m["outputs"]:
        out += ["", "Report files in `.security/`: " + ", ".join(f"`{md(x, 80)}`" for x in m["outputs"][:50]) + "."]
    out += ["", "## Limits", ""]
    out += [f"- {x}" for x in LIMITS]
    # the detail can come from a result file (a DAST note): shown as quoted text, never as the report's own words
    out += [f"- {md(t)} did not run: `{md(d, 200)}`." for t, s, d in tools_table(m) if s == "did not run"]
    out.append("")
    return "\n".join(out)


# --- HTML --------------------------------------------------------------------------------------------------

CSS = """
:root{--ink:#14202b;--muted:#5b6b78;--line:#d7dee4;--bg:#ffffff;--band:#f3f6f8;--accent:#0b5cad;
--crit:#9b1c1c;--high:#c2410c;--med:#a16207;--low:#2f6f3e;--info:#475569}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:10.5pt/1.5 "Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:190mm;margin:0 auto;padding:16px}
h1{font-size:20pt;margin:0 0 4px}h2{font-size:14pt;border-bottom:2px solid var(--accent);padding-bottom:3px;margin-top:22px}
h3{font-size:11.5pt}.meta{color:var(--muted);margin:0 0 12px}
.verdict{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0}
.box{border:1px solid var(--line);border-radius:6px;padding:8px 12px;background:var(--band)}
.box b{display:block;font-size:13pt}
table{width:100%;border-collapse:collapse;margin:8px 0;table-layout:fixed;font-size:9pt}
th,td{border:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}
th{background:var(--band)}
.sev{font-weight:700}.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}.INFO{color:var(--info)}
code,.ev{font-family:Consolas,"Courier New",monospace;font-size:8.5pt}
ul{padding-left:18px}
@page{size:A4;margin:16mm 14mm}
@media print{main{max-width:none;padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
@media (max-width:600px){table{font-size:8pt}}
"""


def render_html(m: dict) -> str:
    root = m["root"]; f_all = m["findings"]; c = counts(f_all)
    e = []
    e.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
             "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
             "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             f"<title>Security test report</title><style>{CSS}</style></head><body><main>")
    e.append(f"<h1>Security test report: {h(m['project'], 80)}</h1>")
    e.append(f"<p class=\"meta\">Date {h(m['date'])}. Generated by NexaForge SecureCode report.py from the gate and test results.</p>")
    e.append("<h2>Executive summary</h2><div class=\"verdict\">")
    e.append(f"<div class=\"box\">Verdict<b>{h(m['verdict'])}</b></div><div class=\"box\">Open risk<b class=\"{m['risk']}\">{h(m['risk'])}</b></div>")
    for s in SEV_ORDER:
        e.append(f"<div class=\"box\">{s.title()}<b class=\"{s}\">{c[s]}</b></div>")
    e.append("</div>")
    e.append(f"<p>{h(m['verdict'])}: {h(m['why'])}. The automated review found {len(f_all)} issue(s). "
             "The verdict covers only what was tested; the Limits section lists what was not.</p>")
    if m["chains"]:
        e.append(f"<p>{len(m['chains'])} possible attack chain(s) combine findings at the same place.</p>")
    if m["coverage_on"]:
        e.append(f"<p><b>Handover readiness: {h(m['readiness'])}.</b> " + "; ".join(h(x, 200) for x in m["readiness_why"]) +
                 ". Readiness describes the review that was done. The security team's own test decides approval.</p>")
    e.append(f"<h2>Scope and method</h2><p>Target: the project folder <code>{h(m['project'], 80)}</code>. Gate mode: {h(m['mode'])}.</p>")
    e.append("<table><colgroup><col style=\"width:28%\"><col style=\"width:14%\"><col></colgroup><tr><th>Tool</th><th>Status</th><th>Detail</th></tr>")
    for t, s, d in tools_table(m):
        e.append(f"<tr><td>{h(t)}</td><td>{h(s)}</td><td>{h(d, 300)}</td></tr>")
    e.append("</table>")
    cov = m["coverage"]
    if m["coverage_on"]:
        e.append("<h2>Coverage</h2>")
        if cov["found"] is not None:
            e.append(f"<p>Entry points found: {cov['found']}. Reviewed: {cov['reviewed'] if cov['reviewed'] is not None else 'not recorded'}.</p>")
        if not cov["recorded"]:
            e.append("<p>No review coverage was recorded (<code>.security/coverage.json</code>), so every class below counts as not examined.</p>")
        e.append("<table><colgroup><col style=\"width:38%\"><col style=\"width:14%\"><col></colgroup>"
                 "<tr><th>Class</th><th>Status</th><th>Evidence or reason</th></tr>")
        for r in cov["rows"]:
            e.append(f"<tr><td>{h(r['label'])}</td><td>{h(r['status'])}</td><td>{h(r['evidence'] or r['reason'], 300)}</td></tr>")
        e.append("</table>")
    e.append("<h2>Findings</h2><p>Each finding is rated on its own. CIA: Confidentiality, Integrity, Availability.</p>")
    e.append("<table><colgroup><col style=\"width:6%\"><col style=\"width:15%\"><col style=\"width:11%\"><col style=\"width:6%\">"
             "<col style=\"width:15%\"><col style=\"width:17%\"><col style=\"width:20%\"><col style=\"width:10%\"></colgroup>"
             "<tr><th>ID</th><th>Title</th><th>Severity</th><th>CIA</th><th>Location</th><th>Evidence</th>"
             "<th>Fix (root cause first)</th><th>Retest</th></tr>")
    for f in f_all:
        fix = f["solution"] or classify(f)[2]
        e.append(f"<tr><td>{f['id']}</td><td>{h(title_of(f), 120)}</td><td class=\"sev {f['severity']}\">{f['severity']}</td>"
                 f"<td>{cia_of(f)}</td><td><code>{h(location_of(f, root), 160)}</code></td>"
                 f"<td class=\"ev\">{h(evidence_of(f), EXCERPT_LEN)}</td><td>{h(fix, 300)}</td><td>{h(f['retest']['outcome'])}</td></tr>")
    if not f_all:
        e.append("<tr><td>-</td><td colspan=\"6\">No findings were reported by the tools that ran.</td><td>Not retested</td></tr>")
    e.append("</table><h3>Finding details</h3><ul>")
    for f in f_all:
        e.append(f"<li><b>{f['id']}</b> ({f['severity']}, <code>{h(f['rule'], 120)}</code>, fingerprint <code>{f['fp']}</code>): "
                 f"{h(f['message'], 600)}</li>")
    e.append("</ul><h2>Attack chains</h2>")
    if m["chains"]:
        e.append("<table><tr><th>Findings</th><th>Place</th><th>Combined severity</th><th>Path</th></tr>")
        for ch in m["chains"]:
            e.append(f"<tr><td>{h(', '.join(ch['ids']))}</td><td><code>{h(ch['place'], 120)}</code></td>"
                     f"<td class=\"sev {ch['severity']}\">{ch['severity']}</td><td>{h(ch['path'], 300)}</td></tr>")
        e.append("</table>")
    else:
        e.append("<p>No two open findings of chainable types share a file or route.</p>")
    e.append("<h2>Retest</h2>")
    if m["retested"]:
        e.append("<table><tr><th>ID</th><th>Outcome</th><th>Evidence</th><th>Variant tried</th><th>Note</th></tr>")
        for f in f_all:
            r = f["retest"]; note = r["note"]
            if r["outcome"] == "Risk accepted":
                note = f"accepted by {r['accepted_by']} on {r['date']}. {note}"
            e.append(f"<tr><td>{f['id']}</td><td>{h(r['outcome'])}</td><td>{h(r['evidence'], 200)}</td>"
                     f"<td>{h(r['variant'], 200)}</td><td>{h(note, 300)}</td></tr>")
        e.append("</table>")
    else:
        e.append("<p>No retest was recorded. Outcome labels: Pass, Fail, Partial, Compensating control, Risk accepted, Not retested.</p>")
    if m["notes"]:
        e.append("<ul>" + "".join(f"<li>{h(n, 300)}</li>" for n in m["notes"]) + "</ul>")
    e.append("<h3>Observations (not part of the retest)</h3>")
    if m["observations"]:
        e.append("<ul>" + "".join(f"<li>{h(o.get('title'), 160)} at <code>{h(o.get('location'), 160)}</code>: {h(o.get('note'), 300)}</li>"
                                  for o in m["observations"]) + "</ul>")
    else:
        e.append("<p>None.</p>")
    e.append("<h2>Artifacts</h2><p>Test users, seeded rows, files and tests created during testing.</p>")
    if m["artifacts"]:
        e.append("<table><tr><th>Item</th><th>Purpose</th><th>Remove after test</th></tr>")
        for a in m["artifacts"]:
            e.append(f"<tr><td>{h(a.get('item'), 160)}</td><td>{h(a.get('purpose'), 200)}</td><td>{h(a.get('remove', 'yes'), 40)}</td></tr>")
        e.append("</table>")
    else:
        e.append("<p>No artifacts were recorded.</p>")
    if m["outputs"]:
        e.append("<p>Report files in <code>.security/</code>: " + ", ".join(h(x, 80) for x in m["outputs"][:50]) + ".</p>")
    e.append("<h2>Limits</h2><ul>" + "".join(f"<li>{h(x)}</li>" for x in LIMITS))
    e.append("".join(f"<li>{h(t)} did not run: {h(d, 200)}.</li>" for t, s, d in tools_table(m) if s == "did not run"))
    e.append("</ul></main></body></html>")
    return "\n".join(e)


# --- PDF ---------------------------------------------------------------------------------------------------

def find_browser() -> str | None:
    from secgate import find_tool
    for name in ("msedge", "chrome", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        p = find_tool(name)
        if p:
            return p
    cands = []
    for env in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if base:
            cands += [Path(base) / "Microsoft/Edge/Application/msedge.exe", Path(base) / "Google/Chrome/Application/chrome.exe",
                      Path(base) / "Chromium/Application/chrome.exe"]
    cands += [Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
              Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
              Path("/Applications/Chromium.app/Contents/MacOS/Chromium")]
    for c in cands:
        if c.is_file():
            return str(c)
    return None


def print_pdf(html_path: Path, pdf_path: Path, browser: str | None = None) -> tuple[bool, str]:
    browser = browser or find_browser()
    if not browser:
        return False, "no Chromium, Chrome or Edge found; open REPORT.html in a browser and print it to PDF (A4)"
    with tempfile.TemporaryDirectory() as prof:
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions", "--no-pdf-header-footer",
               f"--user-data-dir={prof}", f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()]
        try:
            subprocess.run(cmd, capture_output=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as ex:
            return False, f"PDF printing failed ({type(ex).__name__}); open REPORT.html and print it"
    if pdf_path.is_file() and pdf_path.stat().st_size > 0:
        return True, f"wrote {pdf_path}"
    return False, "the browser did not produce a PDF; open REPORT.html and print it"


# --- main --------------------------------------------------------------------------------------------------

def safe_stdout() -> None:
    """A project folder or a finding can hold characters the console's code page has no letter for (cp1252 on a piped
    Windows console). Printing them must not end the run after the files were written."""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def inside(root: Path, p: str | None, default: str | None) -> Path | None:
    v = p or default
    if not v:
        return None
    q = (root / v).resolve() if not os.path.isabs(v) else Path(v).resolve()
    try:
        q.relative_to(root.resolve())
    except ValueError:
        raise SystemExit(f"refused: {v} is outside the project folder")
    return q


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Write REPORT.md and REPORT.html from .security results.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--findings", default=None)
    ap.add_argument("--before", default=None)
    ap.add_argument("--dast", default=None)
    ap.add_argument("--retest", default=None)
    ap.add_argument("--artifacts", default=None)
    ap.add_argument("--review", default=None, help="findings from the code review (default .security/review-findings.json)")
    ap.add_argument("--coverage", default=None, help="review coverage per class (default .security/coverage.json)")
    ap.add_argument("--out", default=".security")
    ap.add_argument("--pdf", action="store_true", help="also print REPORT.pdf with a local headless Chromium or Edge")
    a = ap.parse_args(argv)
    safe_stdout()
    root = Path(a.root).resolve()
    sec = root / ".security"
    findings = inside(root, a.findings, ".security/findings.json")
    if not findings or not findings.is_file():
        print("NOTE: .security/findings.json not found; run the gate first: secgate.py . --mode ci --fail-on high --run-tests")
        return 3
    def opt(v, name):
        q = inside(root, v, None) if v else (sec / name)
        return q if q and os.path.lexists(q) else None      # a folder with that name is "there but unreadable", not absent
    out = inside(root, a.out, ".security")
    try:
        model = build(root, findings, opt(a.before, "findings-before.json"), opt(a.dast, "dast-findings.json"),
                      opt(a.retest, "retest.json"), opt(a.artifacts, "artifacts.json"),
                      opt(a.review, "review-findings.json"), opt(a.coverage, "coverage.json"))
        md_text, html_text = render_md(model), render_html(model)
    except Exception as ex:             # result files are attacker-controlled: a message, never a traceback
        print(f"NOTE: the report could not be built from the result files ({type(ex).__name__}); check that they are valid JSON")
        return 3
    out.mkdir(parents=True, exist_ok=True)
    state = {"verdict": model["verdict"], "why": visible(model["why"]), "readiness": model["readiness"],
             "readiness_why": [visible(x) for x in model["readiness_why"]], "risk": model["risk"], "date": model["date"],
             "counts": counts(model["findings"]), "not_examined": model["coverage"]["open"],
             # what a retest entry names a finding by: the number can change between runs, the fingerprint does not
             "fingerprints": {f["id"]: f["fp"] for f in model["findings"]}}

    def put(name, text):                # a new file moved into place: a hard link or link planted at the name is
        tmp = out / f"{name}.{os.getpid()}.tmp"      # replaced, never written through
        try:
            with open(tmp, "w", encoding="utf-8", errors="replace", newline="\n") as fh:
                fh.write(text)
            os.replace(tmp, out / name)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)
    try:
        put("REPORT.md", md_text)
        put("REPORT.html", html_text)
        put("report-state.json", json.dumps(state, indent=1) + "\n")
    except OSError as ex:               # a folder or a locked file where a report file goes
        print(f"NOTE: the report could not be written in {out} ({type(ex).__name__}); remove or close what is at "
              "REPORT.md, REPORT.html and report-state.json there")
        return 3
    print(f"Wrote {out / 'REPORT.md'} and {out / 'REPORT.html'}")
    print(f"Verdict: {model['verdict']} ({visible(model['why'])}); findings: {counts(model['findings'])}")
    if model["coverage_on"]:
        print(f"Handover readiness: {model['readiness']} ({'; '.join(visible(x) for x in model['readiness_why'])})")
    if a.pdf:
        ok, msg = print_pdf(out / "REPORT.html", out / "REPORT.pdf")
        print(("" if ok else "NOTE: ") + msg)
    else:
        print("For a PDF: run again with --pdf, or open REPORT.html and print it (A4).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
