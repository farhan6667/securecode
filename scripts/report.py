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
EXCERPT_LEN = 160

# --- sanitising -------------------------------------------------------------------------------------------

# C0/C1 controls, zero-width and bidirectional formatting characters, BOM, line/paragraph separators and the
# Unicode tag block. They are shown as [U+XXXX] so a reviewer can see something was hidden there.
INVISIBLE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069"
                       "\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]")


def visible(s) -> str:
    s = "" if s is None else str(s)
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
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "[REDACTED JWT]"),
    # scheme://user:password@host keeps the user, hides the password
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,20}://[^\s:/@'\"]{1,100}:)(?!\[REDACTED\]@)[^\s@'\"]{1,200}@"), r"\1[REDACTED]@"),
    # key = "value", key: value, KEY=value for names that hold secrets
    (re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|"
                r"client[_\-]?secret|auth|bearer|credential|session[_\-]?id)[\w\-]{0,20}[\"']?\s*(?:=>|[:=])\s*)"
                r"([\"'`]?)([^\s\"'`,;]{4,})\2"), r"\1\2[REDACTED]\2"),
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=\-]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=\-]{16,}"), r"\1[REDACTED]"),
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
    s = visible(redact(s)).strip()
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
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError):
        return default


def norm_finding(f) -> dict | None:
    if not isinstance(f, dict):
        return None
    sev = str(f.get("severity", "INFO")).upper()
    if sev not in SEV_ORDER:
        sev = "INFO"
    try:
        line = int(f.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    return {"rule": str(f.get("rule") or "UNKNOWN")[:200], "severity": sev, "file": str(f.get("file") or "")[:500],
            "line": max(0, line), "message": str(f.get("message") or "")[:4000], "code": str(f.get("code") or "")[:2000],
            "engine": str(f.get("engine") or "")[:60], "cia": f.get("cia"), "url": str(f.get("url") or "")[:500],
            "solution": str(f.get("solution") or "")[:2000], "cwe": str(f.get("cwe") or "")[:20]}


def findings_of(report) -> list[dict]:
    raw = report.get("findings", []) if isinstance(report, dict) else []
    out = [n for n in (norm_finding(f) for f in (raw if isinstance(raw, list) else [])[:MAX_FINDINGS]) if n]
    return out


def rel_path(p: str, root: Path) -> str:
    if not p:
        return ""
    try:
        return Path(p).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return p.replace("\\", "/")


def fingerprint(f: dict, root: Path) -> str:
    """Stable across line shifts: rule, file and the normalised code line (or the URL for DAST)."""
    code = re.sub(r"\s+", " ", f.get("code") or "").strip()
    basis = "|".join([f["rule"], rel_path(f["file"], root), code or f.get("url") or str(f["line"])])
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
    if f.get("url"):
        return f["url"]
    p = rel_path(f["file"], root)
    return f"{p}:{f['line']}" if p and f["line"] else (p or "(project)")


def evidence_of(f: dict) -> str:
    if is_secret_finding(f):
        return "[excerpt withheld: secret finding, see the scanner report on the developer's machine]"
    return f["code"] or ""


def route_key(f: dict, root: Path) -> str:
    """The place two findings must share to be chained: the URL path for DAST, otherwise the file."""
    if f.get("url"):
        m = re.match(r"(?i)^[a-z]+://[^/]+(/[^?#]*)?", f["url"])
        return "route:" + ((m.group(1) if m else "") or "/").rstrip("/").lower()
    return "file:" + rel_path(f["file"], root).lower()


# --- retest ------------------------------------------------------------------------------------------------

def apply_retests(found: list[dict], retest, current_fps: set[str] | None) -> tuple[list[dict], list[str]]:
    """Attach an outcome label to every finding. Returns the observations and a list of report notes."""
    notes: list[str] = []
    results = retest.get("results", []) if isinstance(retest, dict) else []
    by_key = {}
    for r in results if isinstance(results, list) else []:
        if isinstance(r, dict):
            for k in (r.get("id"), r.get("fingerprint")):
                if isinstance(k, str) and k:
                    by_key[k] = r
    for f in found:
        r = by_key.get(f["id"]) or by_key.get(f["fp"]) or {}
        outcome = str(r.get("outcome") or "Not retested").strip()
        match = next((o for o in OUTCOMES if o.lower() == outcome.lower()), None)
        evidence = str(r.get("evidence") or "").strip()
        f["retest"] = {"outcome": match or "Not retested", "evidence": evidence, "variant": str(r.get("variant") or ""),
                       "note": str(r.get("note") or ""), "accepted_by": str(r.get("accepted_by") or ""),
                       "date": str(r.get("date") or "")}
        rt = f["retest"]
        if match is None and r:
            rt["note"] = f"unknown outcome label '{outcome}' ignored. " + rt["note"]
            notes.append(f"{f['id']}: unknown outcome label replaced with Not retested")
        if rt["outcome"] == "Pass" and not evidence:
            rt["outcome"] = "Not retested"
            rt["note"] = "a Pass needs evidence (the test or command that reached the sink and was refused). " + rt["note"]
            notes.append(f"{f['id']}: Pass without evidence was recorded as Not retested")
        if rt["outcome"] == "Risk accepted" and not (rt["accepted_by"] and re.fullmatch(r"\d{4}-\d{2}-\d{2}", rt["date"])):
            rt["outcome"] = "Not retested"
            rt["note"] = "Risk accepted needs a named person and a date (YYYY-MM-DD). " + rt["note"]
            notes.append(f"{f['id']}: Risk accepted without a name and date was recorded as Not retested")
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


def overall_risk(found: list[dict]) -> str:
    live = [f["severity"] for f in found if f["retest"]["outcome"] in OPEN_OUTCOMES]
    return min(live, key=SEV_ORDER.index) if live else "LOW"


# --- building the report model -----------------------------------------------------------------------------

def build(root: Path, findings_path: Path, before_path: Path | None, dast_path: Path | None,
          retest_path: Path | None, artifacts_path: Path | None) -> dict:
    current = load_json(findings_path, None)
    before = load_json(before_path, None) if before_path else None
    base = before if isinstance(before, dict) else current
    if not isinstance(base, dict):
        base = {"mode": "unknown", "tool_status": {}, "findings": []}
    tool_status = base.get("tool_status") if isinstance(base.get("tool_status"), dict) else {}
    found = assign_ids(findings_of(base), "F", root)
    dast = load_json(dast_path, {}) if dast_path else {}
    dast = dast if isinstance(dast, dict) else {}
    dfound = assign_ids(findings_of(dast), "D", root)
    allf = found + dfound
    current_fps = None
    if isinstance(before, dict) and isinstance(current, dict):
        current_fps = {fingerprint(f, root) for f in findings_of(current)}
    retest = load_json(retest_path, {}) if retest_path else {}
    observations, notes = apply_retests(allf, retest, current_fps)
    if isinstance(before, dict) and isinstance(current, dict):
        known = {f["fp"] for f in found}
        for f in findings_of(current):
            if fingerprint(f, root) not in known:
                observations.append({"title": title_of(f), "location": location_of(f, root),
                                     "note": f"{f['severity']}: reported by the latest gate run but not in the first one."})
    artifacts = load_json(artifacts_path, []) if artifacts_path else []
    if isinstance(artifacts, dict):
        artifacts = artifacts.get("artifacts", [])
    artifacts = [a for a in (artifacts if isinstance(artifacts, list) else []) if isinstance(a, dict)][:200]
    v, why = verdict(allf, tool_status, dast)
    return {"root": root, "date": datetime.date.today().isoformat(), "mode": str(base.get("mode", "unknown")),
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
    out += ["", "## Scope and method", "",
            f"Target: the project folder `{md(m['project'], 80)}`. Gate mode: {md(m['mode'])}.", "",
            "| Tool | Status | Detail |", "|---|---|---|"]
    for t, s, d in tools_table(m):
        out.append(f"| {md(t)} | {md(s)} | {md(d, 300)} |")
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
        out.append(f"- **{f['id']}** ({f['severity']}, {md(f['rule'], 120)}): {md(f['message'], 600)}")
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
        for o in m["observations"]:
            out.append(f"- {md(o.get('title'), 160)} at {md(o.get('location'), 160)}: {md(o.get('note'), 300)}")
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
        out += ["", "Report files in `.security/`: " + ", ".join(md(x, 80) for x in m["outputs"][:50]) + "."]
    out += ["", "## Limits", ""]
    out += [f"- {x}" for x in LIMITS]
    out += [f"- {md(t)} did not run: {md(d, 200)}." for t, s, d in tools_table(m) if s == "did not run"]
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
    e.append(f"<h2>Scope and method</h2><p>Target: the project folder <code>{h(m['project'], 80)}</code>. Gate mode: {h(m['mode'])}.</p>")
    e.append("<table><colgroup><col style=\"width:28%\"><col style=\"width:14%\"><col></colgroup><tr><th>Tool</th><th>Status</th><th>Detail</th></tr>")
    for t, s, d in tools_table(m):
        e.append(f"<tr><td>{h(t)}</td><td>{h(s)}</td><td>{h(d, 300)}</td></tr>")
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
        e.append(f"<li><b>{f['id']}</b> ({f['severity']}, <code>{h(f['rule'], 120)}</code>): {h(f['message'], 600)}</li>")
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
    ap.add_argument("--out", default=".security")
    ap.add_argument("--pdf", action="store_true", help="also print REPORT.pdf with a local headless Chromium or Edge")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    sec = root / ".security"
    findings = inside(root, a.findings, ".security/findings.json")
    if not findings or not findings.is_file():
        print("NOTE: .security/findings.json not found; run the gate first: secgate.py . --mode ci --fail-on high --run-tests")
        return 3
    def opt(v, name):
        q = inside(root, v, None) if v else (sec / name)
        return q if q and q.is_file() else None
    model = build(root, findings, opt(a.before, "findings-before.json"), opt(a.dast, "dast-findings.json"),
                  opt(a.retest, "retest.json"), opt(a.artifacts, "artifacts.json"))
    out = inside(root, a.out, ".security")
    out.mkdir(parents=True, exist_ok=True)
    (out / "REPORT.md").write_text(render_md(model), encoding="utf-8")
    (out / "REPORT.html").write_text(render_html(model), encoding="utf-8")
    print(f"Wrote {out / 'REPORT.md'} and {out / 'REPORT.html'}")
    print(f"Verdict: {model['verdict']} ({visible(model['why'])}); findings: {counts(model['findings'])}")
    if a.pdf:
        ok, msg = print_pdf(out / "REPORT.html", out / "REPORT.pdf")
        print(("" if ok else "NOTE: ") + msg)
    else:
        print("For a PDF: run again with --pdf, or open REPORT.html and print it (A4).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
