#!/usr/bin/env python3
"""NexaForge SecureCode secret shield (7.0).

Two jobs:

1. PostToolUse hook (Bash, PowerShell, Read, Grep, WebFetch and MCP tools). The agent guard stops the agent
   from opening `.env` and key files, but a secret can still arrive through allowed output: `cat config.php`, a
   test log, an env dump, an MCP response. This hook scans the tool output for high-confidence secret
   patterns and, when one is found, gives Claude Code a copy of the output with every secret value replaced
   (`hookSpecificOutput.updatedToolOutput`, documented for all tools; the copy keeps the tool's own output
   shape, so built-in tools accept it). It also returns `decision: "block"` with a reason that names the
   source and the secret type, never the value, and tells the agent to stop and ask the user. On an older
   Claude Code that ignores `updatedToolOutput`, that reason is the remaining control.

2. `py -I scripts/secret_shield.py sweep [path ...]` reads Claude Code transcripts (~/.claude/projects/**.jsonl)
   and project logs, read only, and lists secrets that already leaked: file, line, type and a masked preview,
   plus how to revoke each kind. It never prints a full secret and never edits a file.

Fail-safe behaviour (decided for a PostToolUse hook; see docs/SECRET-SHIELD-AND-MCP.md):
- Malformed hook input: exit 0 with no output. There is no tool output we could replace.
- Output larger than the scan budget, or a scan that runs past its own deadline: fail closed for what was not
  scanned. That part is replaced by a "withheld, not scanned" marker, in the same output shape.
- An unexpected internal error: fail open with a warning (additionalContext). A crashing redactor cannot be
  trusted to produce a correct replacement, and a hook that breaks every tool call would trap the session.
  Claude Code itself treats a crashed or timed-out PostToolUse hook as non-blocking, so this is also what
  happens when the process dies. The internal deadline (4 s) sits well below the hook timeout (20 s).
Every regex has bounded repetition and no nested quantifiers (linear time per start position).
"""
from __future__ import annotations

import base64, json, math, os, re, stat, sys, time

SCAN_MAX = 2_000_000          # characters scanned per hook event; the rest is withheld (fail closed)
STRING_MAX = 2_000_000        # one string is cut to this before scanning
DEADLINE_S = 4.0              # own deadline, far below the hook timeout
AUDIT_NAME = "shield-audit.jsonl"
AUDIT_MAX_BYTES = 5_000_000
MAX_DEPTH = 64

MARK = "[REDACTED by secret shield: {}]"
WITHHELD = "[secret shield: {} characters withheld because they could not be scanned in time]"

# --------------------------------------------------------------------------------------------------- patterns
# (type, regex, value group). The value group is the part that is replaced; the rest stays readable.
# Every quantifier is bounded and no group is repeated, so each regex runs in linear time per start position.
_P = [
    ("aws-access-key-id", r"(?<![A-Za-z0-9])((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})(?![A-Za-z0-9])", 1),
    ("aws-secret-access-key", r"(?i)aws_?secret_?(?:access_?)?key(?:\\?[\"'])?\s{0,5}(?:=>|:=|=|:)\s{0,5}(?:\\?[\"'])?"
                              r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", 1),
    ("github-token", r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9_])", 1),
    ("github-fine-grained-token", r"(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{60,255})", 1),
    ("gitlab-token", r"(?<![A-Za-z0-9_-])((?:glpat|gldt|glptt|glrt|glsoat|glcbt|glft|glimt|gloas)-[A-Za-z0-9_-]{20,255})", 1),
    ("slack-token", r"(?<![A-Za-z0-9])(xox[abposr]-[A-Za-z0-9-]{10,255})", 1),
    ("slack-webhook", r"https://hooks\.slack\.com/(?:services|workflows|triggers)/([A-Za-z0-9_/+-]{20,255})", 1),
    ("stripe-key", r"(?<![A-Za-z0-9])((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255})", 1),
    ("google-api-key", r"(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])", 1),
    ("anthropic-key", r"(?<![A-Za-z0-9_-])(sk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_-]{40,255})", 1),
    ("openai-key", r"(?<![A-Za-z0-9_-])(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,255}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})", 1),
    ("npm-token", r"(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])", 1),
    ("pypi-token", r"(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,255})", 1),
    ("azure-storage-key", r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)", 1),
    ("jwt", r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{16,4096})", 1),
    ("db-url-password", r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse|"
                        r"cockroachdb|jdbc:[a-z]{2,20})://[^\s:/@\"'<>]{1,128}:([^\s@/\"'<>]{1,256})@", 1),
    ("url-password", r"(?i)\b(?:https?|ftps?|smtps?|ldaps?)://[^\s:/@\"'<>]{1,128}:([^\s@/\"'<>]{1,256})@", 1),
    ("secret-assignment", r"(?i)(?<![A-Za-z0-9])([A-Za-z0-9_.-]{0,40}?(?:secret|passw(?:or)?d|pwd|token|api[_-]?key|apikey|"
                          r"access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credential)s?)(?:\\?[\"'])?\s{0,5}"
                          r"(?:=>|:=|=|:)\s{0,5}(?:\\?[\"'])?([^\s\"'`\\,;<>(){}\[\]]{12,256})", 2),
]
PATTERNS = [(t, re.compile(rx), g) for t, rx, g in _P]
PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----")
PRIVATE_KEY_END = re.compile(r"-----END[ A-Z0-9]{0,40}PRIVATE KEY(?: BLOCK)?-----")
PRIVATE_KEY_SPAN = 20_000

# Words that mark a documentation example or placeholder, not a live secret (AWS's own doc keys end in EXAMPLE).
EXAMPLE_WORDS = re.compile(r"(?i)example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|\*\*\*|redacted|"
                           r"<[a-z_ -]{1,40}>|notreal|not_real|fake|insert[_-]|replace[_-]?me|lorem|0123456789abcdef|"
                           r"abcdefghij|1234567890ab")
REFERENCE = re.compile(r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|\$env:[A-Za-z_]\w*|"
                       r"(?:process\.env|os\.environ|getenv|env)\b.*|\{\{.*\}\}|\{[A-Za-z_][\w.\[\]'\"]{0,80}\}|"
                       r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)$")
IDENT = re.compile(r"^[a-z_][a-z0-9_-]*$")
# Framework validation rules ('required|min:12|confirmed') sit next to password keys all the time.
VALIDATION_RULE = re.compile(r"^[a-z_]+(?::[\w,.]*)?(?:\|[a-z_]+(?::[\w,.]*)?)+$")

SEVERITY = {"private-key": "critical", "aws-access-key-id": "critical", "aws-secret-access-key": "critical",
            "github-token": "critical", "github-fine-grained-token": "critical", "gitlab-token": "critical",
            "slack-token": "high", "slack-webhook": "high", "stripe-key": "critical", "google-api-key": "high",
            "anthropic-key": "critical", "openai-key": "critical", "npm-token": "critical", "pypi-token": "critical",
            "azure-storage-key": "critical", "jwt": "high", "db-url-password": "critical", "url-password": "high",
            "secret-assignment": "high"}
# Types whose leading characters are a public, documented prefix: the masked preview may show them.
PUBLIC_PREFIX = {"aws-access-key-id": 4, "github-token": 4, "github-fine-grained-token": 11, "gitlab-token": 6,
                 "slack-token": 5, "stripe-key": 8, "google-api-key": 4, "anthropic-key": 7, "openai-key": 3,
                 "npm-token": 4, "pypi-token": 5, "jwt": 3}

REVOKE = {
    "aws-access-key-id": "AWS: IAM console > Users > Security credentials > deactivate and delete the access key (or "
                         "`aws iam delete-access-key`), create a new one, and check CloudTrail for use of the old key.",
    "aws-secret-access-key": "AWS: the secret belongs to an access key id; deactivate and delete that key in IAM and "
                             "review CloudTrail.",
    "github-token": "GitHub: Settings > Developer settings > Personal access tokens (or the app or OAuth app) > revoke. "
                    "Check the security log for use.",
    "github-fine-grained-token": "GitHub: Settings > Developer settings > Fine-grained tokens > revoke, then check the "
                                 "audit log of the repositories it could reach.",
    "gitlab-token": "GitLab: User settings > Access tokens (or the project or group token page) > revoke.",
    "slack-token": "Slack: api.slack.com/apps > your app > OAuth & Permissions > revoke or rotate the token.",
    "slack-webhook": "Slack: api.slack.com/apps > Incoming Webhooks > remove the webhook URL and create a new one.",
    "stripe-key": "Stripe: Dashboard > Developers > API keys > roll the key (test keys too, they reveal account data).",
    "google-api-key": "Google Cloud: APIs & Services > Credentials > regenerate or delete the key, then add API and "
                      "referrer restrictions to the new one.",
    "anthropic-key": "Anthropic: Console > API keys > disable and delete the key, create a new one.",
    "openai-key": "OpenAI: platform settings > API keys > revoke the key, create a new one.",
    "npm-token": "npm: npmjs.com > Access Tokens > delete the token (`npm token revoke <id>`), check recent publishes.",
    "pypi-token": "PyPI: Account settings > API tokens > remove the token, check recent releases.",
    "azure-storage-key": "Azure: Storage account > Access keys > rotate the key, then update the apps that use it.",
    "jwt": "JWT: a token is valid until it expires. Revoke the session if the issuer allows it; if it was signed with a "
           "shared secret that may also have leaked, rotate that secret.",
    "db-url-password": "Database: change the password of that database user, update the apps, and check the database "
                       "logs for logins from unknown hosts.",
    "url-password": "Service URL: change the password of the account in that URL.",
    "private-key": "Private key: generate a new key pair, remove the old public key everywhere it is trusted "
                   "(authorized_keys, deploy keys, servers, certificates), and revoke any certificate issued for it.",
    "secret-assignment": "Generic secret: find which service issued it from the variable name, rotate it there, and "
                         "update every place that uses it.",
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _jwt_is_example(v: str) -> bool:
    # The jwt.io sample token (subject 1234567890, "John Doe") is in countless docs.
    try:
        part = v.split(".")[1]
        data = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)).decode("utf-8", "replace")
        return '"1234567890"' in data and "John Doe" in data
    except Exception:
        return False


def is_example(kind: str, value: str, key: str = "") -> bool:
    """True when the value is a documentation example or a placeholder rather than a live secret."""
    if EXAMPLE_WORDS.search(value):
        return True
    if len(set(value)) <= 3:
        return True
    if kind == "jwt" and _jwt_is_example(value):
        return True
    if kind in ("secret-assignment", "db-url-password", "url-password"):
        if REFERENCE.match(value) or value.lower() in ("password", "passwd", "secret", "token", "null", "none", "true",
                                                       "false", "undefined"):
            return True
    return False


def _generic_is_secret(value: str) -> bool:
    """The generic key=value rule fires only on values that look random: long enough, several character
    classes, and high entropy. Code identifiers, references and words are left alone."""
    if REFERENCE.match(value) or IDENT.match(value) or VALIDATION_RULE.match(value):
        return False
    classes = sum(bool(re.search(rx, value)) for rx in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    if classes < 2 or not re.search(r"[0-9]", value) and classes < 3:
        return False
    return _entropy(value) >= 3.2


class Match:
    __slots__ = ("kind", "start", "end", "value", "key", "example")

    def __init__(self, kind, start, end, value, key="", example=False):
        self.kind, self.start, self.end, self.value, self.key, self.example = kind, start, end, value, key, example

    @property
    def severity(self):
        return "low" if self.example else SEVERITY.get(self.kind, "high")


class Budget(Exception):
    """The scan ran past its own deadline."""


def find_secrets(text: str, deadline: float | None = None) -> list[Match]:
    """Every secret-looking span in text, examples included (marked). Overlaps keep the earliest, longest span."""
    out: list[Match] = []
    if not text:
        return out
    pos = 0
    while True:
        m = PRIVATE_KEY_BEGIN.search(text, pos)
        if not m:
            break
        e = PRIVATE_KEY_END.search(text, m.end(), min(len(text), m.end() + PRIVATE_KEY_SPAN))
        end = e.end() if e else min(len(text), m.end() + PRIVATE_KEY_SPAN)
        body = text[m.end():e.start() if e else end]
        # A header with no key body (docs, a regex, an error message) is not a key.
        example = len(re.sub(r"[^A-Za-z0-9+/=]", "", body)) < 40 or bool(EXAMPLE_WORDS.search(body[:200]))
        out.append(Match("private-key", m.start(), end, text[m.start():end], example=example))
        pos = end
    for kind, rx, g in PATTERNS:
        if deadline is not None and time.monotonic() > deadline:
            raise Budget()
        for m in rx.finditer(text):
            v = m.group(g)
            if not v:
                continue
            key = m.group(1) if kind == "secret-assignment" else ""
            if kind == "secret-assignment" and not _generic_is_secret(v) and not is_example(kind, v, key):
                continue
            out.append(Match(kind, m.start(g), m.end(g), v, key, is_example(kind, v, key)))
    out.sort(key=lambda x: (x.start, -(x.end - x.start)))
    merged: list[Match] = []
    for x in out:
        if merged and x.start < merged[-1].end:
            if x.end > merged[-1].end and not x.example:
                merged[-1].end = x.end
            if merged[-1].example and not x.example:
                merged[-1].example = False
                merged[-1].kind = x.kind
            continue
        merged.append(x)
    return merged


def redact_text(text: str, deadline: float | None = None, keep_examples: bool = True) -> tuple[str, list[Match]]:
    """text with every live secret replaced by a typed marker, and the live matches. Examples stay readable."""
    found = [m for m in find_secrets(text, deadline) if not (keep_examples and m.example)]
    if not found:
        return text, []
    parts, last = [], 0
    for m in found:
        parts.append(text[last:m.start])
        parts.append(MARK.format(m.kind))
        last = m.end
    parts.append(text[last:])
    return "".join(parts), found


def redact(text: str, limit: int = 300) -> str:
    """Short, single-line, fully redacted text for audit lines and messages (examples redacted too)."""
    t = str(text)[:limit * 4]
    t, _ = redact_text(t, keep_examples=False)
    t = re.sub(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]", " ", t)
    return t[:limit] + ("..." if len(t) > limit else "")


def mask(m: Match) -> str:
    """A preview that proves which secret it is to its owner without giving any of it away."""
    if m.kind == "private-key":
        head = PRIVATE_KEY_BEGIN.match(m.value)
        return f"{head.group(0) if head else 'PRIVATE KEY'} ...(key block, {len(m.value)} chars)"
    n = PUBLIC_PREFIX.get(m.kind, 0)
    lead = m.value[:n] if len(m.value) > n + 8 else ""
    key = f"{m.key.strip()[:60]}=" if m.key else ""
    return f"{key}{lead}{'*' * 8} ({len(m.value)} chars)"


# --------------------------------------------------------------------------------------------- hook handling

BINARY_KEYS = {"base64"}
BINARY_TYPES = {"image", "audio", "pdf", "blob", "binary", "notebook_image"}


class Walker:
    """Copies a JSON value with every string redacted, within a global character budget and a deadline."""

    def __init__(self, budget: int = SCAN_MAX, deadline_s: float = DEADLINE_S):
        self.left = budget
        self.deadline = time.monotonic() + deadline_s
        self.found: list[Match] = []
        self.withheld = 0
        self.examples = 0

    def text(self, s: str) -> str:
        if self.left <= 0 or time.monotonic() > self.deadline:
            self.withheld += len(s)
            return WITHHELD.format(len(s)) if s else s
        head, tail = s[:min(self.left, STRING_MAX)], s[min(self.left, STRING_MAX):]
        self.left -= len(head)
        try:
            new, found = redact_text(head, self.deadline)
        except Budget:
            self.withheld += len(s)
            return WITHHELD.format(len(s))
        self.found += found
        if tail:
            self.withheld += len(tail)
            # A secret cut in half at the boundary: withhold the last 512 scanned characters as well.
            new = new[:-512] + WITHHELD.format(len(tail) + 512) if len(new) > 512 else WITHHELD.format(len(s))
        return new

    def walk(self, x, depth: int = 0):
        if depth > MAX_DEPTH:
            # Too deep to walk safely: withhold the whole branch, keeping its type so the shape still matches.
            self.withheld += 1
            return WITHHELD.format("deeply nested") if isinstance(x, str) else ([] if isinstance(x, list) else
                                                                                  {} if isinstance(x, dict) else x)
        if isinstance(x, str):
            return self.text(x)
        if isinstance(x, dict):
            # Images, PDFs and other binary payloads (Read's file.base64, MCP image/audio/blob content, Bash image
            # output) pass through untouched: the model does not read them as text, and cutting them would break them.
            binary = {k for k in x if k in BINARY_KEYS}
            if str(x.get("type", "")).lower() in BINARY_TYPES or x.get("mimeType") or x.get("media_type"):
                binary |= {k for k in ("data", "blob") if k in x}
            if x.get("isImage") is True and "stdout" in x:
                binary.add("stdout")
            return {k: (v if k in binary and isinstance(v, str) else self.walk(v, depth + 1)) for k, v in x.items()}
        if isinstance(x, list):
            return [self.walk(v, depth + 1) for v in x]
        return x


def source_of(event: dict) -> str:
    ti = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    for k in ("file_path", "path", "url", "command", "pattern", "notebook_path"):
        v = ti.get(k)
        if isinstance(v, str) and v:
            return redact(v, 160)
    return redact(str(event.get("tool_name") or "tool output"), 80)


def _project_root(event: dict) -> str | None:
    project = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or ""
    if not isinstance(project, str) or not project or len(project) > 4096:
        return None
    root = os.path.realpath(project)
    home = os.path.realpath(os.path.expanduser("~"))
    if not os.path.isdir(root) or os.path.normcase(root) == os.path.normcase(home) or os.path.dirname(root) == root:
        return None
    return root


def audit(event: dict, action: str, found: list[Match], withheld: int = 0) -> bool:
    """Append one line (no values) to <project>/.security/shield-audit.jsonl. Best effort; refuses links."""
    try:
        root = _project_root(event)
        if not root:
            return False
        d = os.path.join(root, ".security")
        if os.path.lexists(d):
            st = os.lstat(d)
            if not stat.S_ISDIR(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
                return False
        else:
            os.mkdir(d)
        f = os.path.join(d, AUDIT_NAME)
        if os.path.lexists(f):
            st = os.lstat(f)
            if not stat.S_ISREG(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400 or st.st_nlink > 1 \
                    or st.st_size > AUDIT_MAX_BYTES:
                return False
        types = sorted({m.kind for m in found})
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "action": action,
                "tool": redact(event.get("tool_name") or "", 80), "source": source_of(event),
                "types": types, "count": len(found), "withheld_chars": withheld}
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(f, flags, 0o600)
        with os.fdopen(fd, "ab") as fh:
            fh.write((json.dumps(line, ensure_ascii=True) + "\n").encode("ascii"))
        return True
    except Exception:
        return False


def handle(event: dict, budget: int = SCAN_MAX, deadline_s: float = DEADLINE_S) -> dict | None:
    """The hook's JSON answer for one PostToolUse event, or None when there is nothing to say."""
    if "tool_response" not in event:
        return None
    w = Walker(budget, deadline_s)
    new = w.walk(event.get("tool_response"))
    if not w.found and not w.withheld:
        return None
    src = source_of(event)
    tool = redact(str(event.get("tool_name") or "tool"), 80)
    types = sorted({m.kind for m in w.found})
    parts = []
    if w.found:
        parts.append(f"Secret shield withheld {len(w.found)} secret value(s) of type {', '.join(types)} from the output "
                     f"of {tool} ({src}). Each value was replaced with a [REDACTED by secret shield: type] marker before "
                     "it reached you. Stop here: do not try to read, print, decode or use the secret another way. Tell "
                     "the user which file or command holds it, that it may need rotating, and ask how to continue.")
    if w.withheld:
        parts.append(f"{w.withheld} characters of this output were withheld because they were beyond what the shield "
                     "can scan in one call. Read a smaller part (an offset and limit, or head/tail) if you need it.")
    reason = " ".join(parts)
    audit(event, "withheld" if w.found else "withheld-unscanned", w.found, w.withheld)
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": new}}


def hook_main() -> int:
    try:
        raw = sys.stdin.buffer.read(64_000_000).decode("utf-8", "replace")
        event = json.loads(raw)
        if not isinstance(event, dict):
            return 0
    except Exception:
        return 0           # malformed input: there is no output we could replace
    try:
        answer = handle(event)
    except Exception as e:  # fail open, but say so: a broken redactor cannot be trusted with a replacement
        audit(event, "error", [])
        msg = (f"Secret shield could not check the output of {source_of(event)} ({type(e).__name__}). If it may contain "
               "credentials, do not repeat or use them; tell the user.")
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": msg}}))
        return 0
    if answer:
        sys.stdout.write(json.dumps(answer, ensure_ascii=True))
    return 0


# ---------------------------------------------------------------------------------------------------- sweep

SWEEP_EXT = {".jsonl", ".json", ".log", ".txt", ".out", ".err"}
SWEEP_SKIP = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", "target"}
LINE_CHUNK = 4_000_000
FILE_MAX = 512_000_000


def claude_projects_dir() -> str:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    return os.path.join(base, "projects")


def _is_link(p: str) -> bool:
    try:
        st = os.lstat(p)
    except OSError:
        return True
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def sweep_files(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        if _is_link(p):
            continue
        if os.path.isfile(p):
            out.append(p)
            continue
        for r, ds, fs in os.walk(p):
            ds[:] = sorted(d for d in ds if d not in SWEEP_SKIP and not _is_link(os.path.join(r, d)))
            for f in sorted(fs):
                fp = os.path.join(r, f)
                if os.path.splitext(f)[1].lower() in SWEEP_EXT and not _is_link(fp):
                    out.append(fp)
    return out


def default_targets(cwd: str) -> list[str]:
    t = []
    proj = claude_projects_dir()
    if os.path.isdir(proj):
        t.append(proj)
    for name in ("logs", "log", "storage/logs", "var/log"):
        p = os.path.join(cwd, name)
        if os.path.isdir(p):
            t.append(p)
    try:
        t += [os.path.join(cwd, f) for f in sorted(os.listdir(cwd)) if f.lower().endswith((".log", ".out"))]
    except OSError:
        pass
    return t


def sweep(paths: list[str]) -> list[dict]:
    hits = []
    for fp in sweep_files(paths):
        try:
            if os.path.getsize(fp) > FILE_MAX:
                hits.append({"file": fp, "line": 0, "type": "not-scanned", "severity": "info",
                             "preview": f"file larger than {FILE_MAX // 1_000_000} MB, not scanned"})
                continue
            with open(fp, "r", encoding="utf-8", errors="replace", newline="") as fh:
                line_no, seen = 1, set()
                while True:
                    chunk = fh.readline(LINE_CHUNK)
                    if not chunk:
                        break
                    for m in find_secrets(chunk):
                        sig = (m.kind, m.value)
                        if sig in seen:
                            continue      # the same secret repeats on many transcript lines; report its first one
                        seen.add(sig)
                        hits.append({"file": fp, "line": line_no, "type": m.kind, "severity": m.severity,
                                     "example": m.example, "preview": mask(m)})
                    if chunk.endswith("\n"):
                        line_no += 1
        except OSError as e:
            hits.append({"file": fp, "line": 0, "type": "unreadable", "severity": "info", "preview": type(e).__name__})
    return hits


def _safe(s: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]", "?", str(s))


def sweep_main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="secret_shield.py sweep",
                                 description="List secrets that already leaked into agent transcripts and logs (read only).")
    ap.add_argument("paths", nargs="*", help="files or folders; default: Claude Code transcripts and this project's logs")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--include-examples", action="store_true", help="also list documentation example keys (LOW)")
    a = ap.parse_args(argv)
    targets = a.paths or default_targets(os.getcwd())
    hits = sweep(targets)
    if not a.include_examples:
        hits = [h for h in hits if not h.get("example")]
    live = [h for h in hits if h["severity"] in ("critical", "high", "medium")]
    if a.json:
        print(json.dumps({"targets": targets, "findings": hits,
                          "revoke": {k: REVOKE[k] for k in sorted({h["type"] for h in live}) if k in REVOKE}}, indent=2))
        return 1 if live else 0
    print("=== SHIELD SWEEP (read only) ===")
    for t in targets:
        print(_safe(f"Scanned: {t}"))
    if not targets:
        print("Nothing to scan: no transcripts folder and no logs found. Pass a path.")
    for h in hits:
        print(_safe(f"[{h['severity'].upper()}] {h['type']} {h['file']}:{h['line']}  {h['preview']}"))
    if live:
        print("\nHow to revoke what was found:")
        for k in sorted({h["type"] for h in live}):
            if k in REVOKE:
                print(_safe(f"- {k}: {REVOKE[k]}"))
        print("- After revoking: these files still hold the old values. This sweep never edits them; delete or redact "
              "the listed transcript and log files yourself once the secrets are revoked.")
        print(f"RESULT: {len(live)} leaked value(s) found, revoke them")
        return 1
    print("RESULT: nothing leaked was found")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "sweep":
        return sweep_main(argv[1:])
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    return hook_main()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
