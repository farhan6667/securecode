#!/usr/bin/env python3
"""Org AI agent guard (Claude Code PreToolUse hook).

Protects the developer's machine and secrets from the AI agent itself:
- blocks reading secret files (.env*, private keys, cloud and agent credentials); shell commands
  that only mention a secret file without reading it are sent to the user as "ask"
- blocks pipe-to-shell installs, force pushes, hard resets, root/home deletes, public repo
  creation and writes to shell startup files
- strict mode (opt-in per project, when a claude_docs/ folder exists): only CLAUDE.md,
  AGENTS.md and claude_docs/ may be read or written as Markdown instruction sources

Exit 2 blocks the call and shows stderr to the agent. "ask" is returned as PreToolUse JSON.
Fails closed: malformed input, internal errors and over-long commands exit 2. All checks are
linear-time (no backtracking-heavy regexes) so the hook cannot be pushed past its timeout.
Rules are documented in docs/AI-AGENT-SECURITY.md.
"""
from __future__ import annotations
import fnmatch, json, os, re, sys
from pathlib import PurePath

MAX_COMMAND = 20_000
SAFE_ENV = re.compile(r"^\.env\.(example|sample|template|dist)$", re.I)
ENV_FILE = re.compile(r"^\.env([._-].*)?$", re.I)
CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java", ".kt", ".cs", ".rs", ".swift", ".vue")
KEY_NAMES = {".git-credentials", ".netrc", ".pgpass", "auth.json", "credentials.json", ".credentials.json", "service-account.json"}
KEY_PREFIX = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")      # id_ed25519_work too; .pub is public
KEY_SUFFIX = (".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".ppk")
# Tool credential stores: often hold tokens, sometimes only settings, so these are "ask", not deny.
ASK_FILES = {".npmrc", ".pypirc", ".yarnrc.yml"}
ASK_IN_DIR = {(".docker", "config.json"), (".kube", "config"), ("gh", "hosts.yml"), (".azure", "accesstokens.json")}
STARTUP_NAMES = {".bashrc", ".zshrc", ".profile", ".bash_profile", "microsoft.powershell_profile.ps1", "profile.ps1",
                 "microsoft.powershellise_profile.ps1", "microsoft.vscode_profile.ps1"}
MD = re.compile(r"\.(md|mdx)$", re.I)
APP_FOLDER = "orgaisecureappsec"
# Places the agent must never write to: the user's own Claude config folder (settings, CLAUDE.md, hooks,
# skills), managed settings, the org runtime and its update keys, and the Python startup hooks that every
# hook interpreter loads (.pth, sitecustomize, py.ini). A project's own .claude/settings.json is NOT here:
# that is ordinary repo content, reviewed through git and flagged by the gate.
USER_SEG = r"[^/\\\"'\n|&;<>]+"            # a user name, spaces allowed (C:\Users\John Smith)
USER_HOME = (r"(?:~|\$home|\$\{home[^}]{0,40}\}|\$env:userprofile|\$\{env:userprofile\}|\$env:home|\$\{env:home\}|\$\{?userprofile\}?"
             r"|%userprofile%|%homepath%|\$env:homedrive\$env:homepath|%homedrive%%homepath%"
             r"|(?:\$env:|%)(?:local)?appdata%?[/\\]+\.\.[/\\]+\.\."                 # AppData\Roaming\..\.. is home
             r"|[a-z]:[/\\]+users[/\\]+" + USER_SEG + r"|/c/users/[^/\s\"']+|/home/[^/\s\"']+"
             r"|(?:[/\\]{2}|unc[/\\]+)[^/\\\s\"']+[/\\]+[a-z]\$[/\\]+users[/\\]+" + USER_SEG + r")")   # admin share
# .claude, .claude. (Windows drops the dot) and .claude.json (Claude's own MCP and state file)
CLAUDE_DIR = r"(?:\.claude(?![\w-])|claude~\d)"
PROTECTED = re.compile(USER_HOME + r"[/\\]+" + CLAUDE_DIR + r"|managed-settings\.json|allowed_signers|orgaisecureappsec"
                       r"|orgais~\d|orgai[*?]|site-packages[/\\]+[^\s\"']*\.pth\b|(?<![\w-])sitecustomize\.py|(?<![\w-])usercustomize\.py"
                       r"|\bpy\.ini\b", re.I)
# The same without a repo's own allowed_signers file, which git may add and commit like any other file.
HOME_PROTECTED = re.compile(USER_HOME + r"[/\\]+" + CLAUDE_DIR + r"|managed-settings\.json|orgaisecureappsec|orgais~\d|orgai[*?]", re.I)
# A relative .claude folder, which only matters when the shell is already in the home folder.
REL_CLAUDE = re.compile(r"(?:^|[\s\"'=(/\\])(?:\.[/\\])?" + CLAUDE_DIR, re.I)
CD_VERBS = {"cd", "chdir", "pushd", "set-location", "sl", "push-location"}
# Shell commands that only read. Anything else that names a protected place is refused.
READ_ONLY = {"cat", "type", "get-content", "gc", "ls", "dir", "get-childitem", "gci", "head", "tail", "more", "less", "grep",
             "egrep", "fgrep", "rg", "findstr", "select-string", "sls", "test-path", "stat", "wc", "diff", "fc", "echo",
             "get-item", "gi", "resolve-path", "pwd", "tree", "jq", "file", "md5sum", "sha256sum", "get-filehash",
             "convertfrom-json", "select-object", "where-object", "foreach-object", "sort-object", "measure-object",
             "out-string", "format-list", "format-table", "sort", "uniq", ""}
GIT_READ_ONLY = {"status", "log", "diff", "show", "blame", "rev-parse", "ls-files", "grep", "describe", "shortlog", "cat-file", ""}
INTERPRETERS = {"py", "python", "python3", "pythonw", "node", "deno", "bun", "perl", "ruby", "php", "pwsh", "powershell", "cmd", "sh", "bash"}
WRITE_VERBS = {"rm", "del", "erase", "rd", "rmdir", "mv", "move", "cp", "copy", "xcopy", "robocopy", "tee", "sed", "dd", "truncate",
               "remove-item", "ri", "move-item", "mi", "copy-item", "cpi", "rename-item", "ren", "set-content", "sc", "add-content", "ac",
               "out-file", "new-item", "ni", "clear-content", "set-itemproperty", "icacls", "takeown", "attrib", "chmod", "ln", "mklink"}
# a redirect into a file (not 2>&1, not >$null / >nul / >/dev/null, not "->")
REDIRECT = re.compile(r"(?<![-=>])>{1,2}\|?(?!&\s*\d)&?\s*(?!\$null\b|nul\b|/dev/null\b)[^\s\d-]", re.I)
SAMPLE_SECRETS = (".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "credentials")

# Shell words that print or ship file contents. A secret path next to one of these is a hard block.
READERS = {"cat", "type", "get-content", "gc", "more", "less", "head", "tail", "grep", "egrep", "fgrep", "rg",
           "findstr", "select-string", "sls", "sed", "awk", "strings", "base64", "xxd", "od", "nl", "bat",
           "source", ".", "certutil", "openssl", "import-csv", "get-item", "format-hex"}
EXFIL = {"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "scp", "rsync", "nc", "ncat",
         "ftp", "sftp", "gh", "gsutil", "aws", "az"}
DOWNLOADERS = {"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "iex", "invoke-expression", "pwsh", "powershell", "python", "python3", "node"}
RM_TARGETS = {"/", "/*", "~", "~/", "~/*", "$home", "$home/", "$home/*", "*", "/."}
WRITERS = {"tee", "add-content", "set-content", "out-file", "ac", "sc"}

SPLIT_STMT = re.compile(r"&&|\|\||;|(?<![>&])&(?![>&])|\n")   # a lone & splits; >& and &> are redirects
WORD = re.compile(r"[^\s|]+")
PATHISH = re.compile(r"[^\s'\"=,;()<>@`|&:]+")
GLOB_SECRET = re.compile(r"(^|[\s/\\'\"=({,])\.e(n(v)?)?[*?\[{]|\{[^}\s]{0,200}\.env\b|\.\{[^}\s]{0,200}env\b|\.ssh[/\\][*?\[{]", re.I)


def canon_path(p: str) -> str:
    """\\\\?\\C:\\x -> C:\\x and \\\\host\\c$\\x -> c:\\x, so device and admin-share paths meet the same checks."""
    s = re.sub(r"^[/\\]{2}[?.][/\\](unc[/\\])?", lambda m: "\\\\" if m.group(1) else "", str(p), flags=re.I)
    s = re.sub(r"^file:/{2,3}", "", s, flags=re.I)
    return re.sub(r"^[/\\]{2}[^/\\]+[/\\]+([a-z])\$(?=[/\\]|$)", r"\1:", s, flags=re.I)


def _collapse_token(t: str) -> str:
    out: list[str] = []
    for i, seg in enumerate(re.split(r"[/\\]+", t)):
        if seg == "." and i:
            continue
        if seg == ".." and out and out[-1] not in ("", "..", "~"):
            out.pop()
            continue
        out.append(seg)
    return "/".join(out)


def collapse(s: str) -> str:
    """Drop /./ and dir/../ so ~/./.claude and AppData/../.claude show their real target. Linear time:
    one pass over each whitespace or quote separated token."""
    return "".join(p if not ("." in p and ("/" in p or "\\" in p)) else _collapse_token(p)
                   for p in re.split(r"([\s\"'=]+)", s))


def cmd_name(w: str) -> str:
    n = PurePath(w.replace("\\", "/")).name.lower()
    return re.sub(r"\.(exe|cmd|bat|com)$", "", n)


def clean_name(p: str) -> str:
    base = PurePath(str(p).replace("\\", "/")).name if str(p) else ""
    base = base.split(":", 1)[0]          # NTFS alternate data streams: .env::$DATA
    return base.rstrip(". ")              # Windows ignores trailing dots and spaces


def is_secret_path(p: str) -> bool:
    base = clean_name(p)
    if not base:
        return False
    low = base.lower()
    if SAFE_ENV.match(base) or low.endswith(CODE_EXT):
        return False
    if re.fullmatch(r"(env\w{0,4}|id_\w{0,4}|git-cr|creden|servic|accoun)~\d+(\.\w{1,3})?", low):   # 8.3 short names
        return True
    if ENV_FILE.match(base) or (low.endswith(".env") and len(low) > 4 and not low.endswith(("process.env", "meta.env"))):  # secrets.env, prod.env
        return True
    if low in KEY_NAMES or low.endswith(KEY_SUFFIX) or (low.startswith(KEY_PREFIX) and not low.endswith(".pub")):
        return True
    if any(c in base for c in "*?[") and base[0] in ".?[" and any(fnmatch.fnmatchcase(s, low) for s in SAMPLE_SECRETS):
        return True   # globs that expand to a secret: .env*, ?env, .[e]nv, .en?
    parts = [x.lower() for x in PurePath(str(p).replace("\\", "/")).parts]
    return low == "credentials" and ".aws" in parts


def is_ask_path(p: str) -> bool:
    parts = [x.lower() for x in PurePath(str(p).replace("\\", "/")).parts]
    if not parts:
        return False
    return clean_name(p).lower() in ASK_FILES or (len(parts) >= 2 and (parts[-2], parts[-1]) in ASK_IN_DIR)


def rel_in_project(p: str, project: str) -> str | None:
    abs_p = os.path.normcase(os.path.abspath(os.path.join(project, str(p))))
    root = os.path.normcase(os.path.abspath(project))
    try:
        rel = os.path.relpath(abs_p, root)
    except ValueError:  # different drive on Windows
        return None
    if rel == ".." or rel.startswith(".." + os.sep) or os.path.isabs(rel):
        return None
    return rel.replace(os.sep, "/")


def words_of(text: str) -> list[str]:
    return [w.strip("'\"`()").lower() for w in WORD.findall(text)]


def first_word(words: list[str]) -> str:
    in_cmd = False
    for k, w in enumerate(words):
        if w in ("sudo", "env", "command", "&", "call", "=") or re.match(r"^[a-z_][a-z0-9_]*=", w):
            continue
        if re.fullmatch(r"\$[\w:]+", w) and words[k + 1:k + 2] == ["="]:   # PowerShell: $x = (Get-Content ...)
            continue
        w = re.split(r"[()]", w)[0] or w
        if cmd_name(w) == "cmd":              # cmd /c gh ... : judge the command cmd runs
            in_cmd = True
            continue
        if in_cmd and re.fullmatch(r"/[a-z]", w):
            continue
        return cmd_name(w)
    return ""


def long_opt(a: str, *full: str) -> bool:
    """git accepts any unique prefix of a long option (--del for --delete, --har for --hard)."""
    base = a.split("=", 1)[0]
    return len(base) >= 4 and base.startswith("--") and any(f.startswith(base) for f in full)


def git_rule(words: list[str], text: str, ctx: dict):
    """Force pushes, hard resets, aliases for them, and git writing into protected places. Only the first git
    in a statement is the command; later ones are arguments (git commit -m "never git push --force")."""
    i = next((k for k, w in enumerate(words) if cmd_name(w) == "git"), None)
    if i is None:
        return None
    no_write = ("deny", "git may not change files inside the agent's own Claude config, the org runtime or its update keys.")
    rest, sub, j, home_opt = words[i + 1:], "", 0, False
    while j < len(rest):                      # global options: -c k=v, -C dir, --git-dir=x, --work-tree x ...
        r = rest[j]
        if r in ("-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"):
            val = rest[j + 1] if j + 1 < len(rest) else ""
            if HOME_PROTECTED.search(collapse(val)):
                return no_write
            # words are lowercased, so -C (directory) arrives as -c; a home path is never a config key
            home_opt = home_opt or (r in ("-c", "-C", "--work-tree") and bool(re.fullmatch(USER_HOME + r"[/\\]*", collapse(val), re.I)))
            j += 2
            continue
        if r.startswith("-"):
            if "=" in r:
                val = r.split("=", 1)[1]
                if HOME_PROTECTED.search(collapse(val)):
                    return no_write
                home_opt = home_opt or (r.startswith(("--work-tree", "--git-dir")) and
                                        bool(re.fullmatch(USER_HOME + r"[/\\]*", collapse(val), re.I)))
            j += 1
            continue
        sub = r
        break
    after = rest[j + 1:]
    if any(w.startswith("alias.") and re.search(r"\b(push|reset)\b|!", " ".join(rest)) for w in rest):
        return "deny", "git aliases for push or reset (or shell aliases) are not allowed from the agent; ask the user."
    if sub == "push" and any(long_opt(a, "--force", "--force-with-lease", "--force-if-includes", "--mirror", "--delete", "--prune")
                             or (re.fullmatch(r"-[a-z]+", a) and set(a[1:]) & {"f", "d"})
                             or (a[:1] in "+:" and len(a) > 1) for a in after):
        return "deny", "force, mirror or delete pushes are not allowed; ask the user to do it themselves."
    if sub == "reset" and any(long_opt(a, "--hard") for a in after):
        return "deny", "git reset --hard discards work; ask the user first."
    writes_file = any(a.startswith("--output") or a == "-o" for a in after)    # git diff --output=x, git archive -o x
    if (sub not in GIT_READ_ONLY or writes_file) and (ctx.get("protected") or HOME_PROTECTED.search(text) or HOME_PROTECTED.search(collapse(text))
                                     or ((home_opt or ctx.get("home")) and REL_CLAUDE.search(" ".join(after)))):
        return no_write
    return None


def gh_rule(words: list[str]):
    for i, w in enumerate(words):
        if cmd_name(w) != "gh":
            continue
        rest = words[i + 1:]
        public = any(a == "--public" or (a.startswith("--public=") and a.split("=", 1)[1] not in ("false", "0")) for a in rest)
        vis = any(a == "--visibility=public" or (a == "--visibility" and rest[k + 1:k + 2] == ["public"]) for k, a in enumerate(rest))
        if ("repo" in rest and "create" in rest and public) or ("repo" in rest and "edit" in rest and vis) or \
           ("api" in rest and any(x in a for a in rest for x in ("private=false", "private:false", "visibility=public",
                                                                  "visibility:public", "visibility:\\\"public"))):
            return "deny", "creating or opening a public repo is not allowed from the agent; ask the user (known exfiltration route)."
    return None


def redirect_targets(plain: str) -> list[str]:
    found = [m.group(1) for m in re.finditer(r"(?<![-=>])>{1,2}\|?&?\s*([^\s|;&<>]+)", plain)]
    return [t for t in found if not re.fullmatch(r"\d+|-", t)]


def check_statement(stmt: str, ctx: dict | None = None):
    """Returns (decision, reason) for one shell statement, or None. ctx carries the shell's folder
    between statements (cd ~ && cp x .claude/...)."""
    ctx = ctx if ctx is not None else {}
    pipe_parts = stmt.split("|")
    plain = re.sub(r"[\"'`^]", "", stmt)                       # settings.jso"n" -> settings.json, g''it -> git
    unesc = re.sub(r"\\(?=[a-z0-9])", "", plain, flags=re.I)  # .e\nv -> .env (bash escapes)
    norm = collapse(plain)
    words = words_of(stmt)
    pwords = words_of(plain)
    fw = first_word(pwords)
    heads = [first_word(words_of(re.sub(r"[\"'`^]", "", p))) for p in pipe_parts]

    if fw in CD_VERBS:
        k = next(n for n, w in enumerate(pwords) if cmd_name(w) == fw)
        target = next((w for w in pwords[k + 1:] if not w.startswith("-") and w.lower() != "/d"), "~")
        follow_cd(ctx, target)
        return None

    low = stmt.lower()
    # Download-and-run in all its usual shapes: pipe, process substitution, $(...), iex (...).
    for i, h in enumerate(heads):
        if h in DOWNLOADERS and any(x in SHELLS for x in heads[i + 1:]):
            return "deny", "piping a download into a shell is not allowed; download, read, then run."
    if re.search(r"<\(\s*(curl|wget)\b|\$\(\s*(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b", low) and \
       (fw in SHELLS or any(w in SHELLS for w in words)):
        return "deny", "running a downloaded script is not allowed; download, read, then run."
    if re.search(r"\b(iex|invoke-expression)\b", low) and (re.search(r"\b(iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod)\b", low)
                                                         or "downloadstring" in low or "downloadfile" in low):
        return "deny", "running a downloaded script is not allowed; download, read, then run."
    if re.search(r"\b(powershell|pwsh)(\.exe)?\b[^|;]*\s-(e|ec|en|enc|enco\w*|encodedcommand)\s+[a-z0-9+/=]{16,}", low):
        return "deny", "encoded PowerShell commands cannot be checked; run the plain command instead."
    r = git_rule(pwords, plain, ctx) or gh_rule(pwords)
    if r:
        return r
    # Links and drive letters that point at the home folder make every later path check blind.
    if (fw in ("ln", "mklink", "subst", "junction") or (fw in ("new-item", "ni") and re.search(r"symboliclink|junction|hardlink", low))) \
            and (re.search(USER_HOME + r"(?:[/\\]+|[\s\"']|$)", plain, re.I) or HOME_PROTECTED.search(norm)):
        return "deny", "links or drive letters that point at the home folder are not allowed from the agent; ask the user."
    if fw == "rm" and any(w.startswith("-") and ("r" in w.lstrip("-") or w == "--recursive") for w in words):
        if any(dangerous_target(w) for w in words[1:] if not w.startswith("-")):
            return "deny", "recursive delete of a drive, root, home or wildcard path is not allowed."
    if fw in ("remove-item", "ri", "rmdir", "rd", "del", "erase") and any(w in ("-recurse", "/s", "-r") for w in words):
        if any(dangerous_target(w) for w in words[1:] if not w.startswith(("-", "/s", "/q"))):
            return "deny", "recursive delete of a drive root or home folder is not allowed."
    # The agent's own settings, the org runtime and the update trust anchor: read-only from the shell.
    # git is judged by git_rule above (it may add or commit a repo's own allowed_signers file), except
    # that a redirect into a protected place is refused for every command.
    deny_protected = ("deny", "the agent may not change its own Claude settings, the org security runtime, its update keys "
                      "or Python startup files.")
    targets = redirect_targets(plain)
    if any(PROTECTED.search(collapse(canon_path(t))) for t in targets) or (targets and ctx.get("protected")) or \
            (ctx.get("home") and any(REL_CLAUDE.search(" " + t) for t in targets)):
        return deny_protected
    hit = PROTECTED.search(stmt) or PROTECTED.search(norm) or PROTECTED.search(collapse(unesc)) or ctx.get("protected") \
        or (ctx.get("home") and REL_CLAUDE.search(plain))
    # Only plain readers may name a protected place. Every other program (curl -o, tar -C, mkdir, touch,
    # npm --prefix, [IO.File]::WriteAllText, an interpreter) is refused, so new write routes need no new rule.
    readers_only = fw in READ_ONLY and all(h in READ_ONLY for h in heads)    # redirect targets were checked above
    if hit and fw != "git" and not readers_only:
        return deny_protected
    names = [clean_name(c).lower() for c in PATHISH.findall(stmt)]
    if (any(n in STARTUP_NAMES for n in names) or "$profile" in low) and (">" in stmt or fw in WRITERS or any(h in WRITERS for h in heads)):
        return "deny", "writing to shell startup files is not allowed (persistence route)."

    if GLOB_SECRET.search(stmt):
        return "deny", "wildcards next to .env or .ssh are not allowed; name a safe file such as .env.example."
    unquoted = re.sub(r"[\"']", "", stmt)                      # .e""nv -> .env
    squash = re.sub(r"\$\{\w*\}|\$(?=[a-z])|\+", "", plain, flags=re.I)   # .e${X}nv, .e$''nv, ('.e'+'nv') -> .env
    tokens = PATHISH.findall(stmt) + PATHISH.findall(unquoted) + PATHISH.findall(plain) + PATHISH.findall(unesc) + \
        PATHISH.findall(squash)
    secrets = [c for c in tokens if is_secret_path(c)]
    if secrets:
        if fw in ("grep", "egrep", "fgrep", "rg", "findstr", "select-string", "sls"):
            positional = [w for w in words[1:] if not w.startswith("-")]
            if positional and is_secret_path(positional[0]) and len(positional) > 1:
                return "ask", "this search uses a secret file name as its pattern; approve if it only searches source code."
        if fw in READERS or any(h in READERS for h in heads) or any(w in EXFIL for w in words) or "$(" in stmt or "`" in stmt:
            return "deny", "shell commands must not read or send secret files (.env*, private keys, credentials)."
        if re.fullmatch(r"\s*(echo|printf)\s+['\"]?[\w.*/\-]+['\"]?\s*>>?\s*[\w./\\-]*\.(git|docker|npm|eslint|prettier)?ignore\s*", stmt, re.I):
            return None  # e.g. echo .env >> .gitignore (a plain name, nothing expanded)
        if words[:3] == ["git", "rm", "--cached"]:
            return None
        return "ask", f"this command touches a secret file ({secrets[0]}). Approve only if it does not read or expose it."
    if any(is_ask_path(c) for c in tokens):
        return "ask", "this command touches a tool credential file (.npmrc, docker/kube/gh config). Approve only if it does not expose tokens."
    return None


def follow_cd(ctx: dict, target: str) -> None:
    """Track the shell's folder across statements so relative paths are judged where they land."""
    home = os.path.normcase(os.path.expanduser("~"))
    t = collapse(target)
    if re.fullmatch(USER_HOME + r"[/\\]*", t, re.I):
        path = home
    elif re.match(USER_HOME + r"[/\\]+", t, re.I):
        path = None                                  # somewhere below home: judged by PROTECTED on the text
        ctx["protected"] = bool(PROTECTED.search(t))
        ctx["home"] = False
        ctx["path"] = None
        return
    elif ctx.get("path") and not os.path.isabs(t):
        path = os.path.normcase(os.path.normpath(os.path.join(ctx["path"], t)))
    elif os.path.isabs(t):
        path = os.path.normcase(os.path.normpath(t))
    else:
        path = None
    ctx["path"] = path
    ctx["home"] = path == home
    ctx["protected"] = bool(path and PROTECTED.search(path.replace(os.sep, "/") + "/"))


def dangerous_target(w: str) -> bool:
    t = w.strip("'\"").lower().replace("\\", "/")
    t = t[:-1] if t.endswith("*") else t
    t = t.rstrip("/")
    if t.endswith("/."):
        t = t[:-2]
    return t in ("", "~", "$home", "${home}", "$userprofile", "${userprofile}", "$env:userprofile", "%userprofile%",
                 "/mnt/c", "*", ".") and w not in (".", "./") or bool(re.fullmatch(r"[a-z]:|/[a-z]|/mnt/[a-z]", t))


def check(event: dict):
    tool = event.get("tool_name") or ""
    ti = event.get("tool_input") or {}
    if not isinstance(ti, dict):
        return "deny", "the tool input could not be read, so this action cannot be checked safely."
    project = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()

    # Every argument that names a file, whatever the tool calls it (MCP servers use their own keys).
    paths = []
    for k, v in ti.items():
        if not re.search(r"(path|file|dir|dest|target|output|source|uri)", str(k), re.I) or re.search(r"(content|text|data)", str(k), re.I):
            continue
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str) and x and len(x) < 4096 and "\n" not in x:
                paths.append(canon_path(x))
    if any(is_secret_path(p) for p in paths):
        return "deny", "secret files (.env, keys, credentials) must not be read or edited. Use .env.example or ask the user."
    if any(is_ask_path(p) for p in paths):
        return "ask", "this is a tool credential file (.npmrc, docker/kube/gh config); approve only if needed."
    if tool in ("Edit", "Write", "MultiEdit") and any(clean_name(p).lower() in STARTUP_NAMES for p in paths):
        return "deny", "editing shell startup files is not allowed (persistence route); ask the user."
    writes = tool in ("Edit", "Write", "MultiEdit", "NotebookEdit") or (
        tool.startswith("mcp__") and re.search(r"(write|edit|move|rename|create|delete|remove|copy|upload|append|patch|put)", tool, re.I))
    if writes:
        home = os.path.normcase(os.path.expanduser("~"))
        for p in paths:
            n = os.path.normcase(os.path.abspath(os.path.expanduser(p)))
            user_claude = n.startswith(os.path.join(home, ".claude") + os.sep) or n == os.path.join(home, ".claude") or \
                bool(re.match(re.escape(os.path.join(home, "claude~")) + r"\d", n))
            if PROTECTED.search(p) or PROTECTED.search(n.replace(os.sep, "/")):
                if user_claude and not tool.startswith("mcp__") and re.search(r"[/\\](settings(\.local)?\.json|claude\.md)$", n, re.I):
                    return "ask", "this changes your global Claude settings or rules; approve only if you asked for it."
                return "deny", "the agent may not change its own Claude config, the org security runtime, its update keys or Python startup files."
            if user_claude:
                return "ask", "this changes your global Claude configuration; approve only if you asked for it."

    if tool == "Grep":
        g = str(ti.get("glob") or "")
        if GLOB_SECRET.search(g) or any(is_secret_path(x) for x in re.split(r"[,{}\s]", g) if x):
            return "deny", "searching secret files is not allowed."

    # Bash, PowerShell, Monitor and any other tool that takes a shell command.
    if tool in ("Bash", "PowerShell") or isinstance(ti.get("command"), str):
        cmd = str(ti.get("command") or "")
        if len(cmd) > MAX_COMMAND:
            return "deny", f"command is longer than {MAX_COMMAND} characters and cannot be checked safely; split it or put it in a script file."
        start = os.path.normcase(os.path.abspath(str(event.get("cwd") or os.getcwd())))
        home = os.path.normcase(os.path.expanduser("~"))
        ctx = {"home": start == home, "path": start, "protected": bool(PROTECTED.search(start.replace(os.sep, "/") + "/"))}
        asked = None
        for stmt in SPLIT_STMT.split(cmd):
            r = check_statement(stmt, ctx)
            if r and r[0] == "deny":
                return r
            asked = asked or r
        if asked:
            return asked

    # Strict instruction-source mode, only for projects that opted in with a claude_docs/ folder.
    if tool in ("Read", "Edit", "Write", "MultiEdit") and os.path.isdir(os.path.join(project, "claude_docs")):
        fp = ti.get("file_path")
        if isinstance(fp, str) and MD.search(fp):
            rel = rel_in_project(fp, project)
            if rel is not None and rel.lower() not in ("claude.md", "agents.md") and not rel.lower().startswith("claude_docs/"):
                return "deny", (f"{rel} is not an instruction source in this project. Only CLAUDE.md, AGENTS.md and "
                                "claude_docs/ may be used; list other docs in claude_docs/IGNORED_FILES.md and ask the user.")
    return None


def main() -> int:
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
        result = check(event)
    except Exception as e:
        sys.stderr.write(f"Blocked by Org AI agent guard: could not check this action safely ({type(e).__name__}).\n")
        return 2
    if not result:
        return 0
    decision, reason = result
    if decision == "ask":
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                                 "permissionDecisionReason": f"Org AI agent guard: {reason}"}}))
        return 0
    sys.stderr.write(f"Blocked by Org AI agent guard: {reason}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
