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

Policy modes (config/guard-policy.json next to this runtime, see load_policy): "owner" turns the
destructive and exposure classes (force push, hard reset, force branch delete, public repo or gist,
package publish) into an "ask" that shows the literal command; "managed" denies them. A missing,
unreadable or malformed policy, or a managed install on the machine, means "managed". Secrets,
pipe-to-shell and writes to the agent's own config never become an "ask".
"""
from __future__ import annotations
import fnmatch, json, os, re, stat, sys, time
from pathlib import Path, PurePath
from urllib.parse import unquote

MAX_COMMAND = 20_000
SAFE_ENV = re.compile(r"^\.env\.(example|sample|template|dist)$", re.I)
ENV_FILE = re.compile(r"^\.env([._-].*)?$", re.I)
CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java", ".kt", ".cs", ".rs", ".swift", ".vue")
KEY_NAMES = {".git-credentials", ".netrc", ".pgpass", "auth.json", "credentials.json", ".credentials.json", "service-account.json",
             ".envrc", "application_default_credentials.json"}
KEY_PREFIX = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")      # id_ed25519_work too; .pub is public
KEY_SUFFIX = (".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".ppk")
# Real secret file names a wildcard may expand to (cat ~/.ssh/id*, Get-Content *env, cat ~/.aws/cred*).
SECRET_SAMPLES = (".env", ".env.local", ".env.production", ".envrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                  "credentials", ".git-credentials", ".netrc", ".pgpass", "credentials.json", ".credentials.json",
                  "service-account.json", "application_default_credentials.json")
GLOB_CHARS = re.compile(r"[*?\[]")
# Tool credential stores: often hold tokens, sometimes only settings, so these are "ask", not deny.
ASK_FILES = {".npmrc", ".pypirc", ".yarnrc.yml"}
ASK_IN_DIR = {(".docker", "config.json"), (".kube", "config"), ("gh", "hosts.yml"), (".azure", "accesstokens.json")}
STARTUP_NAMES = {".bashrc", ".zshrc", ".profile", ".bash_profile", ".bash_login", ".bash_logout", ".zshenv", ".zprofile",
                 ".zlogin", ".zlogout", ".kshrc", ".mkshrc", ".cshrc", ".tcshrc", ".login", ".xprofile",
                 "microsoft.powershell_profile.ps1", "profile.ps1",
                 "microsoft.powershellise_profile.ps1", "microsoft.vscode_profile.ps1"}
MD = re.compile(r"\.(md|mdx)$", re.I)
APP_FOLDER = "orgaisecureappsec"
# Places the agent must never write to: the user's own Claude config folder (settings, CLAUDE.md, hooks,
# skills), managed settings, the org runtime and its update keys, and the Python startup hooks that every
# hook interpreter loads (.pth, sitecustomize, py.ini). A project's own .claude/settings.json is NOT here:
# that is ordinary repo content, reviewed through git and flagged by the gate.
USER_SEG = r"[^/\\\"'\n|&;<>]+"            # a user name, spaces allowed (C:\Users\John Smith)
# Optional drive in front of \Users: C:, /c (Git Bash), /mnt/c (WSL), $env:SystemDrive, %SystemDrive%. With no
# drive at all, \Users\x is root-relative on Windows and /Users/x is the macOS home.
SYS_DRIVE = r"(?:[a-z]:|/mnt/[a-z]|/[a-z](?=[/\\])|\$env:systemdrive|\$\{env:systemdrive\}|%systemdrive%)?"
USER_HOME = (r"(?:~[\w.-]{0,64}|\$home|\$\{home[^}]{0,40}\}|\$env:userprofile|\$\{env:userprofile\}|\$env:home|\$\{env:home\}"
             r"|\$\{?userprofile\}?|%userprofile(?::[^%\s]{0,40})?%|%homepath%|\$env:homedrive\$env:homepath|%homedrive%%homepath%"
             r"|(?:\$env:|%)(?:local)?appdata%?[/\\]+\.\.[/\\]+\.\."                 # AppData\Roaming\..\.. is home
             r"|" + SYS_DRIVE + r"[/\\]+(?:users|documents and settings)[/\\]+" + USER_SEG +
             r"|/home/[^/\s\"']+|/root(?=[/\\]|$)|/var/root(?=[/\\]|$)"
             r"|(?:[/\\]{2}|unc[/\\]+)[^/\\\s\"']+[/\\]+[a-z]\$[/\\]+users[/\\]+" + USER_SEG + r")")   # admin share
# .claude, .claude. (Windows drops the dot) and .claude.json (Claude's own MCP and state file)
CLAUDE_DIR = r"(?:\.claude(?![\w-])|claude~\d)"
PROTECTED = re.compile(USER_HOME + r"[/\\]+" + CLAUDE_DIR + r"|managed-settings\.json|allowed_signers|orgaisecureappsec"
                       r"|orgais~\d|orgai[*?]|site-packages[/\\]+[^\s\"']*\.pth\b|(?<![\w-])sitecustomize\.py|(?<![\w-])usercustomize\.py"
                       r"|\bpy\.ini\b|(?<![\w-])guard-policy\.json|(?<![\w-])guard-audit\.jsonl", re.I)
# The same without a repo's own allowed_signers file, which git may add and commit like any other file.
HOME_PROTECTED = re.compile(USER_HOME + r"[/\\]+" + CLAUDE_DIR + r"|managed-settings\.json|orgaisecureappsec|orgais~\d|orgai[*?]", re.I)
# A relative .claude folder, which only matters when the shell is already in the home folder.
REL_CLAUDE = re.compile(r"(?:^|[\s\"'=(/\\])(?:\.[/\\])?" + CLAUDE_DIR, re.I)
CD_VERBS = {"cd", "chdir", "pushd", "set-location", "sl", "push-location"}
# Shell commands that only read. Anything else that names a protected place is refused. Nothing here may run
# code or write a file: ForEach-Object and Where-Object run script blocks, sort -o and uniq write their output
# file, tree /a > x is caught as a redirect but tree has no reason to be trusted. find is a reader only without
# its action flags (see reads_only).
READ_ONLY = {"cat", "type", "get-content", "gc", "ls", "dir", "get-childitem", "gci", "head", "tail", "more", "less", "grep",
             "egrep", "fgrep", "rg", "findstr", "select-string", "sls", "test-path", "stat", "wc", "diff", "fc", "echo",
             "get-item", "gi", "resolve-path", "pwd", "jq", "file", "md5sum", "sha256sum", "get-filehash",
             "convertfrom-json", "select-object", "sort-object", "measure-object",
             "out-string", "format-list", "format-table", ""}
FIND_ACTIONS = re.compile(r"(?:^|\s)-(?:delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)\b", re.I)
# Method calls, static .NET calls, command substitution and rg --pre turn any reader into a writer:
# (Get-Item x).Delete(), [IO.File]::WriteAllText, echo $(cp ...), rg --pre "sh -c ...".
CODE_IN_STMT = re.compile(r"\)\s*\.\s*[a-z_]\w*\s*\(|\]::|\$\(|`|<\(|--pre\b", re.I)
# PowerShell runs a { script block } handed to any cmdlet (Select-Object @{e={...}}, delay-bind -Path {...}).
PS_ALIASES = {"gc", "gci", "gi", "sls", "dir", "type"}
GIT_READ_ONLY = {"status", "log", "diff", "show", "blame", "rev-parse", "ls-files", "grep", "describe", "shortlog", "cat-file", ""}
INTERPRETERS = {"py", "python", "python3", "pythonw", "node", "deno", "bun", "perl", "ruby", "php", "pwsh", "powershell", "cmd", "sh", "bash",
                "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "lua", "tclsh", "osascript", "rscript", "irb", "jshell"}
WRITE_VERBS = {"rm", "del", "erase", "rd", "rmdir", "mv", "move", "cp", "copy", "xcopy", "robocopy", "tee", "sed", "dd", "truncate",
               "remove-item", "ri", "move-item", "mi", "copy-item", "cpi", "rename-item", "ren", "set-content", "sc", "add-content", "ac",
               "out-file", "new-item", "ni", "clear-content", "set-itemproperty", "icacls", "takeown", "attrib", "chmod", "ln", "mklink"}
# a redirect into a file (not 2>&1, not >$null / >nul / >/dev/null, not "->")
REDIRECT = re.compile(r"(?<![-=>])>{1,2}\|?(?!&\s*\d)&?\s*(?!\$null\b|nul\b|/dev/null\b)[^\s\d-]", re.I)

# Shell words that print or ship file contents. A secret path next to one of these is a hard block.
READERS = {"cat", "type", "get-content", "gc", "more", "less", "head", "tail", "grep", "egrep", "fgrep", "rg",
           "findstr", "select-string", "sls", "sed", "awk", "strings", "base64", "xxd", "od", "nl", "bat",
           "source", ".", "certutil", "openssl", "import-csv", "get-item", "format-hex"}
EXFIL = {"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "scp", "rsync", "nc", "ncat",
         "ftp", "sftp", "gh", "gsutil", "aws", "az"}
DOWNLOADERS = {"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "iex", "invoke-expression", "pwsh", "powershell", "python", "python3", "node"}
# Anything that runs what it is given: every interpreter, every shell, and source or . on stdin.
SINKS = INTERPRETERS | SHELLS | {"source", "."}
# Programs that only start the next word as a command (curl x | exec sh, | xargs -0 bash -c, | timeout 60 zsh).
WRAPPERS = {"exec", "xargs", "nohup", "timeout", "env", "sudo", "doas", "nice", "ionice", "stdbuf", "command", "builtin", "time",
            "setsid", "unbuffer", "chronic", "then", "do", "else", "eval", "busybox", "su", "runuser", "&", "call"}
RM_TARGETS = {"/", "/*", "~", "~/", "~/*", "$home", "$home/", "$home/*", "*", "/."}
WRITERS = {"tee", "add-content", "set-content", "out-file", "ac", "sc"}

SPLIT_STMT = re.compile(r"&&|\|\||;|(?<![>&])&(?![>&])|\n")   # a lone & splits; >& and &> are redirects
WORD = re.compile(r"[^\s|]+")
PATHISH = re.compile(r"[^\s'\"=,;()<>@`|&:]+")
GLOB_SECRET = re.compile(r"(^|[\s/\\'\"=({,])\.e(n(v)?)?[*?\[{]|\{[^}\s]{0,200}\.env\b|\.\{[^}\s]{0,200}env\b|\.ssh[/\\][*?\[{]", re.I)


def canon_path(p: str) -> str:
    """\\\\?\\C:\\x -> C:\\x and \\\\host\\c$\\x -> c:\\x, so device and admin-share paths meet the same checks."""
    s = re.sub(r"^[/\\]{2}[?.][/\\](unc[/\\])?", lambda m: "\\\\" if m.group(1) else "", str(p), flags=re.I)
    if re.match(r"file:", s, re.I):                        # file:///C:/x, file:/C:/x, file://localhost/C:/x, %2Eenv
        s = unquote(re.sub(r"^file:(?://localhost(?=/))?/{0,3}", "", s, flags=re.I))
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


def glob_target(seg: str, names) -> str | None:
    """The name from names that a wildcard segment could expand to, or None. It needs two literal characters
    and must not be a bare extension glob (*.json), so *, *.txt and src/* stay ordinary."""
    if not GLOB_CHARS.search(seg) or len(seg) > 255:     # no file name is longer; keeps fnmatch linear-time
        return None
    literal =re.sub(r"\[[^\]]*\]|[*?]", "", seg)
    if len(literal) < 2 or re.fullmatch(r"\*+\.[\w-]+", seg):
        return None
    low = seg.lower()
    return next((n for n in names if fnmatch.fnmatchcase(n, low)), None)


PROTECTED_NAMES = (".claude", ".claude.json")
RUNTIME_NAMES = (APP_FOLDER, "managed-settings.json", "allowed_signers")
PATH_SEG = re.compile(r"[^/\\\s\"'=|;&<>(),]+")       # one path segment; linear, no backtracking


def deglob(text: str) -> str:
    """Replace each wildcard path segment that could expand to a protected name with that name, so the normal
    checks see it: $HOME/.cl*/settings.json -> $HOME/.claude/settings.json, and the runtime folder name for
    OrgAIS*. A bare * counts for .claude (PowerShell wildcards match dot folders); the home prefix is still
    required by the checks that follow."""
    if not GLOB_CHARS.search(text):
        return text

    def one(m):
        seg = m.group(0)
        if not GLOB_CHARS.search(seg) or len(seg) > 255:
            return seg
        low = seg.lower()
        hit = next((n for n in PROTECTED_NAMES if fnmatch.fnmatchcase(n, low)), None)
        return hit or glob_target(seg, RUNTIME_NAMES) or seg
    return PATH_SEG.sub(one, text)


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
    if glob_target(base, SECRET_SAMPLES):
        return True   # globs that expand to a secret: .env*, ?env, .[e]nv, *env, id*, cred*, .git-cred*
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


# The home folder itself, or a folder above a protected one: a tree copied or unpacked there can drop a .claude
# folder or replace the runtime (tar -C ~, Expand-Archive -DestinationPath $HOME, cp -r x/. ~/, robocopy x
# $env:USERPROFILE). Also AppData, Library/Application Support, .local/share, Program Files, \Users and the root.
HOME_OR_PARENT = re.compile(
    r"(?:" + USER_HOME + r"(?:[/\\]+(?:appdata(?:[/\\]+(?:local|roaming))?|library(?:[/\\]+application support)?"
    r"|\.local(?:[/\\]+share)?|\.config))?"
    r"|(?:\$env:|\$\{env:|%|\$)(?:localappdata|appdata|programfiles|programdata|programw6432|xdg_data_home|xdg_config_home)[%}]?"
    r"|" + SYS_DRIVE + r"(?:[/\\]+(?:users|home|documents and settings|program files(?: \(x86\))?|programdata))?)", re.I)
QUOTED_WORD = re.compile(r"\"[^\"]*\"|'[^']*'|(?:\\ |[^\s\"'])+")


def home_or_parent(word: str) -> bool:
    w = word.strip("\"'()").replace("\\ ", " ")   # Application\ Support
    if "=" in w and w.startswith("-"):
        w = w.split("=", 1)[1]                 # --directory=~, -DestinationPath=$HOME
    elif re.match(r"-{1,2}[a-z]{1,3}[$~%]", w, re.I):
        w = re.sub(r"^-{1,2}[a-z]{1,3}", "", w, flags=re.I)   # 7z -o$HOME, tar -C~
    elif re.match(r"[a-z_]\w*=", w, re.I):
        return False                           # NAME=value is an environment assignment
    if not w or w.startswith("-") and not re.fullmatch(r"-+", w):
        return False
    w = re.sub(r"(?:[/\\]+\.?)+$", "", collapse(canon_path(w)))   # ~/ and payload/. and C:\ end the same way
    return bool(HOME_OR_PARENT.fullmatch(w)) if w else word.strip("\"'()").startswith(("/", "\\"))


def startup_file(token: str) -> bool:
    """Shell and PowerShell startup files, plus fish's config.fish and conf.d/*.fish."""
    parts = [x.lower() for x in re.split(r"[/\\]+", token) if x]
    if not parts:
        return False
    name = clean_name(parts[-1]).lower()
    return name in STARTUP_NAMES or (name.endswith(".fish") and "fish" in parts[-3:-1])


def pipe_runs_code(part: str) -> bool:
    """True when a pipeline stage hands its input to an interpreter, behind any wrapper (exec, xargs,
    timeout 60, env X=1, sudo) or through a variable ($SHELL, ${X})."""
    text = re.sub(r"\\(?=[a-z0-9])", "", re.sub(r"[\"'`^]", "", part), flags=re.I)   # b\ash -> bash
    for w in words_of(text):
        name = cmd_name(w) if not w.startswith("$") else w
        if not name or name.startswith("-") or name == "{}" or re.fullmatch(r"[a-z_]\w*=.*|[\d.]+[smhd]?", name, re.I):
            continue                             # options, VAR=x, xargs -I {}, timeout durations
        if name.startswith("$") or name in SINKS:
            return True
        if name in WRAPPERS:
            continue
        return False
    return False


def config_forces_push(key: str, value: str | None) -> bool:
    """remote.<name>.push=+ref (force) or :ref (delete), remote.<name>.mirror=true, from -c, git config or env."""
    k = key.strip("\"'").lower()
    if not re.fullmatch(r"remote\..+\.(push|mirror)", k):
        return False
    v = (value or "").strip("\"'").lower()
    if k.endswith(".mirror"):
        return value is None or v in ("", "true", "yes", "on", "1")
    return v.startswith(("+", ":"))


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
    force_cfg = ("deny", "git settings that turn a push into a force, delete or mirror push are not allowed; ask the user.")
    # GIT_CONFIG_KEY_0=remote.origin.mirror GIT_CONFIG_VALUE_0=true git push, or GIT_CONFIG_PARAMETERS
    env = {m.group(1): m.group(2) for m in re.finditer(r"\bgit_config_(key_\d+|value_\d+|parameters)=(\S*)", text, re.I)}
    env = {k.lower(): v for k, v in env.items()}
    for k, v in env.items():
        if k.startswith("key_") and config_forces_push(v, env.get("value_" + k[4:], "")):
            return force_cfg
    if "parameters" in env and re.search(r"remote\.[^\s=]+\.(push|mirror)", text, re.I):
        return force_cfg
    rest, sub, j, home_opt = words[i + 1:], "", 0, False
    while j < len(rest):                      # global options: -c k=v, -C dir, --git-dir=x, --work-tree x ...
        r = rest[j]
        if r in ("-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"):
            val = rest[j + 1] if j + 1 < len(rest) else ""
            if HOME_PROTECTED.search(collapse(val)):
                return no_write
            if r in ("-c", "-C"):             # lowercased, so -C may be -c; a folder never parses as remote.x.push
                key, eq, value = val.partition("=")
                if config_forces_push(key, value if eq else None):
                    return force_cfg
            if r == "--config-env" and re.match(r"remote\..+\.(push|mirror)=", val):
                return force_cfg              # the value sits in an env var the guard cannot see
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
    # Writes into protected places come first: a reset --hard inside ~/.claude must stay a deny even in owner
    # mode, where the destructive class below would only ask.
    writes_file = any(a.startswith("--output") or a == "-o" for a in after)    # git diff --output=x, git archive -o x
    if (sub not in GIT_READ_ONLY or writes_file) and (ctx.get("protected") or HOME_PROTECTED.search(text) or HOME_PROTECTED.search(collapse(text))
                                     or ((home_opt or ctx.get("home")) and REL_CLAUDE.search(" ".join(after)))):
        return no_write
    if any(w.startswith("alias.") and re.search(r"\b(push|reset)\b|!", " ".join(rest)) for w in rest):
        return "deny", "git aliases for push or reset (or shell aliases) are not allowed from the agent; ask the user."
    if sub == "push" and any(long_opt(a, "--force", "--force-with-lease", "--force-if-includes", "--mirror", "--delete", "--prune")
                             or (re.fullmatch(r"-[a-z]+", a) and set(a[1:]) & {"f", "d"})
                             or (a[:1] in "+:" and len(a) > 1) for a in after):
        return "destructive", "a force, mirror or delete push rewrites or removes history on the remote."
    if sub == "send-pack" and any(long_opt(a, "--force", "--mirror") or (a[:1] in "+:" and len(a) > 1) for a in after):
        return "destructive", "a force or mirror push rewrites history on the remote."
    if sub == "config":
        pos = [a for a in after if not a.startswith("-")]
        if len(pos) >= 2 and config_forces_push(pos[0], pos[1]):
            return force_cfg
    if sub == "remote" and any(a == "--mirror" or a.startswith("--mirror=") for a in after):
        return force_cfg
    if sub == "reset" and any(long_opt(a, "--hard") for a in after):
        return "destructive", "git reset --hard discards uncommitted work."
    if sub == "branch" and branch_force_delete(text):
        return "destructive", "force-deleting a branch can lose commits that are not merged anywhere."
    return None


def branch_force_delete(text: str) -> bool:
    """git branch -D x, -df, --delete --force (case matters here: -d only deletes merged branches)."""
    toks = re.findall(r"\S+", text)
    k = next((n for n, t in enumerate(toks) if t.lower() == "branch"), None)
    if k is None:
        return False
    args = toks[k + 1:]
    short = [a[1:] for a in args if re.fullmatch(r"-[A-Za-z]+", a)]
    delete = any(long_opt(a.lower(), "--delete") for a in args) or any("d" in s.lower() for s in short)
    force = any("D" in s or "f" in s for s in short) or any(long_opt(a.lower(), "--force") for a in args)
    return delete and force


def gh_rule(words: list[str]):
    for i, w in enumerate(words):
        if cmd_name(w) != "gh":
            continue
        rest = words[i + 1:]
        public = any(a == "--public" or (a.startswith("--public=") and a.split("=", 1)[1] not in ("false", "0")) for a in rest)
        vis = any(a == "--visibility=public" or (a == "--visibility" and rest[k + 1:k + 2] == ["public"]) for k, a in enumerate(rest))
        # GraphQL and REST bodies with any spacing or quoting: visibility : PUBLIC, "private": false
        body = re.sub(r"[\s\"'\\]", "", " ".join(rest))
        if ("repo" in rest and "create" in rest and public) or ("repo" in rest and "edit" in rest and vis) or \
           ("api" in rest and any(x in body for x in ("private=false", "private:false", "visibility=public", "visibility:public"))):
            return "exposure", "creating or opening a public repo publishes code (also a known exfiltration route)."
        if "gist" in rest and "create" in rest and any(a in ("-p", "--public") or a.startswith("--public=") for a in rest):
            return "exposure", "a public gist publishes files (also a known exfiltration route)."
        # gh api --input file.json sends a body the guard cannot read; refuse it for repo, gist and GraphQL calls.
        if "api" in rest and any(a == "--input" or a.startswith("--input=") for a in rest) and \
                any(re.search(r"(^|/)(graphql|repos|gists)(/|$)", a) for a in rest):
            return "deny", "gh api --input to repo, gist or GraphQL endpoints cannot be checked; use -f fields or ask the user."
    return None


def redirect_targets(plain: str) -> list[str]:
    found = [m.group(1) for m in re.finditer(r"(?<![-=>])>{1,2}\|?&?\s*([^\s|;&<>]+)", plain)]
    return [t for t in found if not re.fullmatch(r"\d+|-", t)]


def stage_reads(part: str) -> bool:
    """One pipeline stage that only reads. sort, uniq, tree and find read unless an option makes them write
    (sort -o, uniq in out, tree -o, find -delete or -exec)."""
    ws = words_of(re.sub(r"[\"'`^]", "", part))
    h = first_word(ws)
    if h in READ_ONLY:
        return True
    k = next((n for n, w in enumerate(ws) if cmd_name(re.split(r"[()]", w)[0] or w) == h), len(ws))
    args = ws[k + 1:]
    if h in ("sort", "tree"):
        return not any(a.startswith("--output") or re.fullmatch(r"-[a-z]*o.*", a) for a in args)
    if h == "uniq":
        return len([a for a in args if not a.startswith("-") and not a.isdigit()]) <= 1
    if h == "find":
        return not FIND_ACTIONS.search(" " + " ".join(args))
    return h in ("du", "df")


def stage_args(pipe_parts: list[str]) -> list[str]:
    """The arguments of every pipeline stage, quotes kept together ('C:\\Documents and Settings'), without the
    command word itself or the environment assignments in front of it."""
    out: list[str] = []
    for part in pipe_parts:
        toks = QUOTED_WORD.findall(part)
        h = first_word(words_of(re.sub(r"[\"'`^]", "", part)))
        if h in ("tar", "bsdtar") and re.search(r"(?:^|\s)(?:-?[a-wyz]*c[a-wyz]*f?\b|--create\b)", part) and \
                not re.search(r"(?:^|\s)(?:-?[a-z]*x|--extract\b|--get\b)", part):
            continue                           # tar -c only reads the folder it archives
        k = next((n for n, t in enumerate(toks) if cmd_name(re.split(r"[()]", t.strip("\"'"))[0] or t) == h), -1)
        out += toks[k + 1:]
    return out


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
        if h in DOWNLOADERS and any(pipe_runs_code(p) for p in pipe_parts[i + 1:]):
            return "deny", "piping a download into a shell is not allowed; download, read, then run."
    fetch = re.search(r"\b(iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod)\b", low) or \
        any(x in low for x in ("downloadstring", "downloadfile", "webclient", "httpclient"))
    if re.search(r"<\(\s*(curl|wget)\b|(\$\(|`)\s*(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b", low) and \
       (fw in SINKS or fw.startswith("$") or any(cmd_name(w) in SINKS for w in words)):
        return "deny", "running a downloaded script is not allowed; download, read, then run."
    if fetch and re.search(r"\b(iex|invoke-expression)\b|\[scriptblock\]\s*::\s*create|\.invokescript\b|\.invokecommand\b", low):
        return "deny", "running a downloaded script is not allowed; download, read, then run."
    if re.search(r"\b(powershell|pwsh)(\.exe)?\b[^|;]*\s-(e|ec|en|enc|enco\w*|encodedcommand)\s+[a-z0-9+/=]{16,}", low):
        return "deny", "encoded PowerShell commands cannot be checked; run the plain command instead."
    r = git_rule(pwords, plain, ctx) or gh_rule(pwords)
    if r and r[0] == "deny":
        return r
    # A class result (destructive, exposure, install) is only the floor: every deny check below still runs on the
    # same statement, so "git push -f > ~/.claude/x" or "npm i x --prefix ~/.claude" never shrinks to an ask.
    cls = r or publish_rule(pipe_parts) or install_rule(pipe_parts)
    return stronger(_statement_tail(stmt, ctx, pipe_parts, plain, unesc, norm, words, pwords, fw, heads, low), cls)


def _statement_tail(stmt, ctx, pipe_parts, plain, unesc, norm, words, pwords, fw, heads, low):
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
    if any(PROTECTED.search(deglob(collapse(canon_path(t)))) for t in targets) or (targets and ctx.get("protected")) or \
            (ctx.get("home") and any(REL_CLAUDE.search(" " + deglob(t)) for t in targets)):
        return deny_protected
    # Wildcards are judged by what they could expand to ($HOME/.cl*/x, OrgAIS*), see deglob.
    hit = PROTECTED.search(stmt) or PROTECTED.search(norm) or PROTECTED.search(collapse(unesc)) or ctx.get("protected") \
        or PROTECTED.search(deglob(norm)) or PROTECTED.search(deglob(collapse(unesc))) \
        or (ctx.get("home") and REL_CLAUDE.search(deglob(plain)))
    # Only plain readers may name a protected place. Every other program (curl -o, tar -C, mkdir, touch,
    # npm --prefix, [IO.File]::WriteAllText, an interpreter) is refused, so new write routes need no new rule.
    # A reader stops being one when the statement also runs code: (Get-Item x).Delete(), $(...), { script block }.
    ps_like = any("-" in h or h in PS_ALIASES for h in heads)
    readers_only = all(stage_reads(p) for p in pipe_parts) and not CODE_IN_STMT.search(stmt) and \
        not ("{" in stmt and ps_like)                                       # redirect targets were checked above
    if hit and fw != "git" and not readers_only:
        return deny_protected
    # A tree copied or unpacked into the home folder (or a folder above a protected one) can bring its own
    # .claude folder: tar -C ~, Expand-Archive -DestinationPath $HOME, cp -r x/. ~/, robocopy x $env:USERPROFILE.
    if fw != "git" and not readers_only and any(home_or_parent(w) for w in stage_args(pipe_parts)):
        return "deny", ("commands other than plain readers may not target the home folder itself or a folder above the "
                        "agent's config or the org runtime; name a subfolder instead.")
    startup = any(startup_file(c) for c in PATHISH.findall(plain)) or "$profile" in low
    if startup and (">" in stmt or not (readers_only or fw in ("source", ".", "git"))):
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


# ---------------------------------------------------------------------------------------------------
# Rule classes and policy modes (owner vs managed). Rules return a class instead of a final decision
# for the actions the owner may legitimately want: "destructive" (force, mirror or delete push, hard
# reset, force branch delete) and "exposure" (public repo, public gist, package publish). "install"
# (a new named dependency) is "ask" in both modes. Everything else that is refused (secrets,
# pipe-to-shell, the agent's own config, home and root deletes, evasion routes) stays "deny".
# ---------------------------------------------------------------------------------------------------
CLASSES = ("destructive", "exposure", "install")
MODES = ("owner", "managed")
POLICY_TABLE = {"owner": {"destructive": "ask", "exposure": "ask", "install": "ask"},
                "managed": {"destructive": "deny", "exposure": "deny", "install": "ask"}}
POLICY_NAME = "guard-policy.json"
POLICY_MAX = 4096
POLICY_KEYS = {"mode", "version", "note"}
RANK = {"deny": 4, "destructive": 3, "exposure": 3, "install": 2, "ask": 1}
SHOW_MAX = 2000                     # longest command shown for approval; longer ones are denied
AUDIT_NAME = "guard-audit.jsonl"
AUDIT_MAX_BYTES = 5_000_000
AUDIT_TEXT = 300


def policy_path() -> Path:
    """The policy belongs to the runtime this guard runs from (<app>/scripts/agent_guard.py ->
    <app>/config/guard-policy.json), never to the project, so a repo cannot pick its own mode."""
    return Path(os.path.abspath(__file__)).parent.parent / "config" / POLICY_NAME


def managed_markers() -> list[str]:
    """Files whose presence means an organization manages this machine. Then a per-user policy is ignored."""
    if os.name == "nt":
        roots = {os.environ.get("ProgramFiles") or "", os.environ.get("ProgramW6432") or "", r"C:\Program Files"}
        out = []
        for r in sorted(x for x in roots if x):
            out += [os.path.join(r, "ClaudeCode", "managed-settings.json"),
                    os.path.join(r, "OrgAISecureAppSec", "scripts", "agent_guard.py")]
        return out
    if sys.platform == "darwin":
        return ["/Library/Application Support/ClaudeCode/managed-settings.json"]
    return ["/etc/claude-code/managed-settings.json"]


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _plain_file(st) -> bool:
    reparse = getattr(st, "st_file_attributes", 0) & 0x400          # FILE_ATTRIBUTE_REPARSE_POINT
    return stat.S_ISREG(st.st_mode) and not reparse


def load_policy(path: Path | None = None, markers: list[str] | None = None) -> tuple[str, str]:
    """(mode, why). Fails closed: anything other than a small plain JSON file with exactly
    {"mode": "owner"|"managed"} (plus optional version and note) is "managed"."""
    p = Path(path) if path is not None else policy_path()
    try:
        st = os.lstat(p)
        if not _plain_file(st) or st.st_size > POLICY_MAX:
            return "managed", "policy file is not a small plain file"
        data = json.loads(p.read_bytes().decode("utf-8-sig"), object_pairs_hook=_no_dupes)
    except FileNotFoundError:
        return "managed", "no policy file"
    except Exception:
        return "managed", "policy file unreadable or malformed"
    if not isinstance(data, dict) or set(data) - POLICY_KEYS or data.get("mode") not in MODES:
        return "managed", "policy file malformed"
    mode = data["mode"]
    if mode == "owner":
        for m in (markers if markers is not None else managed_markers()):
            try:
                if os.path.lexists(m):
                    return "managed", "a managed install is present, so the per-user policy is ignored"
            except Exception:
                return "managed", "managed install check failed"
    return mode, "policy file"


_SHOW_ESCAPE = re.compile(r"[\x00-\x1f\x7f-\x9f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]")


def show_command(cmd: str) -> str | None:
    """The command as the person will approve it: the literal text with control, bidi and invisible characters
    spelled out, so nothing hides inside it, plus the collapsed form (dir/../ removed) when that differs.
    The literal text comes first because collapse() is a checking aid, not a shell: it reads ./a/../../x as x.
    None when too long to read."""
    def esc(s):
        return _SHOW_ESCAPE.sub(lambda m: "\\u%04x" % ord(m.group(0)), s)
    raw = cmd.strip()
    shown = esc(raw)
    col = collapse(raw)
    if col != raw:
        shown += f" (paths collapsed: {esc(col)})"
    return shown if len(shown) <= SHOW_MAX else None


def stronger(a, b):
    """The stricter of two statement results (deny > destructive/exposure > install > ask > none)."""
    if not a:
        return b
    if not b:
        return a
    return a if RANK.get(a[0], 4) >= RANK.get(b[0], 4) else b


def apply_policy(result, mode: str, cmd: str):
    """Turn a rule class into the final decision for this mode. Unknown classes are denied."""
    if not result or result[0] not in CLASSES:
        return result
    cls, why = result
    final = POLICY_TABLE.get(mode, POLICY_TABLE["managed"]).get(cls, "deny")
    if final == "ask":
        shown = show_command(cmd)
        if shown is None:
            return "deny", f"{why} The command is too long to show for approval; split it into shorter commands."
        return "ask", f"({mode} mode, {cls}) {why} Approve only if you asked for exactly this command: {shown}"
    return "deny", f"{why} Not allowed from the agent under the managed policy; run it yourself if it is intended."


CMD_PREFIX = WRAPPERS | {"sudo", "-c", "/c", "/k", "-command", "-lc", "-ic", "-m"}


def command_starts(pipe_parts: list[str]):
    """(command name, its arguments) for every word in a command position: the stage head and anything
    started through a wrapper or an inline script (sudo x, timeout 60 x, env A=1 x, sh -c "x", python -m x).
    Statements that only print or record text (git commit -m "...", echo, cat) start nothing."""
    for part in pipe_parts:
        ws = words_of(re.sub(r"[\"'`^]", "", part))
        fw = first_word(ws)
        if not ws or fw == "git" or (fw in READ_ONLY and fw):
            continue
        for k, w in enumerate(ws):
            prev = ws[k - 1] if k else ""
            if k == 0 or prev in CMD_PREFIX or re.fullmatch(r"[a-z_]\w*=\S*|\d+[smhd]?", prev):
                yield cmd_name(re.split(r"[()]", w)[0] or w), ws[k + 1:]


def publish_rule(pipe_parts: list[str]):
    """Package publishing (exposure): npm/pnpm/yarn/bun publish, yarn npm publish, cargo publish, gem push,
    twine upload (also python -m twine), poetry/flit/uv/hatch/pdm publish, dotnet nuget push, nuget push.
    A commit message or an echo that mentions it is not a publish (see command_starts)."""
    for h, rest in command_starts(pipe_parts):
        if "--dry-run" in rest:
            continue
        args = [a for a in rest if not a.startswith("-")]
        sub = args[0] if args else ""
        if (h in ("npm", "pnpm", "bun", "cargo", "poetry", "flit", "uv", "hatch", "pdm") and sub == "publish") or \
                (h == "yarn" and (sub == "publish" or args[:2] == ["npm", "publish"])) or \
                (h == "gem" and sub == "push") or (h == "twine" and sub == "upload") or \
                (h == "dotnet" and args[:2] == ["nuget", "push"]) or (h == "nuget" and sub == "push"):
            return "exposure", "publishing a package makes this code public."
    return None


PIP_VALUE_OPTS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
                  "-f", "--find-links", "-t", "--target", "--prefix", "--root", "--python", "-p"}
INSTALL_SUBS = {"npm": {"install", "i", "add"}, "pnpm": {"add", "install", "i"}, "yarn": {"add"}, "bun": {"add", "install", "i"},
                "pip": {"install"}, "poetry": {"add"}, "uv": {"add"}, "pdm": {"add"}, "composer": {"require"},
                "go": {"get", "install"}, "cargo": {"add", "install"}, "gem": {"install"}, "bundle": {"add"}}


def install_rule(pipe_parts: list[str]):
    """A new named dependency (install class, "ask" in both modes): npm i x, pip install x, composer require x,
    go get x, cargo add x, dotnet add package x ... Installing from the lockfile or the project itself
    (npm install, npm ci, pip install -r requirements.txt, pip install -e .) is not a new dependency."""
    for h, rest in command_starts(pipe_parts):
        if h == "pip3":
            h = "pip"
        elif h == "uv" and rest[:1] == ["pip"]:
            h, rest = "pip", rest[1:]
        if h == "dotnet" and rest[:2] == ["add", "package"] or (h == "dotnet" and rest[:1] == ["add"] and "package" in rest[:3]):
            return "install", "adding a new dependency; check the package name is real and spelled right."
        subs = INSTALL_SUBS.get(h)
        if not subs or not rest:
            continue
        pos = [a for a in rest if not a.startswith("-")]
        if not pos or pos[0] not in subs:
            continue
        args, skip, names = rest[rest.index(pos[0]) + 1:], False, []
        for a in args:
            if skip:
                skip = False
                continue
            if a.startswith("-"):
                skip = h == "pip" and a in PIP_VALUE_OPTS
                continue
            if a in (".", "..") or a.startswith(("./", "../", ".\\", "..\\", "/")):
                continue
            names.append(a)
        if names:
            return "install", f"adding a new dependency ({names[0][:80]}); check the package name is real and spelled right."
    return None


_REDACT_KV = re.compile(r"(?i)((?:token|secret|password|passwd|pwd|api[_-]?key|auth[_-]?token|_authtoken|authorization|"
                        r"bearer|private[_-]?key|client[_-]?secret)[\"']?\s*[=: ]\s*)(\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']+)")
_REDACT_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_\w{16,}|npm_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|"
                           r"xox[abposr]-[\w-]{10,}|sk-[A-Za-z0-9_-]{16,}|glpat-[\w-]{16,}|pypi-[\w-]{16,})")
_REDACT_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,20}://)[^/\s:@]+:[^/\s@]+@")
_REDACT_BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+[^\s\"']+")
_REDACT_LONG = re.compile(r"[A-Za-z0-9+=_-]{40,}")


def redact(text: str, limit: int = AUDIT_TEXT) -> str:
    """Audit text: no token-looking values, no inline passwords, no control characters, at most `limit` characters."""
    t = str(text)[:4 * limit]
    t = _REDACT_URL.sub(r"\1***@", t)
    t = _REDACT_BEARER.sub(lambda m: m.group(1) + " ***", t)
    t = _REDACT_KV.sub(lambda m: m.group(1) + "***", t)
    t = _REDACT_TOKEN.sub("***", t)
    t = _REDACT_LONG.sub("***", t)
    t = _SHOW_ESCAPE.sub(" ", t)
    return t[:limit] + ("..." if len(t) > limit else "")


def audit_ask(event: dict, reason: str, mode: str) -> bool:
    """Append one line to <project>/.security/guard-audit.jsonl for every "ask". Best effort: a failure here
    never changes the decision. Refuses links, junctions and hard links, the home folder, a drive root and
    protected places, so a hostile repo cannot point the write somewhere else."""
    try:
        project = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or ""
        if not isinstance(project, str) or not project or len(project) > 4096:
            return False
        root = os.path.realpath(project)
        home = os.path.realpath(os.path.expanduser("~"))
        if not os.path.isdir(root) or os.path.normcase(root) == os.path.normcase(home) or os.path.dirname(root) == root \
                or PROTECTED.search(root.replace(os.sep, "/") + "/"):
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
            if not _plain_file(st) or st.st_nlink > 1 or st.st_size > AUDIT_MAX_BYTES:
                return False
        ti = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
        what = ti.get("command") if isinstance(ti.get("command"), str) else \
            next((v for k, v in ti.items() if isinstance(v, str) and re.search(r"path|file", str(k), re.I)), "")
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": mode, "decision": "ask",
                "tool": redact(event.get("tool_name") or "", 80), "command": redact(what), "reason": redact(reason.split(" Approve only")[0], 200)}
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(f, flags, 0o600)
        with os.fdopen(fd, "ab") as fh:
            fh.write((json.dumps(line, ensure_ascii=True) + "\n").encode("ascii"))
        return True
    except Exception:
        return False


def dangerous_target(w: str) -> bool:
    t = w.strip("'\"").lower().replace("\\", "/")
    t = t[:-1] if t.endswith("*") else t
    t = t.rstrip("/")
    if t.endswith("/."):
        t = t[:-2]
    return t in ("", "~", "$home", "${home}", "$userprofile", "${userprofile}", "$env:userprofile", "%userprofile%",
                 "/mnt/c", "*", ".") and w not in (".", "./") or bool(re.fullmatch(r"[a-z]:|/[a-z]|/mnt/[a-z]", t))


def check(event: dict, mode: str | None = None):
    """The decision for one tool event, or None to allow. mode is "owner" or "managed"; None reads the policy
    file (and only when a shell command needs it)."""
    tool = event.get("tool_name") or ""
    ti = event.get("tool_input") or {}
    if not isinstance(ti, dict):
        return "deny", "the tool input could not be read, so this action cannot be checked safely."
    project = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()

    # Every argument that names a file, whatever the tool calls it (MCP servers use their own keys).
    paths = []
    for k, v in ti.items():
        if not re.search(r"(path|file|dir|dest|target|output|source|uri|url|href)", str(k), re.I) or re.search(r"(content|text|data)", str(k), re.I):
            continue
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, str) and x and len(x) < 4096 and "\n" not in x:
                paths.append(canon_path(x))
    if any(is_secret_path(p) for p in paths):
        return "deny", "secret files (.env, keys, credentials) must not be read or edited. Use .env.example or ask the user."
    if any(is_ask_path(p) for p in paths):
        return "ask", "this is a tool credential file (.npmrc, docker/kube/gh config); approve only if needed."
    if tool in ("Edit", "Write", "MultiEdit") and any(startup_file(p) for p in paths):
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
                # The user's own global rules (settings, CLAUDE.md, rules/*.md) are "ask", never a silent allow: the
                # owner may ask for a rule change, and a prompt-injected agent still needs the owner's yes.
                # Hooks, skills, agents and commands run code or load as instructions without a prompt: deny.
                if user_claude and not tool.startswith("mcp__") and \
                        re.search(r"[/\\](settings(\.local)?\.json|claude\.md|rules[/\\][^:]+\.md)$", n, re.I):
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
        worst = None
        for stmt in SPLIT_STMT.split(cmd):
            r = check_statement(stmt, ctx)
            if r and r[0] == "deny":
                return r
            worst = stronger(worst, r)
        worst = apply_policy(worst, mode if mode is not None else load_policy()[0], cmd)
        if worst:
            return worst

    # Strict instruction-source mode, only for projects that opted in with a claude_docs/ folder.
    if tool in ("Read", "Edit", "Write", "MultiEdit") and os.path.isdir(os.path.join(project, "claude_docs")):
        fp = ti.get("file_path")
        if isinstance(fp, str) and MD.search(fp):
            rel = rel_in_project(fp, project)
            if rel is not None and rel.lower() not in ("claude.md", "agents.md") and not rel.lower().startswith("claude_docs/"):
                return "deny", (f"{rel} is not an instruction source in this project. Only CLAUDE.md, AGENTS.md and "
                                "claude_docs/ may be used; list other docs in claude_docs/IGNORED_FILES.md and ask the user.")
    return None


def decide(event: dict, mode: str | None = None):
    """check() under the active policy, plus the audit line for every "ask". Used by main() and the
    Cursor and Codex adapters, so all three agents get the same decisions."""
    if mode is None:
        mode = load_policy()[0]
    result = check(event, mode)
    if result and result[0] == "ask":
        audit_ask(event, result[1], mode)
    return result


def main() -> int:
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
        result = decide(event)
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
