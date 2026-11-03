#!/usr/bin/env python3
"""NexaForge SecureCode offline MCP scan (7.0).

Config mode (the default, and what secgate full/ci runs) only reads files:
- project: .mcp.json (Claude Code), .cursor/mcp.json, .codex/config.toml, .gemini/settings.json, .vscode/mcp.json
- user (standalone runs only, never from the gate): ~/.claude.json (top-level and this project's entry),
  ~/.cursor/mcp.json, ~/.codex/config.toml (or CODEX_HOME), ~/.gemini/settings.json
It lists each server with its command, arguments (secret-looking values redacted) and env variable NAMES (never
values), and flags risky launch patterns.

Connect mode (`--connect NAME --yes`) starts one named stdio server, asks it for tools/list over JSON-RPC with a
timeout, scans the tool names, descriptions and input schemas for prompt-injection and poisoning signs, and
pins a SHA-256 of every tool in .security/mcp-lock.json. A later run that sees a changed hash reports HIGH
(rug pull) until the user re-approves with `--approve`. Starting a server runs its code, so the exact command
is printed first and nothing starts without `--yes`. No network traffic beyond what the named local server
does itself; nothing is sent to any vendor.
"""
from __future__ import annotations

import argparse, hashlib, json, os, queue, re, shlex, shutil, stat, subprocess, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))          # hooks and the gate run with -I (no script folder on sys.path)
import secret_shield as shield             # noqa: E402

CONFIG_MAX = 5_000_000
LOCK_NAME = "mcp-lock.json"
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

HIDDEN_UNICODE = re.compile("[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
# Strong signs (HIGH): text that only makes sense as an instruction to the model behind the user's back.
INJECTION = re.compile(
    r"(?i)(ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|rules|prompts?)|disregard (?:the )?"
    r"(?:system|previous) (?:prompt|instructions)|do not (?:tell|inform|mention|reveal|show)[^.\n]{0,40}(?:the )?user|"
    r"without (?:asking|telling|informing) the user|<\s*(?:important|system|instructions?|secret)\s*>|"
    r"curl[^\n]{0,80}\|\s*(?:ba)?sh|--dangerously-skip-permissions)")
# Weak signs (MEDIUM): common in poisoned tools, but honest tools use them too.
INJECTION_WEAK = re.compile(
    r"(?i)(before (?:using|calling) this tool|\bsystem prompt\b|(?:this|the) (?:tool|function) (?:will|must) (?:not )?"
    r"work (?:only )?(?:if|unless)|you must (?:first |always )?(?:read|send|include) (?:the )?(?:contents?|file|config))")
SENSITIVE_PATH = re.compile(r"(?i)(~|\$home|%userprofile%)?[/\\]?\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws[/\\]credentials|"
                            r"\bmcp\.json\b|\.claude\.json\b|\.netrc\b|\bwallet\.dat\b|\.kube[/\\]config|\.git-credentials")
EXFIL = re.compile(r"(?i)\b(?:send|upload|forward|exfiltrat\w*|transmit|email|leak|copy|post)\b[^\n]{0,80}?\b(?:the |all |any )?"
                   r"(?:result|contents?|conversation|chat|history|data|files?|output|credentials?|keys?|tokens?|secrets?|"
                   r"messages?|everything|notes)\b[^\n]{0,80}?https?://")
SHADOW = re.compile(r"(?i)(?:instead of|rather than|whenever|when(?:ever)? (?:you |the )?(?:use|call|run|invoke)s?|"
                    r"before (?:you )?(?:use|call|run|invoke)|also (?:call|run|use)|override|replace)s?\b[^.\n]{0,40}?\b"
                    r"(?:the )?[`'\"]?([A-Za-z][\w.-]{2,63})[`'\"]? (?:tool|function|command)")
BUILTIN_TOOLS = {"bash", "read", "write", "edit", "multiedit", "grep", "glob", "webfetch", "websearch", "powershell",
                 "notebookedit", "task", "agent"}
SECRETISH_NAME = re.compile(r"(?i)secret|passw(?:or)?d|pwd|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
                            r"credential|auth|bearer|session|cookie|signing")
REFERENCE = re.compile(r"^\s*(?:\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|"
                       r"\$\{(?:env|input):[^}]{1,80}\}|\{env:[A-Za-z_]\w*\})\s*$")
PIPE_SHELL = re.compile(r"(?i)\b(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n|]{0,300}\|\s*"
                        r"(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,300}\|\s*iex\b|"
                        r"\$\(\s*(?:curl|wget)\b")
EXACT_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
GIT_SHA = re.compile(r"[0-9a-f]{40}")


# ---------------------------------------------------------------------------------------------- config reading

def _read_json(fp: Path):
    st = os.lstat(fp)
    if not stat.S_ISREG(st.st_mode) or st.st_size > CONFIG_MAX:
        raise ValueError("not a small plain file")
    return json.loads(fp.read_bytes().decode("utf-8-sig"))


def _read_toml(fp: Path):
    st = os.lstat(fp)
    if not stat.S_ISREG(st.st_mode) or st.st_size > CONFIG_MAX:
        raise ValueError("not a small plain file")
    import tomllib          # Python 3.11+
    return tomllib.loads(fp.read_bytes().decode("utf-8-sig"))


def _servers_from(obj, key: str) -> dict:
    v = obj.get(key) if isinstance(obj, dict) else None
    return v if isinstance(v, dict) else {}


def _norm(name, raw, client: str, source: Path) -> dict | None:
    if not isinstance(raw, dict):
        return None
    cmd = raw.get("command")
    args = raw.get("args")
    args = [str(a) for a in args] if isinstance(args, list) else []
    if isinstance(cmd, list):            # some clients accept a list
        cmd, args = (str(cmd[0]) if cmd else ""), [str(a) for a in cmd[1:]] + args
    cmd = str(cmd) if isinstance(cmd, (str, int, float)) else ""
    if cmd and not args and " " in cmd.strip() and not os.path.exists(cmd):
        try:
            parts = shlex.split(cmd, posix=os.name != "nt")
            cmd, args = parts[0], parts[1:]
        except ValueError:
            pass
    env = raw.get("env") if isinstance(raw.get("env"), dict) else {}
    headers = {}
    for hk in ("headers", "http_headers", "requestInit"):
        h = raw.get(hk)
        if isinstance(h, dict):
            headers.update(h.get("headers") if hk == "requestInit" and isinstance(h.get("headers"), dict) else
                           {k: v for k, v in h.items() if not isinstance(v, dict)})
    url = raw.get("url") or raw.get("httpUrl") or raw.get("serverUrl") or ""
    url = url if isinstance(url, str) else ""
    transport = str(raw.get("type") or raw.get("transport") or ("http" if url else "stdio"))
    return {"name": str(name), "client": client, "config": str(source), "command": cmd, "args": args,
            "env": {str(k): v for k, v in env.items()}, "headers": {str(k): v for k, v in headers.items()},
            "url": url, "transport": transport, "trust": raw.get("trust") is True,
            "cwd": raw.get("cwd") if isinstance(raw.get("cwd"), str) else ""}


def config_locations(project: Path, home: Path | None, include_user: bool) -> list[tuple[str, Path, str]]:
    """(client, path, format) for every config this scan reads."""
    locs = [("claude-project", project / ".mcp.json", "json"),
            ("cursor-project", project / ".cursor" / "mcp.json", "json"),
            ("codex-project", project / ".codex" / "config.toml", "toml"),
            ("gemini-project", project / ".gemini" / "settings.json", "json"),
            ("vscode-project", project / ".vscode" / "mcp.json", "json")]
    if include_user and home is not None:
        codex_home = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else home / ".codex"
        locs += [("claude-user", home / ".claude.json", "json"),
                 ("cursor-user", home / ".cursor" / "mcp.json", "json"),
                 ("codex-user", codex_home / "config.toml", "toml"),
                 ("gemini-user", home / ".gemini" / "settings.json", "json")]
    return locs


def read_configs(project: Path, home: Path | None = None, include_user: bool = True) -> tuple[list[dict], list[dict]]:
    servers, findings = [], []
    proj_key = os.path.normcase(os.path.realpath(project))
    for client, fp, fmt in config_locations(project, home, include_user):
        try:
            if not os.path.lexists(fp):
                continue
            if os.path.islink(fp):
                findings.append(_f("MCP_CONFIG_LINK", "LOW", fp, 0, f"{client}: config is a link; not followed"))
                continue
            data = _read_toml(fp) if fmt == "toml" else _read_json(fp)
        except Exception as e:
            findings.append(_f("MCP_CONFIG_UNREADABLE", "LOW", fp, 0, f"{client}: config could not be read ({type(e).__name__})"))
            continue
        groups = []
        if fmt == "toml":
            groups.append(_servers_from(data, "mcp_servers"))
        elif client == "vscode-project":
            groups.append(_servers_from(data, "servers"))
        else:
            groups.append(_servers_from(data, "mcpServers"))
            if client == "claude-user" and isinstance(data.get("projects"), dict):
                for p, pdata in data["projects"].items():
                    try:
                        same = os.path.normcase(os.path.realpath(str(p))) == proj_key
                    except (OSError, ValueError):
                        same = False
                    if same:
                        groups.append(_servers_from(pdata, "mcpServers"))
        for g in groups:
            for name, raw in g.items():
                s = _norm(name, raw, client, fp)
                if s:
                    s["line"] = _line_of(fp, name)
                    servers.append(s)
    return servers, findings


def _line_of(fp: Path, name: str) -> int:
    try:
        for n, line in enumerate(fp.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
            if f'"{name}"' in line or f"mcp_servers.{name}" in line or f"'{name}'" in line:
                return n
    except OSError:
        pass
    return 0


# ------------------------------------------------------------------------------------------------ launch checks

def _f(rule, sev, fp, line, msg):
    return {"rule": rule, "severity": sev, "file": str(fp), "line": int(line or 0), "message": msg, "code": "",
            "engine": "mcp-scan"}


def _base(cmd: str) -> str:
    b = os.path.basename(cmd.replace("\\", "/")).lower()
    for ext in (".cmd", ".exe", ".bat", ".ps1"):
        if b.endswith(ext):
            b = b[: -len(ext)]
    return b


def package_spec(cmd: str, args: list[str]) -> tuple[str, str] | None:
    """(ecosystem, spec) of the package a launcher downloads and runs, or None."""
    b = _base(cmd)
    rest = list(args)
    eco = None
    if b in ("npx", "bunx", "pnpx"):
        eco = "npm"
    elif b in ("pnpm", "yarn") and rest[:1] == ["dlx"] or b == "npm" and rest[:1] in (["exec"], ["x"]) or b == "bun" and rest[:1] == ["x"]:
        eco, rest = "npm", rest[1:]
    elif b == "uvx" or b == "pipx" and rest[:1] == ["run"]:
        eco, rest = "pypi", rest[1:] if b == "pipx" else rest
    elif b == "uv" and rest[:2] == ["tool", "run"]:
        eco, rest = "pypi", rest[2:]
    elif b in ("docker", "podman") and rest[:1] == ["run"]:
        eco, rest = "docker", rest[1:]
    if not eco:
        return None
    takes_value = {"--package", "-p", "--from", "--registry", "--cache", "--python", "--with", "--index-url", "-e", "--env",
                   "-v", "--volume", "--name", "--network", "--mount", "--entrypoint", "-w", "--workdir", "-u", "--user",
                   "--platform", "--env-file", "--userconfig"}
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--package", "-p", "--from") and eco != "docker" and i + 1 < len(rest):
            return eco, rest[i + 1]
        if a.startswith(("--package=", "--from=")):
            return eco, a.split("=", 1)[1]
        if a == "--":
            i += 1
            continue
        if a.startswith("-"):
            i += 2 if a in takes_value and "=" not in a else 1
            continue
        return eco, a
    return None


SHELL_META = re.compile(r"[|&;<>`]|\$\(")


def unwrap_shell(cmd: str, args: list[str]) -> list[str] | None:
    """The command inside `cmd /c ...`, `bash -c "..."` or `powershell -Command ...`, or None when not wrapped."""
    b = _base(cmd)
    low = [a.lower() for a in args]
    if b == "cmd":
        for i, a in enumerate(low):
            if a in ("/c", "/k"):
                rest = args[i + 1:]
                break
        else:
            return None
    elif b in ("sh", "bash", "zsh", "dash", "powershell", "pwsh"):
        flags = ("-c",) if b in ("sh", "bash", "zsh", "dash") else ("-c", "-command", "/c")
        idx = next((i for i, a in enumerate(low) if a in flags), None)
        if idx is None:
            return None
        rest = args[idx + 1:]
    else:
        return None
    if len(rest) == 1:
        try:
            rest = shlex.split(rest[0], posix=True)
        except ValueError:
            rest = rest[0].split()
    return rest or [""]


def pinned(eco: str, spec: str) -> bool | None:
    """True when the spec names one exact version; None when it is a local path (not a download)."""
    s = spec.strip()
    if not s or s.startswith((".", "/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", s) or s.startswith("file:"):
        return None
    if re.match(r"(?i)^(git\+|github:|gitlab:|bitbucket:|https?://)", s):
        return bool(GIT_SHA.search(s))
    if eco == "npm":
        at = s.rfind("@")
        if at <= 0:
            return False
        return bool(EXACT_SEMVER.fullmatch(s[at + 1:]))
    if eco == "pypi":
        m = re.search(r"(?:===?|@)\s*([^\s;,]+)$", s)
        return bool(m and re.fullmatch(r"\d+(?:\.\d+)*(?:[abc]|rc|\.post|\.dev)?\d*", m.group(1)))
    if eco == "docker":
        return "@sha256:" in s
    return False


def _redact_arg(a: str) -> str:
    return shield.redact(a, 200)


HOME_WORDS = {"~", "$home", "${home}", "%userprofile%", "$env:userprofile", "/users", "/home", "c:/users"}


def path_scope(arg: str) -> str | None:
    """'root' when an argument hands over a whole drive or /, 'home' for a whole home folder, else None.
    Looks at the bare argument, a --flag=value, and the host side of a docker-style src:dst volume."""
    low = arg.strip().strip("'\"").lower().replace("\\", "/")
    cands = {low}
    if low.startswith("-") and "=" in low:
        cands.add(low.split("=", 1)[1])
    if not re.match(r"^[a-z]:", low) and ":" in low:
        cands.add(low.split(":", 1)[0])
    home = os.path.expanduser("~").lower().replace("\\", "/").rstrip("/")
    for c in cands:
        c = c.rstrip("/") if len(c) > 1 else c
        if not c:
            continue
        if c in ("/", "/*", "/mnt/c") or re.fullmatch(r"[a-z]:/?\*?", c) or \
                re.fullmatch(r"/mnt/[a-z]", c):
            return "root"
        if c in HOME_WORDS or c == home or c == "~/" or re.fullmatch(r"(?:/home|/users|[a-z]:/users)/[^/]+", c):
            return "home"
    return None


def launch_findings(s: dict, lock: dict | None = None) -> list[dict]:
    out = []
    fp, line, who = s["config"], s.get("line", 0), f"{s['client']} server '{s['name']}'"
    cmd, args = s["command"], s["args"]
    joined = " ".join([cmd] + args)
    inner = unwrap_shell(cmd, args)
    spec = package_spec(cmd, args) if cmd else None
    if spec is None and inner:
        spec = package_spec(inner[0], inner[1:])          # cmd /c npx -y pkg: check the package inside the wrapper
    if spec:
        eco, sp = spec
        p = pinned(eco, sp)
        if p is False:
            what = "an image tag, not a digest" if eco == "docker" else "no exact version"
            out.append(_f("MCP_UNPINNED_PACKAGE", "MEDIUM", fp, line,
                          f"{who} downloads and runs '{_redact_arg(sp)[:120]}' with {what} (or 'latest'). Every start may run "
                          "new code. Pin an exact version (name@1.2.3, name==1.2.3, image@sha256:...)."))
        if eco == "npm" and p is not None and not sp.startswith("@") and not re.match(r"(?i)^(git\+|github:|https?://)", sp):
            out.append(_f("MCP_UNSCOPED_PACKAGE", "LOW", fp, line,
                          f"{who} runs the unscoped npm package '{_redact_arg(sp)[:80]}'. Unscoped names are easier to "
                          "typosquat; check the exact name and publisher."))
        if eco == "docker" and re.search(r"(?i)(?:^|\s)--privileged\b", " ".join(args)):
            out.append(_f("MCP_DOCKER_PRIVILEGED", "HIGH", fp, line, f"{who} runs a privileged container."))
    if PIPE_SHELL.search(joined):
        out.append(_f("MCP_PIPE_TO_SHELL", "HIGH", fp, line,
                      f"{who} downloads a script and pipes it into a shell when it starts. Install a reviewed, pinned "
                      "release instead."))
    elif inner is not None:
        if SHELL_META.search(" ".join(inner)):
            out.append(_f("MCP_SHELL_WRAPPER", "MEDIUM", fp, line,
                          f"{who} starts through a shell command line with shell operators, which hides what really runs. "
                          "Call the program directly."))
        else:
            out.append(_f("MCP_SHELL_WRAPPER", "LOW", fp, line,
                          f"{who} starts through a shell ({_base(cmd)}); fine for npx on Windows, but calling the program "
                          "directly is clearer."))
    for a in args:
        kind = path_scope(a)
        if kind == "root":
            out.append(_f("MCP_FILESYSTEM_ROOT", "HIGH", fp, line,
                          f"{who} gets a whole drive or the filesystem root ('{_redact_arg(a)[:40]}'). Give it the "
                          "project folder only."))
            break
        if kind == "home":
            out.append(_f("MCP_FILESYSTEM_HOME", "MEDIUM", fp, line,
                          f"{who} gets the whole home folder ('{_redact_arg(a)[:40]}'), which holds SSH keys and "
                          "cloud credentials. Give it the project folder only."))
            break
    # Secrets written into the config itself.
    for k, v in list(s["env"].items()) + [(f"header {k}", v) for k, v in s["headers"].items()]:
        if not isinstance(v, str) or not v.strip():
            continue
        bare = re.sub(r"(?i)^\s*(?:bearer|basic|token)\s+", "", v)      # "Bearer ${TOKEN}" is still a reference
        if REFERENCE.match(v) or REFERENCE.match(bare):
            continue
        found = [m for m in shield.find_secrets(v)]
        live = [m for m in found if not m.example]
        named = bool(SECRETISH_NAME.search(k)) and len(v.strip()) >= 8
        if live or (named and not shield.is_example("secret-assignment", v.strip()) and not found):
            out.append(_f("MCP_INLINE_SECRET", "HIGH", fp, line,
                          f"{who} has a literal value in {k} (secret-looking). Use an environment reference such as "
                          "${VAR} and keep the value out of the file; rotate it if this file was ever committed or shared."))
        elif named or found:
            out.append(_f("MCP_INLINE_SECRET_EXAMPLE", "LOW", fp, line,
                          f"{who} has a placeholder-looking value in {k}; make sure the real value is not kept here."))
    for a in args:
        live = [m for m in shield.find_secrets(a) if not m.example]
        flag = re.match(r"(?i)^--?[\w-]*(?:token|key|secret|password|auth)[\w-]*=(.{8,})$", a)
        if live or (flag and not REFERENCE.match(flag.group(1)) and not shield.is_example("secret-assignment", flag.group(1))):
            out.append(_f("MCP_INLINE_SECRET", "HIGH", fp, line,
                          f"{who} passes a secret on its command line. Pass it through an env reference instead; command "
                          "lines are visible to other programs and end up in logs."))
            break
    if s["url"]:
        m = re.match(r"(?i)^(\w+)://\[?([^/\]:]+)", s["url"])
        scheme, host = (m.group(1).lower(), m.group(2).lower()) if m else ("", "")
        if scheme == "http":
            loop = host in ("localhost", "127.0.0.1", "::1") or host.startswith("127.")
            out.append(_f("MCP_INSECURE_REMOTE", "LOW" if loop else "HIGH", fp, line,
                          f"{who} talks to {host or 'a server'} over plain http; " +
                          ("loopback only, acceptable for local development." if loop else
                           "tokens and tool data travel unencrypted. Use https.")))
        if shield.find_secrets(s["url"]) or re.search(r"(?i)[?&](?:api[_-]?key|token|key|secret|access_token)=[^&\s${]{8,}", s["url"]):
            out.append(_f("MCP_INLINE_SECRET", "HIGH", fp, line, f"{who} has a credential inside its URL."))
    if s["trust"]:
        out.append(_f("MCP_TRUSTED_SERVER", "MEDIUM", fp, line,
                      f"{who} is marked trust: true, so the client runs its tools without asking. Remove it."))
    if lock is not None:
        entry = lock.get("servers", {}).get(server_key(s))
        if entry and entry.get("launch_sha256") and entry["launch_sha256"] != launch_hash(s):
            out.append(_f("MCP_LAUNCH_CHANGED", "MEDIUM", fp, line,
                          f"{who} launches differently from the approved version (command, arguments or env names changed). "
                          "Review it, then run mcp_scan.py --connect NAME --yes --approve."))
    return out


def describe(s: dict) -> str:
    if s["url"]:
        u = re.sub(r"\?.*$", "?...", shield.redact(s["url"], 200))
        return f"{s['transport']} {u}"
    return " ".join([s["command"]] + [_redact_arg(a) for a in s["args"]])[:400]


# ----------------------------------------------------------------------------------------------------- lock file

def server_key(s: dict) -> str:
    return f"{s['client']}:{s['name']}"


def launch_hash(s: dict) -> str:
    data = {"command": s["command"], "args": s["args"], "env_names": sorted(s["env"]), "url": s["url"]}
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def tool_hash(t: dict) -> str:
    data = {k: t.get(k) for k in ("name", "title", "description", "inputSchema", "outputSchema", "annotations")}
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def load_lock(fp: Path) -> dict:
    try:
        if not os.path.lexists(fp):
            return {"version": 1, "servers": {}}
        st = os.lstat(fp)
        if not stat.S_ISREG(st.st_mode) or st.st_size > CONFIG_MAX:
            raise ValueError("lock is not a small plain file")
        d = json.loads(fp.read_text(encoding="utf-8"))
        if not isinstance(d, dict) or not isinstance(d.get("servers"), dict):
            raise ValueError("malformed lock")
        return d
    except Exception as e:
        raise RuntimeError(f"cannot read {fp}: {e}") from None


def save_lock(fp: Path, lock: dict) -> None:
    fp.parent.mkdir(parents=True, exist_ok=True)
    if os.path.islink(fp.parent) or os.path.islink(fp):
        raise RuntimeError("refusing to write the lock through a link")
    tmp = fp.with_name(fp.name + ".tmp")
    tmp.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, fp)


# --------------------------------------------------------------------------------------------- tool poisoning

def _strings(x, out: list, depth=0):
    if depth > 32 or len(out) > 5000:
        return
    if isinstance(x, str):
        out.append(x)
    elif isinstance(x, dict):
        for k, v in x.items():
            out.append(str(k))
            _strings(v, out, depth + 1)
    elif isinstance(x, list):
        for v in x:
            _strings(v, out, depth + 1)


def show(s: str, n: int = 80) -> str:
    s = HIDDEN_UNICODE.sub(lambda m: "[U+%04X]" % ord(m.group(0)), s)
    s = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", s)
    return shield.redact(s, n)


def tool_findings(server: dict, tools: list[dict], other_tools: set[str], instructions: str = "") -> list[dict]:
    out = []
    fp, line, who = server["config"], server.get("line", 0), f"server '{server['name']}'"
    items = [("server instructions", instructions, {})] if instructions else []
    items += [(f"tool '{show(str(t.get('name', '?')), 60)}'", str(t.get("description") or ""), t) for t in tools]
    for label, desc, t in items:
        texts = [desc]
        _strings({k: t.get(k) for k in ("name", "title", "inputSchema", "annotations")}, texts)
        blob = "\n".join(texts)[:200_000]
        m = HIDDEN_UNICODE.search(blob)
        if m:
            out.append(_f("MCP_TOOL_HIDDEN_UNICODE", "HIGH", fp, line,
                          f"{who} {label} contains invisible or bidirectional characters (U+{ord(m.group(0)):04X}). Hidden "
                          "text in a tool description is read by the model but not by you."))
        m = INJECTION.search(blob)
        if m:
            out.append(_f("MCP_TOOL_INJECTION", "HIGH", fp, line,
                          f"{who} {label} contains instructions aimed at the model: '{show(m.group(0))}'."))
        else:
            m = INJECTION_WEAK.search(blob)
            if m:
                out.append(_f("MCP_TOOL_DIRECTIVE", "MEDIUM", fp, line,
                              f"{who} {label} gives the model directions ('{show(m.group(0))}'). Often harmless; read "
                              "the full description."))
        m = EXFIL.search(blob)
        if m:
            out.append(_f("MCP_TOOL_EXFIL", "HIGH", fp, line,
                          f"{who} {label} asks for data to be sent to a URL: '{show(m.group(0))}'."))
        m = SENSITIVE_PATH.search(blob)
        if m:
            out.append(_f("MCP_TOOL_SENSITIVE_PATH", "HIGH", fp, line,
                          f"{who} {label} mentions a credential file ('{show(m.group(0), 40)}'); a tool has no reason to "
                          "ask the model for it."))
        own = str(t.get("name") or "").lower()
        for sm in SHADOW.finditer(desc):
            ref = sm.group(1).lower()
            if ref != own and (ref in other_tools or ref in BUILTIN_TOOLS):
                out.append(_f("MCP_TOOL_SHADOWING", "HIGH", fp, line,
                              f"{who} {label} tries to change how another tool ('{show(ref, 40)}') is used: "
                              f"'{show(sm.group(0))}'."))
                break
        else:
            for ref in sorted(other_tools):
                if len(ref) >= 5 and ref != own and re.search(rf"(?i)(?<![\w-]){re.escape(ref)}(?![\w-])", desc):
                    out.append(_f("MCP_TOOL_CROSS_REFERENCE", "MEDIUM", fp, line,
                                  f"{who} {label} mentions another server's tool '{show(ref, 40)}'. Check that it does "
                                  "not try to steer that tool."))
                    break
        if len(desc) > 4000:
            out.append(_f("MCP_TOOL_LONG_DESCRIPTION", "LOW", fp, line,
                          f"{who} {label} has a {len(desc)}-character description; long descriptions are where hidden "
                          "instructions usually sit. Read it."))
    return out


def compare_lock(server: dict, tools: list[dict], lock: dict, instructions: str = "") -> tuple[list[dict], bool]:
    """Rug-pull findings against the pinned hashes, and whether an entry exists."""
    out = []
    entry = lock.get("servers", {}).get(server_key(server))
    if not entry:
        return out, False
    fp, line, who = server["config"], server.get("line", 0), f"server '{server['name']}'"
    pinned_tools = entry.get("tools") or {}
    now = {str(t.get("name")): tool_hash(t) for t in tools}
    for name, h in now.items():
        if name not in pinned_tools:
            out.append(_f("MCP_TOOL_NEW", "MEDIUM", fp, line,
                          f"{who} added tool '{show(name, 60)}' since it was approved. Review it, then --approve."))
        elif pinned_tools[name] != h:
            out.append(_f("MCP_TOOL_RUG_PULL", "HIGH", fp, line,
                          f"{who} tool '{show(name, 60)}' changed its description or schema since it was approved "
                          "(rug pull pattern). Review the new text, then re-approve with --approve."))
    for name in pinned_tools:
        if name not in now:
            out.append(_f("MCP_TOOL_REMOVED", "LOW", fp, line, f"{who} no longer offers tool '{show(name, 60)}'."))
    ih = entry.get("instructions_sha256")
    if isinstance(ih, str) and ih != hashlib.sha256(instructions.encode("utf-8")).hexdigest():
        out.append(_f("MCP_INSTRUCTIONS_CHANGED", "HIGH", fp, line,
                      f"{who} changed its server instructions since it was approved. Review them, then --approve."))
    return out, True


# ------------------------------------------------------------------------------------------- stdio connection

CMD_META = re.compile(r'["&|<>^%!\r\n()]')


def find_program(cmd: str, cwd: Path) -> str | None:
    """PATH lookup that never uses the current folder (like secgate.find_tool); absolute paths as given."""
    if os.path.isabs(cmd):
        return cmd if os.path.isfile(cmd) else None
    if "/" in cmd or "\\" in cmd:
        p = (cwd / cmd).resolve()
        return str(p) if p.is_file() else None
    here = os.path.normcase(os.path.realpath(os.getcwd()))
    exts = [""]
    if os.name == "nt" and not os.path.splitext(cmd)[1]:
        exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        d = d.strip('"')
        if not d or not os.path.isabs(d):
            continue
        rd = os.path.normcase(os.path.realpath(d))
        if rd == here or rd.startswith(here.rstrip(os.sep) + os.sep):
            continue
        for e in exts:
            c = os.path.join(d, cmd + e)
            if os.path.isfile(c) and (os.name == "nt" or os.access(c, os.X_OK)):
                return c
    return None


def _expand(v: str) -> str:
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                  lambda m: os.environ.get(m.group(1) or m.group(3), m.group(2) or ""), v)


def _system32() -> str:
    """The real System32 folder from the Windows API, never from an environment variable the caller controls."""
    import ctypes
    buf = ctypes.create_unicode_buffer(520)
    n = ctypes.windll.kernel32.GetSystemDirectoryW(buf, 520)
    if not n or n >= 520:
        raise OSError("GetSystemDirectoryW failed")
    return buf.value


def _kill(proc: subprocess.Popen) -> None:
    try:
        if proc.poll() is None:
            if os.name == "nt":
                taskkill = [os.path.join(_system32(), "taskkill.exe"), "/T", "/F", "/PID", str(int(proc.pid))]
                subprocess.run(taskkill, capture_output=True, timeout=10)
            else:
                import signal
                os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def list_tools(server: dict, project: Path, timeout: float = 20.0, max_bytes: int = 8_000_000) -> tuple[list[dict], str]:
    """Start the stdio server, initialize, page through tools/list. Returns (tools, instructions)."""
    if server["url"] or server["transport"] not in ("stdio", ""):
        raise RuntimeError("only stdio servers can be connected; remote servers are never contacted")
    cwd = Path(server["cwd"]).resolve() if server["cwd"] else project
    exe = find_program(server["command"], cwd)
    if not exe:
        raise RuntimeError(f"program not found on PATH: {server['command']}")
    if exe.lower().endswith((".bat", ".cmd")) and any(CMD_META.search(a) for a in server["args"]):
        raise RuntimeError("refused: an argument contains a character cmd.exe would interpret")
    env = dict(os.environ)
    env.update({k: _expand(v) for k, v in server["env"].items() if isinstance(v, str)})
    kw = {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen([exe, *server["args"]], cwd=str(cwd), env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **kw)
    q: queue.Queue = queue.Queue()
    used = [0]

    def reader():
        try:
            while True:
                line = proc.stdout.readline(max_bytes)
                if not line:
                    break
                used[0] += len(line)
                if used[0] > max_bytes:
                    q.put(None)
                    break
                q.put(line)
        except Exception:
            pass
        q.put(None)

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.monotonic() + timeout

    def send(obj):
        proc.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        proc.stdin.flush()

    def wait_for(rid):
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise RuntimeError(f"no answer within {timeout:.0f} s")
            try:
                line = q.get(timeout=left)
            except queue.Empty:
                raise RuntimeError(f"no answer within {timeout:.0f} s") from None
            if line is None:
                raise RuntimeError("the server closed its output or sent too much data")
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                continue                      # servers sometimes log to stdout; skip non-JSON lines
            if isinstance(msg, dict) and msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"server error: {show(json.dumps(msg['error'])[:200], 200)}")
                res = msg.get("result")
                if not isinstance(res, dict):
                    raise RuntimeError("malformed answer")
                return res

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "nexaforge-mcp-scan", "version": "7.0"}}})
        init = wait_for(1)
        instructions = init.get("instructions") if isinstance(init.get("instructions"), str) else ""
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools, cursor, rid = [], None, 2
        for _ in range(50):
            send({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {"cursor": cursor} if cursor else {}})
            res = wait_for(rid)
            page = res.get("tools")
            tools += [t for t in page if isinstance(t, dict)] if isinstance(page, list) else []
            cursor = res.get("nextCursor")
            rid += 1
            if not isinstance(cursor, str) or not cursor or len(tools) > 2000:
                break
        return tools, instructions
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        _kill(proc)


# ------------------------------------------------------------------------------------------------------- entry

def gate_findings(root: Path) -> tuple[list[dict], list[str]]:
    """Config-mode findings for secgate full/ci: project configs only, never user files, never a connect."""
    notes = []
    servers, findings = read_configs(root, None, include_user=False)
    lock = None
    try:
        lock = load_lock(root / ".security" / LOCK_NAME)
    except RuntimeError as e:
        notes.append(f"mcp-scan: {e}")
    for s in servers:
        findings += launch_findings(s, lock)
    if servers:
        notes.append(f"mcp-scan: {len(servers)} MCP server(s) in project configs checked offline (config mode, nothing started)")
    return findings, notes


def safe(s) -> str:
    return re.sub(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]", "?", str(s))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Offline MCP config scan, with an optional tools/list check of named stdio servers.")
    ap.add_argument("--project", default=".", help="project folder (default: current folder)")
    ap.add_argument("--home", help="home folder for user-level configs (default: your home)")
    ap.add_argument("--project-only", action="store_true", help="skip user-level configs")
    ap.add_argument("--connect", action="append", default=[], metavar="NAME", help="start this stdio server and list its tools")
    ap.add_argument("--yes", action="store_true", help="confirm starting the --connect servers (their code runs)")
    ap.add_argument("--approve", action="store_true", help="pin the current tool hashes of the --connect servers")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--lock", help="lock file (default: <project>/.security/mcp-lock.json)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="high")
    a = ap.parse_args(argv)
    project = Path(a.project).resolve()
    home = Path(a.home).resolve() if a.home else Path(os.path.expanduser("~"))
    lock_fp = Path(a.lock).resolve() if a.lock else project / ".security" / LOCK_NAME
    servers, findings = read_configs(project, home, include_user=not a.project_only)
    try:
        lock = load_lock(lock_fp)
    except RuntimeError as e:
        print(safe(f"ERROR: {e}"))
        return 3
    for s in servers:
        findings += launch_findings(s, lock)
    lines = []
    lock_changed = False
    listed = []                                    # (server, tools, instructions) of every server started
    for name in a.connect:
        matches = [s for s in servers if s["name"] == name]
        if not matches:
            lines.append(f"CONNECT {name}: no server with that name in the configs read")
            findings.append(_f("MCP_CONNECT_FAILED", "LOW", project, 0, f"server '{safe(name)[:60]}' not found"))
            continue
        s = matches[0]
        if len(matches) > 1:
            lines.append(f"CONNECT {name}: several configs define it; using {s['client']} ({s['config']})")
        plan = f"{s['client']} '{s['name']}': {describe(s)} (in {s['cwd'] or project})"
        if s["url"] or s["transport"] not in ("stdio", ""):
            lines.append(f"CONNECT {name}: remote server, not contacted (offline scan)")
            continue
        if not a.yes:
            lines.append(f"CONNECT {name}: would start {plan}. Its code runs on this machine. Re-run with --yes to start it.")
            continue
        lines.append(f"CONNECT {name}: starting {plan}")
        try:
            tools, instructions = list_tools(s, project, a.timeout)
        except Exception as e:
            lines.append(f"CONNECT {name}: failed ({show(str(e), 200)})")
            findings.append(_f("MCP_CONNECT_FAILED", "LOW", s["config"], s.get("line", 0),
                               f"server '{safe(name)[:60]}' could not be listed: {show(str(e), 160)}"))
            continue
        listed.append((s, tools, instructions))
    for s, tools, instructions in listed:
        name = s["name"]
        other = set()
        for o in servers:
            if o is not s:
                other |= {str(t).lower() for t in (lock.get("servers", {}).get(server_key(o), {}).get("tools") or {})}
        for o, otools, _ in listed:
            if o is not s:
                other |= {str(t.get("name")).lower() for t in otools}
        poison = tool_findings(s, tools, other, instructions)
        drift, had_entry = compare_lock(s, tools, lock, instructions)
        findings += poison + drift
        lines.append(f"CONNECT {name}: {len(tools)} tool(s): " + ", ".join(show(str(t.get('name')), 40) for t in tools[:40]))
        high = any(f["severity"] in ("HIGH", "CRITICAL") for f in poison)
        if a.approve or (not had_entry and not high):
            lock.setdefault("servers", {})[server_key(s)] = {
                "config": s["config"], "launch_sha256": launch_hash(s),
                "tools": {str(t.get("name")): tool_hash(t) for t in tools},
                "instructions_sha256": hashlib.sha256(instructions.encode("utf-8")).hexdigest(),
                "approved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "how": "approved with --approve" if a.approve else "first seen (trust on first use)"}
            lock_changed = True
            lines.append(f"CONNECT {name}: tool hashes pinned in {lock_fp}")
        elif not had_entry:
            lines.append(f"CONNECT {name}: NOT pinned, because the scan found HIGH issues. Review, then --approve.")
    if lock_changed:
        try:
            save_lock(lock_fp, lock)
        except Exception as e:
            print(safe(f"ERROR: lock not written: {e}"))
            return 3
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["file"], f["line"]))
    if a.json:
        print(json.dumps({"servers": [{"name": s["name"], "client": s["client"], "config": s["config"],
                                        "launch": describe(s), "env_names": sorted(s["env"]),
                                        "header_names": sorted(s["headers"])} for s in servers],
                          "findings": findings, "connect": lines}, indent=2))
    else:
        print("=== MCP SCAN (offline) ===")
        if not servers:
            print("No MCP servers found in the configs read.")
        for s in servers:
            print(safe(f"- {s['client']} '{s['name']}' ({s['config']}): {describe(s)}"))
            if s["env"]:
                print(safe(f"    env names: {', '.join(sorted(s['env']))}"))
            if s["headers"]:
                print(safe(f"    header names: {', '.join(sorted(s['headers']))}"))
        for ln in lines:
            print(safe(ln))
        for f in findings:
            print(safe(f"[{f['severity']}] {f['rule']} {f['file']}:{f['line']} {f['message']}"))
    th = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "never": None}[a.fail_on]
    blocked = bool(th and any(SEV_ORDER.get(f["severity"], 9) <= SEV_ORDER[th] for f in findings))
    if not a.json:
        print("RESULT: BLOCKED" if blocked else "RESULT: PASS")
    return 2 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
