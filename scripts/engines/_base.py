"""Shared parts of the engine adapters: the pinned versions, where tools live, how a tool is found and run,
and the helpers every normalizer uses.

Every adapter follows the same contract:
  detect(project, langs)  should this engine run here (manifest files, never a user string)
  status(find)            installed? where? which version?
  install_plan()          what setup would download, from where, at which version and checksum
  argv(project, out, ctx) the exact argument list (no shell), its working folder, timeout and environment
  run(project, out, ctx)  runs it and returns the raw report text
  normalize(raw, project) turns the report into secgate's finding dicts
"""
from __future__ import annotations
import json, os, platform, re, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent.parent                       # the SecureCode package root
LOCK = json.loads((HERE / "engines.lock.json").read_text(encoding="utf-8"))
SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
MAX_REPORT = 50_000_000                        # bytes of engine output we are willing to parse
SKIP = {".git", "node_modules", "vendor", "dist", "build", "coverage", ".next", "venv", ".venv", "__pycache__",
        "target", ".security", ".tox", ".gradle", "bin", "obj"}
# Control characters, bidi overrides and zero-width characters never reach a report or a terminal.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
# Characters cmd.exe treats specially. A .bat or .cmd file is always run through cmd.exe, which re-parses its
# arguments (the BatBadBut class of bugs), so such a call is refused when any argument contains one of them.
_CMD_META = re.compile(r'["&|<>^%!\r\n]')


class NotRunnable(Exception):
    """The engine cannot run in this project (nothing to scan, or a runtime is missing)."""


def clean(s, n=300):
    return _CONTROL.sub("?", str(s if s is not None else ""))[:n]


def platform_key():
    s = platform.system().lower()
    m = platform.machine().lower()
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(m, m)
    return f"{s}-{arch}"


def tools_root():
    """Where setup installs tools: outside every project and outside the SecureCode app folder, so an
    update of either never removes them. NEXAFORGE_TOOLS_DIR overrides it (absolute paths only)."""
    env = os.environ.get("NEXAFORGE_TOOLS_DIR", "")
    if env and os.path.isabs(env):
        return Path(env)
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")) / "NexaForgeTools"
    return Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")) / "nexaforge-tools"


def setup_command(system=None):
    """The exact command a person types to install missing engines, pointing at the installed runtime (so it
    works from any project folder). Same text in the README, the gate's NOTE and doctor."""
    s = (system or platform.system()).lower()
    if s == "windows":
        return 'py -I "%LOCALAPPDATA%\\OrgAISecureAppSec\\scripts\\securecode.py" setup'
    if s == "darwin":
        return 'python3 -I "$HOME/Library/Application Support/OrgAISecureAppSec/scripts/securecode.py" setup'
    return 'python3 -I "${XDG_DATA_HOME:-$HOME/.local/share}/OrgAISecureAppSec/scripts/securecode.py" setup'


def inside(child, parent):
    c = os.path.normcase(os.path.realpath(str(child)))
    p = os.path.normcase(os.path.realpath(str(parent))).rstrip(os.sep)
    return c == p or c.startswith(p + os.sep)


def find_tool(name):
    """PATH only, same rules as secgate.find_tool: the current folder, relative PATH entries and anything
    inside the scanned tree are never searched, so a planted osv-scanner.bat in a repo cannot run."""
    if os.path.isabs(name):
        return name if os.path.isfile(name) else None
    here = os.getcwd()
    exts = [""]
    if os.name == "nt" and not os.path.splitext(name)[1]:
        exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        d = d.strip('"')
        if not d or not os.path.isabs(d) or inside(d, here):
            continue
        for e in exts:
            c = os.path.join(d, name + e)
            if os.path.isfile(c) and (os.name == "nt" or os.access(c, os.X_OK)):
                return c
    return None


def execute(argv, cwd, timeout=600, env=None):
    """Run an argument list (never a shell string) with a timeout. Returns (rc, stdout, stderr)."""
    exe = find_tool(str(argv[0]))
    if not exe:
        return 127, "", f"missing executable: {argv[0]}"
    if exe.lower().endswith((".bat", ".cmd")) and any(_CMD_META.search(str(a)) for a in argv[1:]):
        return 126, "", "refused: an argument contains a character cmd.exe would interpret"
    try:
        p = subprocess.run([exe, *map(str, argv[1:])], cwd=str(cwd), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout, env=env, shell=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"missing executable: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {argv[0]}"
    except OSError as e:
        return 125, "", str(e)


class Ctx:
    """What an engine needs from its caller. secgate passes its own find_tool and run so the gate and the
    engines share one way of finding and starting programs (and tests can replace both)."""

    def __init__(self, find=None, runner=None, mode="full", run_tests=False):
        self.find = find or find_tool
        self.runner = runner or execute
        self.mode = mode
        self.run_tests = run_tests

    def run(self, argv, cwd, timeout, env=None):
        if env is None:
            return self.runner(argv, cwd, timeout)
        return self.runner(argv, cwd, timeout, env=env)


def scrubbed_env(extra=None):
    """The caller's environment plus fixed values. Used for Go so a repo cannot pull a toolchain or run cgo."""
    env = dict(os.environ)
    env.update(extra or {})
    return env


def read_capped(path):
    p = Path(path)
    if not p.is_file():
        return ""
    if p.stat().st_size > MAX_REPORT:
        raise ValueError(f"report larger than {MAX_REPORT // 1_000_000} MB")
    return p.read_text(encoding="utf-8", errors="replace")


def load_json(raw):
    if isinstance(raw, (dict, list)):
        return raw
    if raw is None or not str(raw).strip():
        return None
    if len(raw) > MAX_REPORT:
        raise ValueError("report too large")
    return json.loads(raw)


def rel(path, project):
    """Project-relative path when the file is inside the project, otherwise the cleaned original."""
    s = str(path or "")
    if not s:
        return ""
    try:
        p = Path(s)
        if not p.is_absolute():
            p = Path(project) / p
        r = p.resolve().relative_to(Path(project).resolve())
        return clean(r.as_posix(), 400)
    except (ValueError, OSError):
        return clean(s.replace("\\", "/"), 400)


def to_int(v):
    try:
        m = re.match(r"\s*(\d{1,9})", str(v))
        return int(m.group(1)) if m else 0
    except (TypeError, ValueError):
        return 0


def items(d, key):
    """d[key] when d is a dict and the value is a list, else []. Engine output is untrusted input too."""
    v = d.get(key) if isinstance(d, dict) else None
    return v if isinstance(v, list) else []


def cvss_to_sev(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"
    if s != s:                                       # NaN
        return "MEDIUM"
    return "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW"


def finding(engine, rule, sev, file, line, message, code="", **extra):
    f = {"rule": clean(rule, 200), "severity": sev if sev in SEV else "MEDIUM", "file": file, "line": to_int(line),
         "message": clean(message, 400), "code": clean(code, 180), "engine": engine}
    f.update(extra)
    return f


def sarif_findings(engine, raw, project, level_map=None, prefix=""):
    """Shared SARIF 2.1.0 reader (SpotBugs, Security Code Scan, CodeQL)."""
    data = load_json(raw)
    out = []
    lm = level_map or {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
    for run in items(data, "runs"):
        if not isinstance(run, dict):
            continue
        for r in items(run, "results"):
            if not isinstance(r, dict):
                continue
            locs = items(r, "locations")
            loc = (locs[0].get("physicalLocation") if locs and isinstance(locs[0], dict) else None) or {}
            loc = loc if isinstance(loc, dict) else {}
            art = loc.get("artifactLocation") if isinstance(loc.get("artifactLocation"), dict) else {}
            reg = loc.get("region") if isinstance(loc.get("region"), dict) else {}
            uri, line = art.get("uri", ""), reg.get("startLine", 0)
            msg = (r.get("message") or {}).get("text", "") if isinstance(r.get("message"), dict) else ""
            sev = lm.get(str(r.get("level", "warning")).lower(), "MEDIUM")
            out.append(finding(engine, f"{prefix}{r.get('ruleId', engine)}", sev, rel(uri, project), line, msg or engine))
    return out


class Engine:
    name = ""            # key in engines.lock.json and in reports
    command = None       # program name looked up on PATH when setup did not install it
    languages = ()       # "any" or language keys from detect_languages()
    finds = ""           # one line for doctor and the README table
    needs = ()           # runtimes the engine itself needs: "java", "go", "node", "npm", "dotnet"
    run_by = "engines"   # "secgate" for the engines secgate already runs itself
    optional = False     # never counted as missing (opt-in or uncertain-maintenance engines)
    version_args = ("--version",)
    timeout = 900

    # --- pins ---
    def pin(self):
        return LOCK["engines"].get(self.name, {})

    @property
    def licence(self):
        return self.pin().get("licence", "")

    @property
    def kind(self):
        return self.pin().get("kind", "manual")

    def install_dir(self):
        return tools_root() / self.name / str(self.pin().get("version", "x")).lstrip("v")

    def installed_path(self):
        """Where setup puts this engine's main file, or None when setup does not install it."""
        p = self.pin()
        k = p.get("kind")
        d = self.install_dir()
        if k == "download":
            art = (p.get("artifacts") or {}).get(platform_key()) or (p.get("artifacts") or {}).get("any")
            return d / art["exe"] if art else None
        if k == "pip":
            return d / "venv" / ("Scripts" if os.name == "nt" else "bin") / ((self.command or self.name) + (".exe" if os.name == "nt" else ""))
        if k == "go":
            return d / "bin" / ((self.command or self.name) + (".exe" if os.name == "nt" else ""))
        if k == "npm":
            return d / "node_modules" / ".bin" / ((self.command or self.name) + (".cmd" if os.name == "nt" else ""))
        return None

    def locate(self, find=find_tool):
        p = self.installed_path()
        if p is not None and p.is_file() and not inside(p, os.getcwd()):
            return str(p)
        return find(self.command) if self.command else None

    def missing_runtimes(self, find=find_tool):
        return [r for r in self.needs if not find(r)]

    # --- the contract ---
    def detect(self, project, langs=None):
        from . import detect_languages
        langs = detect_languages(project) if langs is None else langs
        return "any" in self.languages or bool(set(self.languages) & set(langs))

    def status(self, find=find_tool):
        path = self.locate(find)
        st = {"engine": self.name, "installed": bool(path), "path": path or "", "version": "",
              "pinned": str(self.pin().get("version", "")), "licence": self.licence, "kind": self.kind,
              "missing_runtimes": self.missing_runtimes(find)}
        if path and self.version_args:
            st["version"] = self.read_version(path)
        return st

    def read_version(self, path):
        argv = self.version_cmd(path)
        if not argv:
            return ""
        rc, out, err = execute(argv, tools_root() if tools_root().is_dir() else Path.home(), 60)
        m = re.search(r"\d+\.\d+(?:\.\d+)?", (out or "") + " " + (err or ""))
        return m.group(0) if m else "unknown"

    def version_cmd(self, path):
        return [path, *self.version_args]

    def install_plan(self):
        from ._install import plan_for
        return plan_for(self)

    def argv(self, project, out_dir, ctx):
        raise NotImplementedError

    def run(self, project, out_dir, ctx):
        """Returns (ok, raw, message). ok=None means 'not run' (reason in message)."""
        try:
            argv, cwd, timeout, env, report = self.argv(project, out_dir, ctx)
        except NotRunnable as e:
            return None, "", str(e)
        rc, out, err = ctx.run(argv, cwd, timeout, env)
        if rc in (124, 125, 126, 127):
            return False, "", clean(err or f"exited {rc}", 300)
        try:
            raw = read_capped(report) if report else out
        except (OSError, ValueError) as e:
            return False, "", f"report could not be read ({type(e).__name__})"
        ok, why = self.exit_ok(rc, raw, err)
        return ok, raw, why

    def exit_ok(self, rc, raw, err):
        if rc in (0, 1) and str(raw).strip():
            return True, "completed"
        return False, clean(f"exited {rc}: {(err or '').strip()[-300:]}", 400)

    def normalize(self, raw, project):
        raise NotImplementedError
