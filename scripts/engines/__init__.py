"""NexaForge SecureCode engine adapters: one small adapter per scanner, a language detector, and the loop
secgate uses in full and ci modes. See _base.py for the adapter contract and _install.py for setup."""
from __future__ import annotations
import os, shutil, tempfile
from pathlib import Path

from ._base import Ctx, SKIP, clean, find_tool, inside, tools_root
from .core import Gitleaks, Psalm, Retire, Semgrep, Trivy
from .osv_scanner import OsvScanner
from .bandit import Bandit
from .pip_audit import PipAudit
from .golang import Gosec, Govulncheck
from .node import EslintSecurity, NpmAudit
from .java import DependencyCheck, SpotBugs
from .dotnet_codeql import CodeQL, SecurityCodeScan

# Dependency engines first, so the code engines' results come after and duplicates are dropped in one place.
RUNNABLE = [OsvScanner(), NpmAudit(), PipAudit(), Govulncheck(), DependencyCheck(),
            Bandit(), Gosec(), EslintSecurity(), SpotBugs(), SecurityCodeScan(), CodeQL()]
ENGINES = [Semgrep(), Trivy(), Gitleaks(), Retire(), Psalm()] + RUNNABLE
BY_NAME = {e.name: e for e in ENGINES}

LANG_FILES = {
    "python": {"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock"},
    "node": {"package.json"},
    "go": {"go.mod"},
    "java": {"pom.xml", "build.gradle", "build.gradle.kts"},
    "php": {"composer.json"},
}
LANG_EXT = {".py": "python", ".java": "java", ".csproj": "dotnet", ".sln": "dotnet", ".fsproj": "dotnet",
            ".vbproj": "dotnet", ".html": "web", ".htm": "web"}


def detect_languages(project, max_files=20000, max_depth=8):
    """Languages present in the project, from manifest files and a few extensions. Links and the usual
    dependency and build folders are not walked."""
    root = Path(project)
    langs, seen = set(), 0
    for r, dirs, files in os.walk(root):
        depth = len(Path(r).relative_to(root).parts)
        dirs[:] = [d for d in dirs if d not in SKIP and not os.path.islink(os.path.join(r, d))] if depth < max_depth else []
        for f in files:
            seen += 1
            low = f.lower()
            for lang, names in LANG_FILES.items():
                if low in names or (lang == "python" and low.startswith("requirements") and low.endswith(".txt")):
                    langs.add(lang)
            lang = LANG_EXT.get(os.path.splitext(low)[1])
            if lang:
                langs.add(lang)
        if seen > max_files:
            break
    return langs


def relevant(project, langs=None):
    langs = detect_languages(project) if langs is None else langs
    return [e for e in ENGINES if e.detect(project, langs)]


def installed_tool_path(command):
    """The setup-installed copy of a tool secgate runs by name (semgrep, trivy, gitleaks, retire), or None."""
    for e in ENGINES:
        if e.command == command:
            p = e.installed_path()
            if p is not None and p.is_file() and not inside(p, os.getcwd()):
                return str(p)
    return None


def _dedupe_key_ids(f):
    return {str(a) for a in (f.get("aliases") or [])} | {str(f.get("rule", ""))}


def run_engines(root, findings, notes, mode="full", run_tests=False, find=None, runner=None):
    """Run every installed engine that fits the project's languages. A missing engine is a NOTE, never a
    failure; a crash or an unreadable report is a NOTE too, and its findings are reported as missing."""
    root = Path(root)
    langs = detect_languages(root)
    ctx = Ctx(find, runner, mode, run_tests)
    seen = {(str(f.get("rule", "")), str(f.get("file", "")).replace("\\", "/")) for f in findings if f.get("engine") == "trivy"}
    status = {}
    out_root = Path(tempfile.mkdtemp(prefix="nfsc-engines-"))      # outside the repo: no planted links to follow
    try:
        for e in RUNNABLE:
            if not e.detect(root, langs):
                continue
            d = out_root / e.name
            d.mkdir()
            try:
                ok, raw, msg = e.run(root, d, ctx)
            except Exception as ex:   # an engine must never crash the gate
                ok, raw, msg = False, "", f"{type(ex).__name__}"
            if ok is None:
                status[e.name] = "not run"
                if e.name == "codeql" and msg.startswith(("not installed", "opt-in")) and not e.locate(ctx.find):
                    continue
                hint = "install with securecode setup" if msg == "not installed" and e.kind in ("download", "pip", "go", "npm") else msg
                notes.append(clean(f"not run: {e.name} ({hint})", 300))
                continue
            if not ok:
                status[e.name] = "failed"
                notes.append(clean(f"{e.name}: did not complete: {msg}", 400))
                continue
            try:
                new = e.normalize(raw, root)
            except Exception as ex:
                status[e.name] = "failed"
                notes.append(f"{e.name}: report could not be read ({type(ex).__name__}); its findings are missing")
                continue
            added = 0
            for f in new:
                keys = {(i, str(f.get("file", ""))) for i in _dedupe_key_ids(f)}
                if f.get("aliases") is not None and keys & seen:
                    continue
                seen |= keys
                findings.append(f)
                added += 1
            status[e.name] = "ran"
            notes.append(f"{e.name}: completed, {added} findings")
    finally:
        shutil.rmtree(out_root, ignore_errors=True)
    return status
