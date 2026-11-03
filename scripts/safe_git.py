"""Run git, and scanners that run git, without honouring programs named in the scanned repository's config.

A repository controls .git/config (and files it includes). Git runs programs named there: core.fsmonitor on
status and diff, hooks under core.hooksPath, filter drivers (clean, smudge, process), diff textconv and external
diff commands, merge drivers, the pager, ssh and credential helpers. The stop gate and the scanners run git inside
the project, so a repo could run code on the developer's machine without any tool call the guard can see.

safe_git_env() returns an environment whose GIT_CONFIG_COUNT entries (command-line scope, which wins over every
config file) switch all of that off: fixed keys always, plus every driver key the repo's config actually defines,
found by `git config --list --name-only` (which only parses config files and never runs anything). Inherited GIT_*
variables are dropped so the caller's environment cannot point git elsewhere. The hooks path is an empty folder
that the caller removes afterwards.
"""
from __future__ import annotations
import os, re, shutil, subprocess, tempfile

DRIVER_KEY = re.compile(r"^(?:filter|diff|merge)\.(.+)\.(?:clean|smudge|process|textconv|command|driver|cachetextconv)$", re.I)
# diff.external cannot be switched off from here (an empty value makes git fail); git log and show only use it with
# --ext-diff, and the stop gate passes --no-ext-diff to git diff.
FIXED = [("core.fsmonitor", "false"), ("core.untrackedCache", "false"), ("core.quotePath", "false"),
         ("core.pager", "cat"), ("core.sshCommand", ""), ("core.askPass", ""), ("credential.helper", ""),
         ("core.alternateRefsCommand", ""), ("protocol.ext.allow", "never"), ("protocol.file.allow", "never"),
         ("core.editor", ":"), ("sequence.editor", ":"), ("gpg.program", ""), ("uploadpack.packObjectsHook", ""),
         ("core.gitProxy", ""), ("submodule.recurse", "false"), ("diff.noprefix", "false")]


def _base_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    return env


def _with_pairs(env: dict, pairs: list) -> dict:
    env = dict(env)
    env["GIT_CONFIG_COUNT"] = str(len(pairs))
    for i, (k, v) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    return env


def safe_git_env(git_exe: str | None, root, hooks_dir: str) -> dict:
    """The environment for git (or a scanner that runs git) inside root."""
    pairs = list(FIXED) + [("core.hooksPath", hooks_dir)]
    env = _with_pairs(_base_env(), pairs)
    if git_exe:
        try:
            p = subprocess.run([git_exe, "config", "--list", "--name-only", "--includes", "-z"], cwd=str(root),
                               capture_output=True, timeout=20, env=env)
            names = p.stdout.decode("utf-8", "replace").split("\0") if p.returncode == 0 else []
        except Exception:
            names = []
        seen = set()
        for name in names:
            m = DRIVER_KEY.match(name.strip())
            if m and name.lower() not in seen and len(seen) < 200:
                seen.add(name.lower())
                # textconv, clean and smudge become the identity ("cat"), so diffs and status stay correct; anything
                # else (process, command, driver) becomes empty: git then fails or skips it, it never runs the repo's program
                last = name.strip().rsplit(".", 1)[-1].lower()
                pairs.append((name.strip(), "cat" if last in ("textconv", "clean", "smudge") else ""))
                if name.lower().startswith("filter."):
                    pairs.append((f"filter.{m.group(1)}.required", "false"))
        env = _with_pairs(_base_env(), pairs)
    return env


class SafeGit:
    """Context manager: .run(*args) runs git in root with the safe environment; the empty hooks folder is removed on exit."""

    def __init__(self, git_exe: str, root):
        self.exe, self.root = git_exe, root
        self.hooks = tempfile.mkdtemp(prefix="nfsc-nohooks-")
        self.env = safe_git_env(git_exe, root, self.hooks)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.hooks, ignore_errors=True)

    def run(self, *args, timeout: int = 20):
        p = subprocess.run([self.exe, *args], cwd=str(self.root), capture_output=True, timeout=timeout, env=self.env)
        return p.returncode, p.stdout.decode("utf-8", "replace")
