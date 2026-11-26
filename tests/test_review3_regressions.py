"""Regressions from the third independent review (guard bypasses, planted scanners, CI output)."""
import importlib.util, os, subprocess, sys, tempfile
from pathlib import Path

from test_agent_guard import decide, tool

ROOT = Path(__file__).resolve().parents[1]
SECGATE = ROOT / "scripts" / "secgate.py"
H = "C:/Users/x"


def bash(cmd, cwd=None):
    e = tool("Bash", command=cmd)
    if cwd:
        e["cwd"] = cwd
    return e


DENY = [
    # git used to skip the protected-path check entirely
    bash(f"git show HEAD:evil.json > {H}/.claude/settings.json"),
    bash(f"git --work-tree={H}/.claude --git-dir=evil/.git checkout -f HEAD -- settings.json"),
    bash(f"git -C {H}/.claude checkout -- settings.json"),
    # force push shapes
    bash("git push -fu origin main"),
    bash("git -c a=b -C . push --force"),
    bash("git.exe push --force"),
    bash("g''it push --force"),
    bash("git push origin --delete main"),
    # public repo shapes
    bash("gh repo create leak --public=true --push"),
    bash("gh.exe repo create leak --public"),
    tool("PowerShell", command="cmd /c gh repo create leak --public"),
    bash("gh repo edit leak --visibility public"),
    bash("gh repo edit leak --visibility=public"),
    bash("gh api -X POST user/repos -f name=leak -F private=false"),
    # path normalisation
    bash(f"cp evil.json ~/./.claude/settings.json"),
    bash(f"cp evil.json {H}/AppData/../.claude/settings.json"),
    tool("PowerShell", command="Copy-Item evil.json ${env:USERPROFILE}\\.claude\\settings.json"),
    bash("cd ~ && cp evil.json .claude/settings.json"),
    bash("cd ~/.claude && cp ../evil.json settings.json"),
    bash("cp evil.json \\\\localhost\\c$\\Users\\x\\.claude\\settings.json"),
    # escapes inside a secret name
    bash("cat .e\\nv"),
    tool("PowerShell", command="Get-Content .e`nv"),
    # 8.3 short names
    tool("Read", file_path="ENV~1"),
    tool("Read", file_path="C:\\app\\ENV~1.LOC"),
    tool("Write", file_path=f"{H}/CLAUDE~1/hooks/x.py", content="x"),
    # UNC and device paths to the user's Claude folder
    tool("Write", file_path="\\\\localhost\\c$\\Users\\x\\.claude\\hooks\\x.py", content="x"),
    tool("Write", file_path="\\\\?\\C:\\Users\\x\\.claude\\hooks\\x.py", content="x"),
    # tools with a shell command that the guard never looked at
    tool("Monitor", command="cat .env"),
    # MCP write tools with other path keys
    tool("mcp__fs__write_output", output_path="backend/.env", content="x"),
    tool("mcp__fs__upload", target="C:/Users/x/.ssh/id_ed25519"),
    tool("mcp__fs__write_any", uri="file:///C:/Users/x/.claude/hooks/x.py", content="x"),
]

ALLOW = [
    bash("git add config/allowed_signers"),
    bash('git commit -m "add the release key to allowed_signers"'),
    bash("git push origin main"),
    bash("git push -u origin main"),
    bash("gh repo create mine --private"),
    bash("cat .env.example"),
    bash("git log --oneline > notes.txt"),
    bash("cd src && cp a.txt b.txt"),
    tool("mcp__fs__write_file", path="src/app.py", content="print('hi')\nimport os  # reads .env"),
]


def test_review3_bypasses_are_denied():
    bad = [(e, r) for e in DENY if (r := decide(e)) != "deny"]
    assert not bad, bad


def test_review3_normal_work_is_still_allowed():
    bad = [(e, r) for e in ALLOW if (r := decide(e)) != "allow"]
    assert not bad, bad


def test_non_object_tool_input_fails_closed():
    assert decide({"tool_name": "Bash", "tool_input": ["rm -rf /"]}) == "deny"
    assert decide({"tool_name": "Bash", "tool_input": "rm -rf /"}) == "deny"


def test_a_scanner_planted_in_the_repo_never_runs():
    with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as empty:
        marker = Path(d, "MARKER.txt")
        for name in ("semgrep", "trivy", "gitleaks"):
            if os.name == "nt":
                Path(d, name + ".bat").write_text(f"@echo off\r\necho ran> \"{marker}\"\r\necho {{}}\r\n")
            else:
                f = Path(d, name)
                f.write_text(f"#!/bin/sh\necho ran > '{marker}'\necho '{{}}'\n")
                f.chmod(0o755)
        env = dict(os.environ)
        env.pop("NoDefaultCurrentDirectoryInExePath", None)
        env["PATH"] = os.pathsep.join([".", d, empty])   # relative entry and the repo itself
        p = subprocess.run([sys.executable, "-I", str(SECGATE), ".", "--mode", "full"], cwd=d, env=env,
                           text=True, capture_output=True, timeout=120, encoding="utf-8", errors="replace")
        assert not marker.exists(), p.stdout + p.stderr
        assert "PARTIAL SCAN" in p.stdout, p.stdout


def _secgate():
    spec = importlib.util.spec_from_file_location("secgate_mod", SECGATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_console_output_cannot_forge_lines():
    s = _secgate().safe_text("a.js\nRESULT: PASS\n::error::x\u202eevil")
    assert "\n" not in s and "\u202e" not in s and s.startswith("a.js?RESULT")


def test_null_scanner_json_does_not_crash():
    m = _secgate()
    findings = []
    real_run, real_find = m.run, m.find_tool
    try:
        m.find_tool = lambda name: name
        m.run = lambda cmd, cwd, timeout=600: (0, '{"Results": null}', "")
        assert m.collect_trivy(Path("."), findings)[0]
        m.run = lambda cmd, cwd, timeout=600: (0, '{"results": null}', "")
        assert m.collect_semgrep(Path("."), findings)[0]
    finally:
        m.run, m.find_tool = real_run, real_find
    assert findings == []


def test_symlinked_files_are_not_followed():
    with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
        secret = Path(outside, "secret.js")
        secret.write_text("const k = 'sk_live_" + "a" * 24 + "';\n")
        try:
            os.symlink(secret, Path(d, "a.js"))
        except (OSError, NotImplementedError):
            import pytest
            pytest.skip("symlinks need extra rights on this machine")
        files = _secgate().walk_files(d)
        assert not any(f.name == "a.js" for f in files)


def test_edit_hook_scans_only_the_changed_file():
    hook = ROOT / "scripts" / "global_hook.py"
    with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as other:
        Path(cwd, "old.py").write_text("import subprocess\nsubprocess.run(x, shell" + "=True)\n")
        changed = Path(other, "new.py")
        changed.write_text("print('hello')\n")
        event = {"tool_name": "Edit", "cwd": cwd, "tool_input": {"file_path": str(changed)}}
        env = {**os.environ, "SECURECODE_CACHE_DIR": other, "SECURECODE_HOOK_VERBOSE": "1"}   # verbose: show the PASS
        p = subprocess.run([sys.executable, "-I", str(hook)], input=__import__("json").dumps(event), text=True,
                           capture_output=True, timeout=60, encoding="utf-8", errors="replace", env=env)
        assert p.returncode == 0
        assert "RESULT: PASS" in p.stdout and "old.py" not in p.stdout, p.stdout
        bad = {"tool_name": "Edit", "cwd": cwd, "tool_input": ["x"]}
        q = subprocess.run([sys.executable, "-I", str(hook)], input=__import__("json").dumps(bad), text=True,
                           capture_output=True, timeout=60, encoding="utf-8", errors="replace")
        assert q.returncode == 0 and "Traceback" not in q.stderr


def test_hook_matchers_are_identical_and_include_monitor():
    # 7.0: the guard matcher is ".*" (every tool, Monitor and Artifact included) in all three places; the old
    # allowlist matcher must be gone everywhere. The exact check is in test_guard_positive_model.py.
    import re as _re
    for f in ("install-global.py", "install-managed.py", "enterprise-managed-settings.example.json"):
        text = (ROOT / f).read_text(encoding="utf-8")
        assert not _re.search(r"Read\|Edit\|Write\|[A-Za-z|]*\|mcp__\.\*", text), f


def test_updater_storage_hop_never_follows_a_second_redirect():
    import io, urllib.error, urllib.request
    import pytest
    from test_updater import make_app
    with tempfile.TemporaryDirectory() as d:
        mod, _ = make_app(Path(d))

        def opener_for(second):
            calls = []

            class Fake:
                def open(self, req, timeout=60):
                    calls.append(req.full_url)
                    if len(calls) == 1:
                        raise urllib.error.HTTPError(req.full_url, 302, "Found",
                                                     {"Location": "https://objects.githubusercontent.com/a"}, io.BytesIO())
                    return second(req)
            return lambda *a: Fake()

        def bounce(req):
            raise urllib.error.HTTPError(req.full_url, 302, "Found", {"Location": "http://evil.example/a"}, io.BytesIO())

        real = mod.urllib.request.build_opener
        try:
            mod.urllib.request.build_opener = opener_for(bounce)
            with pytest.raises(RuntimeError):
                mod.download("https://api.github.com/repos/o/r/releases/assets/1", "", Path(d) / "x")
            assert not (Path(d) / "x").exists() or (Path(d) / "x").stat().st_size == 0

            class Ok(io.BytesIO):
                status = 200
            mod.urllib.request.build_opener = opener_for(lambda req: Ok(b"zipbytes"))
            mod.download("https://api.github.com/repos/o/r/releases/assets/1", "", Path(d) / "y")
            assert (Path(d) / "y").read_bytes() == b"zipbytes"
        finally:
            mod.urllib.request.build_opener = real


def test_release_zip_takes_only_committed_files():
    import shutil as _sh
    git = _sh.which("git")
    if not git:
        import pytest
        pytest.skip("git not installed")
    with tempfile.TemporaryDirectory() as d:
        pkg = Path(d).resolve()                   # 8.3 short temp names (RUNNER~1) differ from PKG
        (pkg / "scripts" / "release").mkdir(parents=True)
        _sh.copy2(ROOT / "scripts" / "release" / "make_release.py", pkg / "scripts" / "release" / "make_release.py")
        (pkg / "README.md").write_text("x")
        (pkg / ".ai-media").mkdir()
        (pkg / ".ai-media" / "internal-draft.png").write_bytes(b"x")
        (pkg / "notes.txt").write_text("untracked")
        run = lambda *a: subprocess.run([git, "-C", str(pkg), *a], check=True, capture_output=True)
        import pytest
        run("init", "-q")
        spec = importlib.util.spec_from_file_location("mk_rel", pkg / "scripts" / "release" / "make_release.py")
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        with pytest.raises(SystemExit):           # nothing committed yet: refuse, never sign an empty zip
            m.release_files()
        run("add", "README.md", "scripts")
        run("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "x")
        (pkg / "README.md").write_text("changed but not committed")
        with pytest.raises(SystemExit):           # a dirty tracked file would ship bytes that are not in git
            m.release_files()
        (pkg / "README.md").write_text("x")
        names = {p.relative_to(pkg).as_posix() for p in m.release_files()}
        assert "README.md" in names and "scripts/release/make_release.py" in names
        assert not any(n.startswith(".ai-media") or n == "notes.txt" for n in names), names
        assert ".ai-media" in m.EXCLUDE_DIRS and "org-internal" in m.EXCLUDE_DIRS
