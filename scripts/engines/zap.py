"""OWASP ZAP (Apache-2.0) for the local DAST step (scripts/local_dast.py). It does not scan source code, so the
gate never runs it; `securecode setup --engine zap` installs it and `doctor` shows it.

The official cross-platform zip is unpacked to <tools>/zap/ZAP_<version>/, where local_dast._zap_dirs() looks,
and is started as `java -jar zap-<version>.jar`. ZAP needs Java 17 or newer. SecureCode never installs Java: it
checks `java -version` and says clearly when Java is missing or too old."""
from __future__ import annotations
import re
from pathlib import Path
from ._base import Engine, execute, find_tool, tools_root

JAVA_MIN = 17


def java_major(text: str) -> int | None:
    """The major version from `java -version` output: 'version "17.0.9"' -> 17, 'version "1.8.0_392"' -> 8."""
    m = re.search(r'version\s+"(\d+)(?:\.(\d+))?', str(text or ""))
    if not m:
        return None
    major = int(m.group(1))
    if major == 1 and m.group(2):
        major = int(m.group(2))
    return major


def java_problem(find=find_tool, runner=execute):
    """None when a Java 17+ is on PATH, else a short reason ("java 17+ not on PATH", "java 17+ (found 11)")."""
    java = find("java")
    if not java:
        return f"java {JAVA_MIN}+ (not on PATH)"
    rc, out, err = runner([java, "-version"], str(Path.home()), 60)
    major = java_major((err or "") + "\n" + (out or ""))
    if major is None:
        return f"java {JAVA_MIN}+ (could not read the version of {java})"
    if major < JAVA_MIN:
        return f"java {JAVA_MIN}+ (found {major})"
    return None


class Zap(Engine):
    name, command, languages = "zap", None, ()
    optional = True
    needs = ("java",)
    finds = "local DAST only (local_dast.py): a passive or active OWASP ZAP scan of your own app on this machine"
    version_args = ()

    def install_dir(self):
        return tools_root() / "zap"

    def detect(self, project, langs=None):
        return False          # never part of a project's needed set; install it with --engine zap or --all

    def missing_runtimes(self, find=find_tool):
        p = java_problem(find)
        return [p] if p else []

    def status(self, find=find_tool):
        st = super().status(find)
        if st["installed"]:
            st["version"] = str(self.pin().get("version", ""))      # the jar's own name carries the version
        return st

    def argv(self, project, out_dir, ctx):
        raise NotImplementedError("ZAP is run by local_dast.py, not by the gate")
