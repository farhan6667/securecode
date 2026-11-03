"""Engines SecureCode never installs itself.

Security Code Scan (.NET, LGPL-3.0, separate process): the standalone `security-scan` runner builds the
solution with MSBuild, and a build runs the project's own targets, so it only runs with --run-tests (the same
rule as the project's test suite). Last release 2022: maintenance uncertain.

CodeQL: the CLI is under GitHub's own terms (free for open source and research, a paid GitHub licence for
private commercial code), so SecureCode never downloads it. When the user has installed it and sets
SECGATE_CODEQL=1, the gate builds a database without running a build (build-mode none) and runs the
security-extended suites."""
from __future__ import annotations
import os
from pathlib import Path
from ._base import Engine, NotRunnable, read_capped, sarif_findings


class SecurityCodeScan(Engine):
    name, command, languages = "security-code-scan", "security-scan", ("dotnet",)
    needs = ("dotnet",)
    optional = True
    finds = ".NET: SQL and command injection, XSS, path traversal, weak crypto, insecure deserialization (needs --run-tests)"
    timeout = 1800
    version_args = ()

    def argv(self, project, out_dir, ctx):
        exe = self.locate(ctx.find)
        if not exe:
            raise NotRunnable("not installed")
        if not ctx.run_tests:
            raise NotRunnable("builds the solution, so it runs only with --run-tests")
        sln = sorted(p for p in Path(project).glob("*.sln") if p.is_file() and not p.is_symlink())
        if not sln:
            raise NotRunnable("no .sln at the project root")
        report = out_dir / "security-code-scan.sarif"
        return [exe, str(sln[0]), f"--export={report}"], project, self.timeout, None, report

    def normalize(self, raw, project):
        return sarif_findings("security-code-scan", raw, project)


CODEQL_LANG = {"python": "python", "node": "javascript-typescript", "java": "java", "dotnet": "csharp"}
CODEQL_SUITE = {"python": "python", "javascript-typescript": "javascript", "java": "java", "csharp": "csharp"}


class CodeQL(Engine):
    name, command, languages = "codeql", "codeql", ("python", "node", "java", "dotnet")
    optional = True
    finds = "deep data-flow SAST (user input to dangerous sinks across files); opt-in, user-installed, licence permitting"
    timeout = 3600

    def plan_languages(self, project):
        from . import detect_languages
        return sorted({CODEQL_LANG[l] for l in detect_languages(project) if l in CODEQL_LANG})

    def run(self, project, out_dir, ctx):
        if os.environ.get("SECGATE_CODEQL") != "1":
            return None, "", "opt-in: set SECGATE_CODEQL=1 if your CodeQL licence covers this code"
        exe = self.locate(ctx.find)
        if not exe:
            return None, "", "not installed (install it yourself, see the README licence note)"
        langs = self.plan_languages(project)
        if not langs:
            return None, "", "no CodeQL language detected"
        db = out_dir / "codeql-db"
        # cwd is the private output folder, so a codeql-workspace.yml or qlpack in the repo cannot change packs.
        rc, out, err = ctx.run([exe, "database", "create", str(db), "--db-cluster", f"--language={','.join(langs)}",
                                f"--source-root={project}", "--build-mode=none", "--overwrite", "--threads=0"],
                               out_dir, self.timeout)
        if rc != 0:
            return False, "", f"database create exited {rc}: {(err or '')[-300:]}"
        raws = []
        for lang in langs:
            sarif = out_dir / f"codeql-{lang}.sarif"
            suite = f"codeql/{CODEQL_SUITE[lang]}-queries:codeql-suites/{CODEQL_SUITE[lang]}-security-extended.qls"
            rc, out, err = ctx.run([exe, "database", "analyze", str(db / lang), suite, "--format=sarif-latest",
                                    f"--output={sarif}", "--threads=0"], out_dir, self.timeout)
            if rc != 0 or not sarif.is_file():
                return False, "", f"analyze {lang} exited {rc}: {(err or '')[-300:]}"
            try:
                raws.append(read_capped(sarif))
            except (OSError, ValueError) as e:
                return False, "", f"report could not be read ({type(e).__name__})"
        return True, raws, "completed"

    def normalize(self, raw, project):
        out = []
        for r in (raw if isinstance(raw, list) else [raw]):
            out += sarif_findings("codeql", r, project, prefix="CODEQL_")
        return out
