"""Java engines, both started as separate Java processes (never linked into SecureCode):
OWASP Dependency-Check (Apache-2.0) and SpotBugs with Find Security Bugs (LGPL; the official findsecbugs-cli
bundle, which carries SpotBugs itself)."""
from __future__ import annotations
import os
from pathlib import Path
from ._base import PKG, Engine, NotRunnable, cvss_to_sev, finding, items, load_json, rel, sarif_findings

SPOTBUGS_INCLUDE = PKG / "config" / "spotbugs-security-include.xml"
# Analyzers that start other programs inside the scanned repo (yarn can run a repo-supplied yarnPath, pnpm and
# bundle-audit read repo config, go mod and dotnet run toolchains) or send data to third parties. npm audit,
# Retire.js and govulncheck already run as their own engines.
DC_DISABLED = ["--disableYarnAudit", "--disablePnpmAudit", "--disableNodeAudit", "--disableGolangMod", "--disableAssembly",
               "--disableBundleAudit", "--disableMixAudit", "--disableOssIndex", "--disableRetireJs", "--disableCocoapodsAnalyzer",
               "--disableSwiftPackageManagerAnalyzer"]
DC_EXCLUDES = ["**/node_modules/**", "**/.git/**", "**/.security/**", "**/.venv/**", "**/venv/**"]


class DependencyCheck(Engine):
    name, command, languages = "dependency-check", None, ("java", "dotnet")
    needs = ("java",)
    finds = "known-vulnerable Java (Maven, Gradle, JAR) and .NET dependencies, matched against the NVD"
    timeout = 3600
    version_args = ()

    def base(self):
        return self.install_dir() / "dependency-check"

    def argv(self, project, out_dir, ctx):
        jar = self.locate(ctx.find)
        if not jar:
            raise NotRunnable("not installed")
        java = ctx.find("java")
        if not java:
            raise NotRunnable("java is not on PATH")
        base, lib = self.base(), self.base() / "lib"
        cmd = [java, "-XX:+IgnoreUnrecognizedVMOptions", "-Dapp.name=dependency-check", f"-Dapp.repo={lib}",
               f"-Dapp.home={base}", f"-Dbasedir={base}", f"-javaagent:{jar}={base / 'plugins'}", "-jar", jar,
               "--project", "securecode-scan", "--scan", str(project), "--format", "JSON", "--out", str(out_dir),
               "--disableVersionCheck", *DC_DISABLED]
        for x in DC_EXCLUDES:
            cmd += ["--exclude", x]
        key = os.environ.get("NVD_API_KEY", "")
        if key:
            # The key goes in a private properties file, never on the command line (process lists are readable).
            props = out_dir / "dependency-check.properties"
            props.write_text("nvd.api.key=" + key.replace("\n", "").replace("\r", "") + "\n", encoding="utf-8")
            cmd += ["--propertyfile", str(props)]
        data = os.environ.get("SECGATE_DEPCHECK_DATA", "")
        if data and os.path.isabs(data):
            cmd += ["--data", data]
        if os.environ.get("SECGATE_DEPCHECK_NOUPDATE") == "1":
            cmd.append("--noupdate")
        return cmd, out_dir, self.timeout, None, out_dir / "dependency-check-report.json"

    def normalize(self, raw, project):
        data = load_json(raw)
        out = []
        for dep in items(data, "dependencies"):
            if not isinstance(dep, dict):
                continue
            for v in items(dep, "vulnerabilities"):
                if not isinstance(v, dict) or not v.get("name"):
                    continue
                sev = str(v.get("severity", "")).upper()
                sev = {"MODERATE": "MEDIUM"}.get(sev, sev)
                if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    sev = cvss_to_sev((v.get("cvssv3") or {}).get("baseScore") if isinstance(v.get("cvssv3"), dict) else None)
                out.append(finding("dependency-check", v["name"], sev, rel(dep.get("filePath") or dep.get("fileName", ""), project), 0,
                                   f"{dep.get('fileName', 'dependency')}: {str(v.get('description') or 'known vulnerability')[:200]}",
                                   aliases=[str(v["name"])]))
        return out


def compiled_inputs(project, limit=50):
    """Folders of compiled classes and built jars. SpotBugs reads bytecode only, so nothing here is executed."""
    root = Path(project)
    found = []
    skip = {".git", "node_modules", ".security", ".venv", "venv", "vendor"}
    for r, dirs, _ in os.walk(root):
        depth = len(Path(r).relative_to(root).parts)
        dirs[:] = [d for d in dirs if d not in skip and not os.path.islink(os.path.join(r, d))] if depth < 5 else []
        here = Path(r)
        if here.name == "target" and (here / "classes").is_dir():
            found.append(here / "classes")
            found += sorted(p for p in here.glob("*.jar") if p.is_file() and not p.is_symlink())
            dirs[:] = []
        elif here.name == "build" and (here / "classes").is_dir():
            found += [p for p in (here / "classes").glob("*/main") if p.is_dir()]
            found += sorted(p for p in (here / "libs").glob("*.jar") if p.is_file() and not p.is_symlink())
            dirs[:] = []
        if len(found) >= limit:
            break
    return found[:limit]


class SpotBugs(Engine):
    name, command, languages = "spotbugs", None, ("java",)
    needs = ("java",)
    finds = "Java bytecode: SQL, command, LDAP and XPath injection, XXE, unsafe deserialization, weak crypto, path traversal"
    timeout = 1800
    version_args = ()

    def argv(self, project, out_dir, ctx):
        plugin = self.locate(ctx.find)
        if not plugin:
            raise NotRunnable("not installed")
        java = ctx.find("java")
        if not java:
            raise NotRunnable("java is not on PATH")
        inputs = compiled_inputs(project)
        if not inputs:
            raise NotRunnable("no compiled classes (target/classes or build/classes); build the project first")
        report = out_dir / "spotbugs.sarif"
        cmd = [java, "-cp", str(self.install_dir() / "lib" / "*"), "edu.umd.cs.findbugs.LaunchAppropriateUI", "-textui",
               "-quiet", "-effort:max", "-pluginList", plugin, "-include", str(SPOTBUGS_INCLUDE),
               "-sarif", "-output", str(report), *map(str, inputs)]
        return cmd, out_dir, self.timeout, None, report

    def normalize(self, raw, project):
        return sarif_findings("spotbugs", raw, project, prefix="FINDSECBUGS_")
