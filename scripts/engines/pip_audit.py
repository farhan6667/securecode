"""pip-audit (PyPA, Apache-2.0): pinned Python requirements checked against the PyPI/OSV advisories.

It runs with --no-deps --disable-pip, so it never creates a virtual environment, never installs the
project's requirements and never builds an sdist (any of which would run code from the scanned repo).
The trade-off: only pinned (==) requirements are checked; transitive pins need a lock-style requirements file.
pip-audit does not rate severity; findings are MEDIUM unless Trivy or osv-scanner already reported them."""
from __future__ import annotations
from pathlib import Path
from ._base import Engine, NotRunnable, finding, items, load_json, rel


def requirement_files(project):
    p = Path(project)
    files = sorted(x for x in p.glob("requirements*.txt") if x.is_file() and not x.is_symlink())
    return files[:10]


class PipAudit(Engine):
    name, command, languages = "pip-audit", "pip-audit", ("python",)
    finds = "known-vulnerable pinned Python packages in requirements*.txt"
    timeout = 600

    def argv(self, project, out_dir, ctx):
        exe = self.locate(ctx.find)
        if not exe:
            raise NotRunnable("not installed")
        reqs = requirement_files(project)
        if not reqs:
            raise NotRunnable("no requirements*.txt at the project root (osv-scanner covers lockfiles)")
        report = out_dir / "pip-audit.json"
        cmd = [exe, "--no-deps", "--disable-pip", "--progress-spinner", "off", "-f", "json", "-o", str(report)]
        for r in reqs:
            cmd += ["-r", str(r)]
        return cmd, project, self.timeout, None, report

    def normalize(self, raw, project):
        data = load_json(raw)
        out = []
        req = rel(requirement_files(project)[0], project) if requirement_files(project) else "requirements.txt"
        for d in items(data, "dependencies"):
            if not isinstance(d, dict):
                continue
            for v in items(d, "vulns"):
                if not isinstance(v, dict) or not v.get("id"):
                    continue
                fix = ", ".join(str(x) for x in items(v, "fix_versions")[:3]) or "no fixed version"
                out.append(finding("pip-audit", v["id"], "MEDIUM", req, 0,
                                   f"{d.get('name', 'package')} {d.get('version', '')} -> {fix}: "
                                   f"{str(v.get('description') or 'known vulnerability')[:200]}",
                                   aliases=sorted({str(a) for a in items(v, "aliases") + [v["id"]]})))
        return out
