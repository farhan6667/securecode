"""Bandit (PyCQA, Apache-2.0): Python security linter."""
from __future__ import annotations
from ._base import PKG, Engine, NotRunnable, finding, items, load_json, rel

CI_INI = PKG / "config" / "bandit-ci.ini"
EXCLUDE = ",".join(f"./{d}" for d in (".git", ".venv", "venv", "node_modules", "vendor", ".tox", "build", "dist", ".security"))


class Bandit(Engine):
    name, command, languages = "bandit", "bandit", ("python",)
    finds = "Python: shell injection, eval/exec, pickle, weak crypto, TLS verification off, hardcoded passwords"

    def argv(self, project, out_dir, ctx):
        exe = self.locate(ctx.find)
        if not exe:
            raise NotRunnable("not installed")
        report = out_dir / "bandit.json"
        cmd = [exe, "-r", ".", "-f", "json", "-o", str(report), "-q", "-x", EXCLUDE]
        if ctx.mode == "ci":
            # --ini replaces the repo's .bandit file; --ignore-nosec drops "# nosec" comments in the code under review.
            if not CI_INI.is_file():
                raise NotRunnable("ci ini file missing from the package")
            cmd += ["--ini", str(CI_INI), "--ignore-nosec"]
        return cmd, project, self.timeout, None, report

    def normalize(self, raw, project):
        data = load_json(raw)
        out = []
        for r in items(data, "results"):
            if not isinstance(r, dict):
                continue
            sev = str(r.get("issue_severity", "MEDIUM")).upper()
            cwe = (r.get("issue_cwe") or {}).get("id") if isinstance(r.get("issue_cwe"), dict) else None
            out.append(finding("bandit", f"BANDIT_{r.get('test_id', '')}_{r.get('test_name', '')}".rstrip("_"),
                               sev if sev in ("HIGH", "MEDIUM", "LOW") else "MEDIUM",
                               rel(r.get("filename", ""), project), r.get("line_number", 0),
                               f"{r.get('issue_text', 'Bandit finding')}" + (f" (CWE-{cwe})" if cwe else ""),
                               r.get("code", ""), confidence=str(r.get("issue_confidence", ""))[:10]))
        return out
