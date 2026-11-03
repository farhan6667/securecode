"""osv-scanner (Google, Apache-2.0): lockfiles and manifests checked against the OSV database.
Note: it sends package names and versions to api.osv.dev."""
from __future__ import annotations
from ._base import PKG, Engine, NotRunnable, cvss_to_sev, finding, items, load_json, rel

CI_CONFIG = PKG / "config" / "osv-scanner-ci.toml"


class OsvScanner(Engine):
    name, command, languages = "osv-scanner", "osv-scanner", ("any",)
    finds = "known-vulnerable dependencies in lockfiles (npm, PyPI, Go, Maven, NuGet, Composer, crates...)"
    timeout = 900

    def argv(self, project, out_dir, ctx):
        exe = self.locate(ctx.find)
        if not exe:
            raise NotRunnable("not installed")
        cmd = [exe, "scan", "source", "-r", "--format", "json"]
        if ctx.mode == "ci":
            # --config replaces every osv-scanner.toml in the repo, so a repo cannot ignore its own vulnerabilities.
            if not CI_CONFIG.is_file():
                raise NotRunnable("ci config missing from the package")
            cmd += ["--config", str(CI_CONFIG)]
        return cmd + ["."], project, self.timeout, None, None

    def exit_ok(self, rc, raw, err):
        # 0 clean, 1 vulnerabilities found, 128 no packages found (nothing to check is not an error)
        if rc == 128:
            return True, "no lockfiles found"
        return super().exit_ok(rc, raw, err)

    def normalize(self, raw, project):
        data = load_json(raw)
        out = []
        for res in items(data, "results"):
            if not isinstance(res, dict):
                continue
            src = rel((res.get("source") if isinstance(res.get("source"), dict) else {}).get("path", ""), project)
            for pkg in items(res, "packages"):
                if not isinstance(pkg, dict):
                    continue
                info = pkg.get("package") if isinstance(pkg.get("package"), dict) else {}
                vulns = {str(v.get("id")): v for v in items(pkg, "vulnerabilities") if isinstance(v, dict) and v.get("id")}
                groups = [g for g in items(pkg, "groups") if isinstance(g, dict) and items(g, "ids")]
                if not groups:      # older output without groups: one finding per vulnerability
                    groups = [{"ids": [i], "aliases": items(v, "aliases"), "max_severity": ""} for i, v in vulns.items()]
                for g in groups:
                    ids = [str(i) for i in items(g, "ids")]
                    first = vulns.get(ids[0]) or {}
                    out.append(finding("osv-scanner", ids[0], cvss_to_sev(g.get("max_severity")), src, 0,
                                       f"{info.get('name', 'package')} {info.get('version', '')} ({info.get('ecosystem', '')}): "
                                       f"{first.get('summary') or 'known vulnerability'}. See https://osv.dev/{ids[0]}",
                                       aliases=sorted({str(a) for a in items(g, "aliases") + ids})))
        return out
