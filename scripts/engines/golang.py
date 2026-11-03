"""Go engines: gosec (Apache-2.0) and govulncheck (Go team, BSD-3-Clause).

Both load the module with the Go toolchain. They run with GOTOOLCHAIN=local (a go.mod 'toolchain' line cannot
make Go download another toolchain), CGO_ENABLED=0 (no C compiler runs) and GOWORK=off (a go.work file
in the repo cannot pull in folders outside it). govulncheck sends module paths to vuln.go.dev."""
from __future__ import annotations
import json
from pathlib import Path
from ._base import Engine, NotRunnable, finding, items, load_json, rel, scrubbed_env

GO_ENV = {"GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOWORK": "off"}


def _go_env():
    return scrubbed_env(GO_ENV)


class Gosec(Engine):
    name, command, languages = "gosec", "gosec", ("go",)
    needs = ("go",)
    finds = "Go: SQL and command injection, path traversal, weak crypto, TLS settings, unsafe file permissions"
    version_args = ("-version",)

    def argv(self, project, out_dir, ctx):
        exe = self.locate(ctx.find)
        if not exe:
            raise NotRunnable("not installed")
        if not ctx.find("go"):
            raise NotRunnable("go is not on PATH")
        report = out_dir / "gosec.json"
        cmd = [exe, "-fmt=json", f"-out={report}", "-no-fail", "-quiet"]
        if ctx.mode == "ci":
            cmd.append("-nosec")     # #nosec and //gosec:disable comments in the code under review do not count
        return cmd + ["./..."], project, self.timeout, _go_env(), report

    def exit_ok(self, rc, raw, err):
        return (True, "completed") if str(raw).strip() else (False, f"exited {rc} without a report")

    def normalize(self, raw, project):
        data = load_json(raw)
        out = []
        for i in items(data, "Issues"):
            if not isinstance(i, dict):
                continue
            sev = str(i.get("severity", "MEDIUM")).upper()
            cwe = (i.get("cwe") or {}).get("id") if isinstance(i.get("cwe"), dict) else None
            out.append(finding("gosec", f"GOSEC_{i.get('rule_id', '')}", sev if sev in ("HIGH", "MEDIUM", "LOW") else "MEDIUM",
                               rel(i.get("file", ""), project), i.get("line", 0),   # "12" or "12-14"
                               f"{i.get('details', 'gosec finding')}" + (f" (CWE-{cwe})" if cwe else ""),
                               i.get("code", ""), confidence=str(i.get("confidence", ""))[:10]))
        return out


class Govulncheck(Engine):
    name, command, languages = "govulncheck", "govulncheck", ("go",)
    needs = ("go",)
    finds = "Go: known vulnerabilities in modules, ranked by whether your code really calls the vulnerable function"
    version_args = ("-version",)

    def argv(self, project, out_dir, ctx):
        exe = self.locate(ctx.find)
        if not exe:
            raise NotRunnable("not installed")
        if not ctx.find("go"):
            raise NotRunnable("go is not on PATH")
        return [exe, "-format", "json", "./..."], project, self.timeout, _go_env(), None

    def exit_ok(self, rc, raw, err):
        # with -format json the exit code is 0 even when vulnerabilities are found
        if rc == 0 and str(raw).strip():
            return True, "completed"
        return False, f"exited {rc}: {(err or '').strip()[-300:]}"

    @staticmethod
    def messages(raw):
        """govulncheck -format json writes a stream of JSON objects, not one document."""
        if isinstance(raw, list):
            return raw
        dec = json.JSONDecoder()
        s, i, out = str(raw or ""), 0, []
        if len(s) > 50_000_000:
            raise ValueError("report too large")
        while i < len(s):
            while i < len(s) and s[i].isspace():
                i += 1
            if i >= len(s):
                break
            obj, i = dec.raw_decode(s, i)
            out.append(obj)
        return out

    def normalize(self, raw, project):
        osv, best = {}, {}
        for m in self.messages(raw):
            if not isinstance(m, dict):
                continue
            if isinstance(m.get("osv"), dict) and isinstance(m["osv"].get("id"), str):
                osv[m["osv"]["id"]] = m["osv"]
            f = m.get("finding")
            if not isinstance(f, dict) or not isinstance(f.get("osv"), str) or not f["osv"]:
                continue
            trace = [t for t in items(f, "trace") if isinstance(t, dict)]
            top = trace[0] if trace else {}
            level = 2 if top.get("function") else 1 if top.get("package") else 0
            prev = best.get(f["osv"])
            if prev is None or level > prev[0]:
                best[f["osv"]] = (level, f, top)
        out = []
        for vid, (level, f, top) in best.items():
            info = osv.get(vid, {})
            # trace[0] is the vulnerable symbol; the last frame with a position is the call site in your code
            frames = [t for t in items(f, "trace") if isinstance(t, dict) and isinstance(t.get("position"), dict)]
            pos = frames[-1]["position"] if frames else {}
            where = rel(pos.get("filename", ""), project) if level == 2 and pos.get("filename") else "go.mod"
            called = {2: "your code calls the vulnerable function", 1: "a vulnerable package is imported but the "
                      "vulnerable function is not called", 0: "a required module has a vulnerability that your code does not reach"}[level]
            out.append(finding("govulncheck", vid, "HIGH" if level == 2 else "LOW", where, pos.get("line", 0) if level == 2 else 0,
                               f"{top.get('module', 'module')} {top.get('version', '')} -> {f.get('fixed_version') or 'no fixed version'}: "
                               f"{info.get('summary') or 'known vulnerability'} ({called})",
                               aliases=sorted({str(a) for a in items(info, "aliases") + [vid]})))
        return out
