"""Engines secgate already runs itself (collect_semgrep, collect_trivy, collect_gitleaks, collect_retire,
collect_psalm). Their adapters only report status and install plans; running and normalizing stays in secgate."""
from __future__ import annotations
from ._base import Engine


class _Secgate(Engine):
    run_by = "secgate"

    def argv(self, project, out_dir, ctx):          # pragma: no cover - never called for run_by="secgate"
        raise NotImplementedError

    def normalize(self, raw, project):              # pragma: no cover
        raise NotImplementedError


class Semgrep(_Secgate):
    name, command, languages = "semgrep", "semgrep", ("any",)
    finds = "SAST: injection, XSS, unsafe APIs, auth mistakes, with SecureCode's own rules plus registry packs"


class Trivy(_Secgate):
    name, command, languages = "trivy", "trivy", ("any",)
    finds = "known-vulnerable dependencies, IaC and container misconfigurations, secrets"


class Gitleaks(_Secgate):
    name, command, languages = "gitleaks", "gitleaks", ("any",)
    version_args = ("version",)
    finds = "secrets in source and git history"


class Retire(_Secgate):
    name, command, languages = "retire", "retire", ("node", "web")
    needs = ("node",)
    finds = "outdated front-end libraries with known vulnerabilities (jQuery, Bootstrap, Angular...)"


class Psalm(_Secgate):
    name, command, languages = "psalm", None, ("php",)
    version_args = ()
    finds = "PHP taint analysis: user input reaching SQL, shell, file and HTML sinks (needs --run-tests)"

    def locate(self, find=None):
        return None   # lives in each project's vendor/bin; secgate looks there itself
