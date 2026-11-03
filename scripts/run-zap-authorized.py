#!/usr/bin/env python3
"""Run an OWASP ZAP baseline (or the authenticated automation plan) against an authorized staging URL only.

Nothing runs unless a person set SECURITY_DAST_ALLOW=true and SECURITY_DAST_URL. The target gets the same
checks as run-nuclei-authorized.py (dast_target.py): cloud metadata, link-local, private and loopback
addresses are refused (private only when named in SECURITY_DAST_PRIVATE_HOSTS), the name is resolved once,
and the container gets that answer pinned with --add-host so its own lookup cannot be moved elsewhere.
Docker is found by an absolute PATH lookup (never the scanned folder).
"""
import os, re, subprocess, sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run with python -I
from secgate import find_tool  # noqa: E402
from dast_target import Refused, check_staging, default_resolver, literal_ip  # noqa: E402

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:2.17.0"


def build_cmd(env, cwd: Path, resolver=default_resolver, find=find_tool):
    """Returns (argv, None) or (None, error message)."""
    url = env.get("SECURITY_DAST_URL", "")
    plan = env.get("SECURITY_ZAP_PLAN", "zap/automation-template.yaml")
    active = env.get("SECURITY_DAST_ACTIVE", "false").lower() == "true"
    if not url or env.get("SECURITY_DAST_ALLOW", "").lower() != "true":
        return None, "DAST not run: SECURITY_DAST_ALLOW=true and SECURITY_DAST_URL are required."
    # Values from the environment become docker/ZAP arguments: allow only a plain http(s) URL and a
    # relative plan path inside the mounted folder (no leading dash, no traversal).
    if not re.fullmatch(r"https?://[A-Za-z0-9.\-_]+(:\d{1,5})?(/[^\s]*)?", url):
        return None, "DAST not run: SECURITY_DAST_URL must be a plain http(s) URL"
    if plan.startswith(("-", "/", "\\")) or ".." in re.split(r"[\\/]", plan) or not re.fullmatch(r"[\w./\\-]+\.ya?ml", plan):
        return None, "DAST not run: SECURITY_ZAP_PLAN must be a relative .yaml path inside the project"
    try:
        t, ips = check_staging(url, resolver, env)
    except Refused as e:
        return None, f"DAST not run: {e}"
    docker = find("docker")
    if not docker or not os.path.isabs(docker):
        return None, "DAST not run: docker is not installed (or not on PATH as an absolute path)"
    host = t["host"].rstrip(".")
    # a DNS name: pin the answer that was checked, so the container's own lookup cannot be rebound
    pin = [f"--add-host={host}:{ips[0]}"] if literal_ip(host) is None else []
    base = [docker, "run", "--rm", *pin, "-v", f"{cwd}:/zap/wrk/:rw", ZAP_IMAGE]
    if active and env.get("SECURITY_AUTH_LOGIN_URL") and env.get("SECURITY_DAST_USERNAME") and env.get("SECURITY_DAST_PASSWORD"):
        print("Authenticated active ZAP requires Docker and a populated plan; use the supplied automation template.")
        return base + ["zap.sh", "-cmd", "-autorun", f"/zap/wrk/{plan}"], None
    return base + ["zap-baseline.py", "-t", url, "-r", "zap-baseline.html", "-J", "zap-baseline.json"], None


def main(env=None, resolver=default_resolver, runner=subprocess.call, find=find_tool) -> int:
    env = os.environ if env is None else env
    cmd, err = build_cmd(env, Path.cwd(), resolver, find)
    if err:
        print(err)
        return 4
    print("Running authorized non-production DAST:", cmd)
    return runner(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
