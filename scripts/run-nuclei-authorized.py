#!/usr/bin/env python3
"""Run nuclei (MIT, ProjectDiscovery) against an authorized staging URL only.

Same gate as run-zap-authorized.py: nothing runs unless SECURITY_DAST_ALLOW=true and SECURITY_DAST_URL
are set by a person. Intrusive, denial-of-service and fuzzing templates are excluded, the request rate
is capped, and production, cloud metadata, link-local, private and loopback addresses are refused (see
dast_target.py; private hosts only when a person names them in SECURITY_DAST_PRIVATE_HOSTS). Only test
systems you are allowed to test.
"""
import os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run with python -I
from secgate import find_tool  # noqa: E402
from dast_target import Refused, check_staging, default_resolver  # noqa: E402


def check_url(url: str, resolver=default_resolver, env=None) -> str | None:
    """Returns an error message, or None when the URL is acceptable. The host is resolved once here."""
    if not isinstance(url, str) or not re.fullmatch(r"https?://[A-Za-z0-9.\-\[\]:_]+(:\d{1,5})?(/[^\s]*)?", url):
        return "SECURITY_DAST_URL must be a plain http(s) URL"
    try:
        check_staging(url, resolver, env)
    except Refused as e:
        return str(e)
    return None


def main() -> int:
    url = os.environ.get("SECURITY_DAST_URL", "")
    if os.environ.get("SECURITY_DAST_ALLOW", "").lower() != "true" or not url:
        print("nuclei not run: SECURITY_DAST_ALLOW=true and SECURITY_DAST_URL are required.")
        return 4
    err = check_url(url)
    if err:
        print(f"nuclei not run: {err}")
        return 4
    nuclei = find_tool("nuclei")
    if not nuclei:
        print("nuclei not run: nuclei is not installed (see ENTERPRISE_DEPLOYMENT.md)")
        return 4
    # nuclei resolves the name again itself; a host whose DNS answer changes between this check and the scan
    # can still move it (documented in SECURITY-CONTEXT.md). The URL is set by a person, not by the repo.
    cmd = [nuclei, "-u", url, "-severity", "medium,high,critical", "-etags", "dos,intrusive,fuzz,bruteforce",
           "-rl", "30", "-c", "10", "-jsonl", "-o", "nuclei-results.jsonl", "-duc", "-silent"]
    print("Running authorized non-production nuclei scan:", cmd)
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
