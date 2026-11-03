#!/usr/bin/env python3
"""Run nuclei (MIT, ProjectDiscovery) against an authorized staging URL only.

Same gate as run-zap-authorized.py: nothing runs unless SECURITY_DAST_ALLOW=true and SECURITY_DAST_URL
are set by a person. Intrusive, denial-of-service and fuzzing templates are excluded, the request rate
is capped, and production, cloud metadata and link-local addresses are refused. Only test systems you
are allowed to test.
"""
import ipaddress, os, re, subprocess, sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run with python -I
from secgate import find_tool

BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata", "100.100.100.200", "fd00:ec2::254"}


def check_url(url: str) -> str | None:
    """Returns an error message, or None when the URL is acceptable."""
    if not re.fullmatch(r"https?://[A-Za-z0-9.\-\[\]:]+(:\d{1,5})?(/[^\s]*)?", url or ""):
        return "SECURITY_DAST_URL must be a plain http(s) URL"
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    if not host or host in BLOCKED_HOSTS or host.startswith("instance-data") or \
            re.search(r"(^|[.-])169[.-]254[.-]\d{1,3}[.-]\d{1,3}([.-]|$)", host):     # also 169.254.169.254.nip.io
        return "that host is a cloud metadata, link-local or empty address; refused"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return "link-local, multicast or unspecified addresses are refused"
    except ValueError:
        pass
    if re.search(r"(^|[.-])(prod|production|live)([.-]|$)", host) and os.environ.get("SECURITY_DAST_PROD_OK") != "yes":
        return "the host looks like production; set SECURITY_DAST_PROD_OK=yes only with written approval"
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
    cmd = [nuclei, "-u", url, "-severity", "medium,high,critical", "-etags", "dos,intrusive,fuzz,bruteforce",
           "-rl", "30", "-c", "10", "-jsonl", "-o", "nuclei-results.jsonl", "-duc", "-silent"]
    print("Running authorized non-production nuclei scan:", cmd)
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
