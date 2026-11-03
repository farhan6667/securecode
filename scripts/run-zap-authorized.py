#!/usr/bin/env python3
import os,re,sys,subprocess
from pathlib import Path
url=os.environ.get("SECURITY_DAST_URL","")
allow=os.environ.get("SECURITY_DAST_ALLOW","").lower()=="true"
plan=os.environ.get("SECURITY_ZAP_PLAN","zap/automation-template.yaml")
active=os.environ.get("SECURITY_DAST_ACTIVE","false").lower()=="true"
if not url or not allow:
    print("DAST not run: SECURITY_DAST_ALLOW=true and SECURITY_DAST_URL are required.")
    raise SystemExit(4)
# Values from the environment become docker/ZAP arguments: allow only a plain http(s) URL and a
# relative plan path inside the mounted folder (no leading dash, no traversal).
if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?(/[^\s]*)?", url):
    raise SystemExit("SECURITY_DAST_URL must be a plain http(s) URL")
if plan.startswith(("-", "/", "\\")) or ".." in re.split(r"[\\/]", plan) or not re.fullmatch(r"[\w./\\-]+\.ya?ml", plan):
    raise SystemExit("SECURITY_ZAP_PLAN must be a relative .yaml path inside the project")
if active and os.environ.get("SECURITY_AUTH_LOGIN_URL") and os.environ.get("SECURITY_DAST_USERNAME") and os.environ.get("SECURITY_DAST_PASSWORD"):
    print("Authenticated active ZAP requires Docker and a populated plan; use the supplied automation template.")
    cmd=["docker","run","--rm","-v",f"{Path.cwd()}:/zap/wrk/:rw","ghcr.io/zaproxy/zaproxy:2.17.0","zap.sh","-cmd","-autorun",f"/zap/wrk/{plan}"]
else:
    cmd=["docker","run","--rm","-v",f"{Path.cwd()}:/zap/wrk/:rw","ghcr.io/zaproxy/zaproxy:2.17.0","zap-baseline.py","-t",url,"-r","zap-baseline.html","-J","zap-baseline.json"]
print("Running authorized non-production DAST:",cmd)
raise SystemExit(subprocess.call(cmd))
