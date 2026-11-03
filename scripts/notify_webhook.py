#!/usr/bin/env python3
"""Optional generic webhook notifier. Requires SECURITY_FINDINGS_WEBHOOK_URL and is opt-in."""
import json, os, sys, urllib.request
url=os.getenv('SECURITY_FINDINGS_WEBHOOK_URL')
if not url: sys.exit(0)
if not url.startswith('https://'):
    sys.exit('SECURITY_FINDINGS_WEBHOOK_URL must be an https:// URL')  # no file://, no plain http
with open(sys.argv[1],encoding='utf-8') as f: data=json.load(f)
findings=data.get('findings',[])
sev={s:sum(1 for x in findings if x.get('severity')==s) for s in ('CRITICAL','HIGH','MEDIUM','LOW')}
payload=json.dumps({'text':f"AI AppSec findings: CRITICAL={sev['CRITICAL']} HIGH={sev['HIGH']} MEDIUM={sev['MEDIUM']} LOW={sev['LOW']}"}).encode()
req=urllib.request.Request(url,data=payload,headers={'Content-Type':'application/json'},method='POST')
with urllib.request.urlopen(req,timeout=10) as r: r.read()
