import os,sys,requests
base=os.environ.get("SECURITY_API_BASE_URL")
auth=os.environ.get("SECURITY_API_AUTH_HEADER")
uid=os.environ.get("SECURITY_API_USER_ID")
other=os.environ.get("SECURITY_API_OTHER_USER_ID")
if not all([base,auth,uid,other]):
    print("Set SECURITY_API_BASE_URL, SECURITY_API_AUTH_HEADER, SECURITY_API_USER_ID, SECURITY_API_OTHER_USER_ID")
    raise SystemExit(4)
# Explicit BOLA/IDOR negative test scaffold: endpoint MUST be customized per application.
# Expected behavior: authenticated user A must NOT retrieve object owned by user B.
endpoint=os.environ.get("SECURITY_API_OBJECT_ENDPOINT","/api/users/{id}")
url=base.rstrip("/") + endpoint.format(id=other)
r=requests.get(url,headers={"Authorization":auth},timeout=15)
print("Status:",r.status_code)
if r.status_code in (200,206):
    print("POTENTIAL_BOLA: user A accessed user B object. Investigate immediately.")
    raise SystemExit(2)
print("No obvious BOLA signal from this configured test.")
