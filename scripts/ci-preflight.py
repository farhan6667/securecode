import shutil,sys
required=["semgrep","trivy","gitleaks"]
missing=[x for x in required if not shutil.which(x)]
if missing:
    print("Missing required CI scanners:",", ".join(missing))
    raise SystemExit(3)
print("All required AppSec scanners are present.")
