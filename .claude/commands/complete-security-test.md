---
description: "Complete security test of the whole project (deep review, fixes, retest and the script-made report)."
---
Use the global `org-appsec-security` skill, Mode B, exactly as for "Complete Security Test". Review the whole project, not only the latest changes. Run the full gate (`--run-tests` already runs the project tests, so do not run them separately) and run it again after each fix round, review entry point by entry point, record what the review found, fix, retest with evidence (at most three fix rounds), then let `report.py` write the report. Finish with the gate verdict, what was fixed, what is still open and what was not tested. Do not attack production. Do not hide or downgrade findings, and do not say the project passed a pentest.
