---
name: Compatibility report
about: Tell us how it ran on your machine and your stack (this helps the most)
labels: compatibility
---

**Setup**
- OS and version (Windows 10/11, macOS, Linux distro, WSL):
- Install type (per user, managed, CI only):
- AI tool and version:
- Python version:

**What you tried**
- [ ] Install and `verify-global.py`
- [ ] `Security Test Karo` or `Advisory QA Karo`
- [ ] `secgate.py --mode ci` on a real project (which stack?)
- [ ] The CI template (GitHub or GitLab)
- [ ] The signed auto-update

**What worked, what didn't**
False positives and missed findings are both useful. Remove secrets and internal names first.
