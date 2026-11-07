"""Shared test setup: the test suite must never write into this repository's own .security/guard-audit.jsonl.

Many guard tests run the guard with the repository as the working folder. The guard logs every "ask" to
<project>/.security/guard-audit.jsonl, so before this file existed those runs filled the real audit file with made-up asks
(`cp .env.example .env`, `Read C:\\Users\\u\\.npmrc`, ...) that a person reading it would take for real ones.

Two layers: (1) the in-process guard refuses to write an audit line for the repository itself (and the guard itself never logs
into its own source folder); (2) at the end of the run the size of the real file is compared with the size at the start, and any growth
fails the run, which also catches a test that runs the guard in a subprocess.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / ".security" / "guard-audit.jsonl"


def _size():
    try:
        return AUDIT.stat().st_size
    except OSError:
        return None


_START = _size()


def _is_repo(path) -> bool:
    try:
        p = Path(os.path.realpath(str(path)))
        return p == ROOT or ROOT in p.parents
    except (OSError, ValueError, TypeError):
        return False


@pytest.fixture(autouse=True)
def _tests_never_write_the_repos_own_audit(monkeypatch):
    g = sys.modules.get("agent_guard")
    real = getattr(g, "audit_ask", None) if g is not None else None
    if real is not None and not getattr(real, "_repo_safe", False):
        def audit_ask(event, *args, **kwargs):
            project = os.environ.get("CLAUDE_PROJECT_DIR") or (event.get("cwd") if isinstance(event, dict) else "") or ""
            if project and _is_repo(project):
                return False                       # never log a test's ask into the repository's own audit file
            return real(event, *args, **kwargs)
        audit_ask._repo_safe = True
        monkeypatch.setattr(g, "audit_ask", audit_ask)
    yield


def pytest_sessionfinish(session, exitstatus):
    now = _size()
    if now != _START:
        sys.stderr.write(f"\nA test wrote to the repository's own guard audit file ({AUDIT}): size {_START} -> {now}. "
                         "Give the test its own CLAUDE_PROJECT_DIR.\n")
        session.exitstatus = 1
