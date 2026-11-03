#!/usr/bin/env python3
"""Fail CI when a test was skipped that is not on the explicit skip allowlist.

A skipped security test passes silently: in the past the test job skipped 15 scanner tests because semgrep,
gitleaks and ssh-keygen were missing, and nothing turned red. This reads the JUnit XML that pytest wrote and
checks every skipped test against tests/skip-allowlist.json. An entry names one test id (fnmatch pattern), the
reason, and optionally the OS and Python versions where the skip is allowed.

Usage: python -I scripts/ci/check_skips.py junit.xml [tests/skip-allowlist.json]
Exit 0: every skip is allowed. Exit 1: a skip is not allowed, or the input is unreadable (fails closed).
"""
from __future__ import annotations

import fnmatch
import json
import platform
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_BYTES = 50 * 1024 * 1024


def current_os() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


def node_id(classname: str, name: str) -> str:
    """pytest's JUnit classname "tests.test_x" (or "tests.test_x.TestClass") plus name -> "tests/test_x.py::name".
    A whole module skipped at import (importorskip) has an empty classname and the module as its name."""
    if not classname:
        return name.replace(".", "/") + ".py"
    mod = classname.split(".")
    cls = [mod.pop()] if len(mod) > 1 and mod[-1][:1].isupper() else []
    return "/".join(mod) + ".py::" + "::".join(cls + [name])


def skipped_tests(junit: Path) -> list[tuple[str, str]]:
    raw = junit.read_bytes()
    if len(raw) > MAX_BYTES or b"<!DOCTYPE" in raw[:4096].upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("JUnit file too large or holds a DOCTYPE/ENTITY declaration")
    root = ET.fromstring(raw)
    out = []
    for case in root.iter("testcase"):
        sk = case.find("skipped")
        if sk is not None:
            out.append((node_id(case.get("classname", ""), case.get("name", "")), (sk.get("message") or "").strip()))
    return out


def allowed(test: str, entries: list[dict], os_name: str, py: str) -> dict | None:
    for e in entries:
        if not fnmatch.fnmatchcase(test, e["test"]):
            continue
        if e.get("os") and os_name not in e["os"]:
            continue
        if e.get("python") and py not in e["python"]:
            continue
        return e
    return None


def load_allowlist(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("allowed") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError("allowlist must be {\"allowed\": [...]}")
    for e in entries:
        if not (isinstance(e, dict) and isinstance(e.get("test"), str) and e["test"] and isinstance(e.get("reason"), str) and e["reason"].strip()):
            raise ValueError(f"every allowlist entry needs a test pattern and a reason: {e!r}"[:300])
        for k in ("os", "python"):
            if k in e and not (isinstance(e[k], list) and all(isinstance(x, str) for x in e[k])):
                raise ValueError(f"'{k}' must be a list of strings: {e!r}"[:300])
    return entries


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 1
    junit = Path(argv[0])
    allow = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2] / "tests" / "skip-allowlist.json"
    try:
        skips = skipped_tests(junit)
        entries = load_allowlist(allow)
    except (OSError, ValueError, ET.ParseError) as e:
        print(f"SKIP CHECK FAILED: cannot read input ({type(e).__name__}: {e})")
        return 1
    os_name, py = current_os(), ".".join(platform.python_version_tuple()[:2])
    bad = []
    for test, msg in skips:
        e = allowed(test, entries, os_name, py)
        print(f"{'allowed' if e else 'NOT ALLOWED'}: {test} ({msg[:120]})" + (f" [allowlist: {e['reason'][:80]}]" if e else ""))
        if not e:
            bad.append(test)
    print(f"{len(skips)} skipped on {os_name} Python {py}; {len(bad)} not on the allowlist")
    if bad:
        print("Install the missing tool in CI or add the test to tests/skip-allowlist.json with a reason.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
