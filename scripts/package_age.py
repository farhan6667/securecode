#!/usr/bin/env python3
"""Check that a package version exists and is old enough before an agent adds or upgrades it.

Freshly published versions are where hijacked releases and look-alike packages live (the s1ngularity
and Shai-Hulud npm waves were caught within days). The agent rules ask for a version that is at least
--min-days old (default 14) and for a name that really exists (slopsquatting).

    py -I scripts/package_age.py npm express 4.21.2
    py -I scripts/package_age.py pypi requests 2.32.3 --min-days 30
    py -I scripts/package_age.py packagist laravel/framework v12.3.0

Exit codes: 0 old enough, 1 too new, 2 not found or bad input, 3 registry unreachable.
Only the three public registries are contacted, over HTTPS, with a size and time limit.
"""
from __future__ import annotations
import argparse, datetime as dt, json, re, sys, urllib.error, urllib.parse, urllib.request

MAX_BYTES = 20_000_000
NAMES = {
    "npm": re.compile(r"(@[a-z0-9][a-z0-9._-]{0,213}/)?[a-z0-9][a-z0-9._-]{0,213}"),
    "pypi": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}"),
    # Simple, unambiguous classes (Composer's own pattern backtracks badly on long input).
    "packagist": re.compile(r"[a-z0-9][a-z0-9_.-]{0,99}/[a-z0-9][a-z0-9_.-]{0,99}"),
}
VERSION = re.compile(r"v?[0-9][0-9A-Za-z.+_-]{0,63}")


def fetch_json(url: str):
    if not url.startswith(("https://registry.npmjs.org/", "https://pypi.org/pypi/", "https://repo.packagist.org/p2/")):
        raise ValueError("refusing a non-registry URL")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "securecode-package-age"})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = r.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("registry answer too large")
    return json.loads(body.decode("utf-8"))


def published(eco: str, name: str, version: str, fetch=fetch_json) -> dt.datetime | None:
    if eco == "npm":
        data = fetch("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
        t = (data.get("time") or {}).get(version.lstrip("v"))
    elif eco == "pypi":
        data = fetch(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
        files = data.get("urls") or []
        t = min((f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")), default=None)
    else:
        data = fetch(f"https://repo.packagist.org/p2/{urllib.parse.quote(name, safe='/')}.json")
        t = next((v.get("time") for v in (data.get("packages") or {}).get(name, [])
                  if str(v.get("version", "")).lstrip("v") == version.lstrip("v")), None)
    if not t:
        return None
    return dt.datetime.fromisoformat(str(t).replace("Z", "+00:00")).astimezone(dt.timezone.utc)


def main(argv=None, fetch=fetch_json, now=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("ecosystem", choices=sorted(NAMES))
    ap.add_argument("name")
    ap.add_argument("version")
    ap.add_argument("--min-days", type=int, default=14)
    a = ap.parse_args(argv)
    if len(a.name) > 214 or len(a.version) > 64 or not NAMES[a.ecosystem].fullmatch(a.name) or not VERSION.fullmatch(a.version) or not 0 <= a.min_days <= 3650:
        print("bad input: check the package name, version and --min-days")
        return 2
    try:
        when = published(a.ecosystem, a.name, a.version, fetch)
    except urllib.error.HTTPError as e:
        print(f"{a.name} {a.version}: not found in {a.ecosystem} (HTTP {e.code}). Check the name; it may not exist.")
        return 2
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        print(f"registry unreachable or unreadable ({type(e).__name__}); nothing was checked")
        return 3
    if when is None:
        print(f"{a.name} {a.version}: this version is not published in {a.ecosystem}. Check the name and version.")
        return 2
    age = ((now or dt.datetime.now(dt.timezone.utc)) - when).days
    if age < a.min_days:
        print(f"{a.name} {a.version}: published {age} days ago, younger than {a.min_days} days. Use an older version or ask the user.")
        return 1
    print(f"{a.name} {a.version}: published {age} days ago, OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
