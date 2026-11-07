#!/usr/bin/env python3
"""Org AI Secure AppSec Gate: signed auto-update from the organization's private GitHub repo.

Runs daily from Task Scheduler (Windows), a systemd user timer or launchd agent (install-global.py --update-timer)
or cron. Two runs never overlap (update.lock); a GitHub rate limit (403/429) is a logged back-off, not a failure;
each run records its time and result in update-state.json for verify-global.py. Steps:
1. Read config/update.json (repo, asset name, signer identity) from the installed app folder.
2. Ask GitHub for the latest release using the developer's own `gh` login (or GH_TOKEN /
   GITHUB_TOKEN). No token is shipped with the package.
3. Skip unless the release version is newer than the installed one (never downgrade).
4. Download the zip and its .sig, verify the signature with `ssh-keygen -Y verify` against the
   security team's public key in config/allowed_signers. No valid signature, no install.
5. Extract safely (no absolute paths, no "..", no links) and run install-global.py from it.
Everything is logged to update.log in the app folder. Any failure leaves the current install untouched.
"""
from __future__ import annotations
import json, os, re, shutil, subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request, zipfile
from pathlib import Path

NAMESPACE = "org-appsec-update"
APP = Path(__file__).resolve().parent.parent
LOG = APP / "update.log"
LOCK = APP / "update.lock"
STATE = APP / "update-state.json"   # last check time and result, and a rate-limit back-off; read by verify-global.py
MAX_ZIP = 50 * 1024 * 1024
MAX_BACKOFF = 24 * 3600             # a reset time further away than this is not trusted
# install-global.py exit code when everything installed but the daily update task could not be (re)created
# (for example schtasks failed). The update itself worked, so it is reported as "updated" with a schedule warning.
INSTALL_SCHEDULE_ONLY = 4


class RateLimited(Exception):
    """GitHub refused the request because of its rate limit; `until` is when to try again (epoch seconds)."""

    def __init__(self, until: float):
        super().__init__(f"GitHub rate limit, retry after {time.strftime('%Y-%m-%d %H:%M', time.localtime(until))}")
        self.until = until


def rate_limit_until(e, now: float = None) -> float | None:
    """The retry time for a GitHub 403 or 429 that is a rate limit, else None (a plain 403 stays an error)."""
    now = time.time() if now is None else now
    if not isinstance(e, urllib.error.HTTPError) or e.code not in (403, 429):
        return None
    h = e.headers or {}
    retry, remaining, reset = h.get("Retry-After"), h.get("X-RateLimit-Remaining"), h.get("X-RateLimit-Reset")
    until = None
    if retry and str(retry).strip().isdigit():
        until = now + int(str(retry).strip())
    elif remaining is not None and str(remaining).strip() == "0" and reset and str(reset).strip().isdigit():
        until = float(str(reset).strip())
    elif e.code == 429 or (remaining is not None and str(remaining).strip() == "0"):
        until = now + 3600
    if until is None:
        return None
    return min(max(until, now + 60), now + MAX_BACKOFF)


def read_state(app: Path = None) -> dict:
    try:
        f = (app or APP) / "update-state.json"
        if f.is_symlink() or f.stat().st_size > 4096:
            return {}
        d = json.loads(f.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def write_state(result: str, ok: bool, backoff_until: float | None = None, app: Path = None):
    st = {"last_check": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "result": str(result)[:200], "ok": bool(ok)}
    if backoff_until:
        st["backoff_until"] = int(backoff_until)
    f = (app or APP) / "update-state.json"
    try:
        if f.is_symlink():
            f.unlink()
        tmp = f.with_name(f.name + ".tmp")
        tmp.write_text(json.dumps(st) + "\n", encoding="utf-8")
        os.replace(tmp, f)
    except OSError:
        pass


def backoff_active(now: float = None) -> float | None:
    """A stored back-off that is still in the future (and not absurdly far, the file is in a user folder)."""
    now = time.time() if now is None else now
    until = read_state().get("backoff_until")
    if isinstance(until, (int, float)) and now < until <= now + MAX_BACKOFF:
        return float(until)
    return None


DEFAULT_PRODUCT = "NexaForge SecureCode"
ORG_OWNED = ("config/brand.json", "docs/ORG-FINDINGS.md")   # org files an update must never replace or remove
LAST_RELEASE: dict = {}


def log(msg: str):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def valid_product_name(v) -> bool:
    # Same allowlist as install-global.py (tests keep the two in step).
    if not isinstance(v, str) or not (1 <= len(v) <= 60) or not v.isprintable():
        return False
    if not (v[0].isalnum() and v[-1].isalnum()) or "  " in v:
        return False
    return all(c.isalnum() or c in " .-_()+," for c in v)


def product_name(app: Path = None) -> str:
    try:
        f = (app or APP) / "config" / "brand.json"
        if f.stat().st_size > 4096:
            return DEFAULT_PRODUCT
        name = json.loads(f.read_text(encoding="utf-8-sig")).get("product_name")
    except Exception:
        return DEFAULT_PRODUCT
    return name if valid_product_name(name) else DEFAULT_PRODUCT


def org_owned_snapshot(app: Path = None) -> dict:
    out = {}
    for rel in ORG_OWNED:
        f = (app or APP) / rel
        try:
            if f.is_file() and not f.is_symlink() and f.stat().st_size <= 1 << 20:
                out[rel] = f.read_bytes()
        except OSError:
            pass
    return out


def org_owned_restore(kept: dict, app: Path = None):
    # Belt and braces next to the installer's own rule: put back any org file the install changed.
    for rel, data in kept.items():
        f = (app or APP) / rel
        try:
            if f.is_symlink() or not f.is_file() or f.read_bytes() != data:
                if f.is_symlink():
                    f.unlink()
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(data)
                log(f"restored {rel} after install")
        except OSError as e:
            log(f"could not restore {rel}: {e}")


def _ver(t) -> str:
    return ".".join(map(str, t)) if t else "unknown"


def result_line(status: str = None, error: BaseException = None) -> str:
    """One plain line for a person running the updater by hand. Return codes are unchanged."""
    if error is not None:
        if isinstance(error, RateLimited):
            return f"GitHub rate limit reached, next try after {time.strftime('%H:%M', time.localtime(error.until))}, nothing installed"
        if isinstance(error, urllib.error.HTTPError):
            return f"GitHub answered HTTP {error.code}, nothing installed"
        if isinstance(error, (urllib.error.URLError, TimeoutError, ConnectionError)):
            return "no network or GitHub unreachable"
        return f"update check failed ({type(error).__name__}), nothing installed; see update.log"
    if status == "updated":
        return f"updated to {_ver(parse_version(LAST_RELEASE.get('tag', '')))}"
    if status == "updated-schedule-warning":
        return (f"updated to {_ver(parse_version(LAST_RELEASE.get('tag', '')))} (schedule warning: the daily update task "
                "could not be renewed; run the installer again)")
    if status == "up-to-date":
        return f"already up to date ({_ver(installed_version())})"
    if status == "SIGNATURE-INVALID":
        return "signature invalid, nothing installed"
    return {
        "not-configured": "auto-update is not configured (config/update.json), nothing to do",
        "busy": "another update check is running, try again later",
        "bad-release-tag": "latest release has an unreadable version tag, nothing installed",
        "installed-version-unknown": "installed version unknown (install-report.json), nothing installed; re-run the installer",
        "release-missing-signed-asset": "latest release has no signed package, nothing installed",
        "installer-not-found": "signed package has no installer, nothing installed",
        "VERSION-MISMATCH": "signed package version does not match the release tag, nothing installed",
        "download-incomplete": "download was incomplete (size differs from the release), nothing installed; the next run tries again",
    }.get(status, f"not updated: {status}")


def say(line: str):
    msg = f"{product_name()}: {line}"
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode())
    except (OSError, ValueError, AttributeError):
        pass   # no console (pythonw from Task Scheduler)


def parse_version(v: str):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(v).strip())
    return tuple(int(x) for x in m.groups()) if m else None


def installed_version():
    try:
        return parse_version(json.loads((APP / "install-report.json").read_text(encoding="utf-8")).get("version", ""))
    except Exception:
        return None


def token():
    for k in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(k):
            return os.environ[k]
    gh = shutil.which("gh")
    if gh:
        p = subprocess.run([gh, "auth", "token"], capture_output=True, text=True, timeout=30)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    return None


def retry_without_token(e) -> bool:
    """401, 403 (not a rate limit) or 404 with a token: worth one more try without it."""
    return isinstance(e, urllib.error.HTTPError) and e.code in (401, 403, 404) and not rate_limit_until(e)


def api(url: str, tok: str, accept="application/vnd.github+json"):
    # Only GitHub's API over HTTPS: release JSON is remote data, so a URL in it must never point at
    # file://, another host, or plain HTTP (the token is sent with every request).
    if not url.startswith("https://api.github.com/"):
        raise RuntimeError(f"refusing non-GitHub API URL: {url[:80]!r}")
    return urllib.request.urlopen(urllib.request.Request(url, headers=gh_headers(tok, accept)), timeout=60)


def gh_headers(tok, accept):
    # Public repos work without a token (a daily check is far below the anonymous rate limit);
    # the token is only sent when one exists, for private repos.
    h = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "org-appsec-updater"}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface the 30x so we can follow it ourselves without the token


def download(url: str, tok: str, dest: Path):
    # Asset downloads redirect to GitHub's object storage. urllib would forward the Authorization
    # header there, so follow the redirect manually, without the token, to GitHub's hosts only.
    if not url.startswith("https://api.github.com/"):
        raise RuntimeError(f"refusing non-GitHub asset URL: {url[:80]!r}")
    req = urllib.request.Request(url, headers=gh_headers(tok, "application/octet-stream"))
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(req, timeout=60)
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307, 308):
            raise
        loc = e.headers.get("Location", "")
        host = urllib.parse.urlparse(loc).hostname or ""
        if urllib.parse.urlparse(loc).scheme != "https" or not (host.endswith(".githubusercontent.com") or host == "github.com"):
            raise RuntimeError(f"unexpected download redirect to {host!r}")
        # The storage hop is fetched without the token and must answer 200 itself: no further
        # redirects, so it can never be bounced to plain http or another host.
        try:
            resp = opener.open(urllib.request.Request(loc, headers={"User-Agent": "org-appsec-updater"}), timeout=60)
        except urllib.error.HTTPError as e2:
            raise RuntimeError(f"download storage hop answered {e2.code}; only a direct 200 is accepted")
        if getattr(resp, "status", 200) != 200:
            resp.close()
            raise RuntimeError(f"download storage hop answered {resp.status}; only a direct 200 is accepted")
    with resp as r, open(dest, "wb") as f:
        total = 0
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ZIP:
                raise RuntimeError("download larger than the 50 MB limit")
            f.write(chunk)
        # A connection that drops mid-way can end the read early without an error: compare with the announced length.
        length = (getattr(r, "headers", None) or {}).get("Content-Length")
        if length and str(length).isdigit() and int(length) != total:
            raise IncompleteDownload(f"got {total} of {length} bytes")


class IncompleteDownload(RuntimeError):
    pass


def size_matches(path: Path, expected) -> bool:
    """The asset size GitHub lists for the release. A missing or odd size is not judged here (the signature
    check still covers the content); a listed size must match exactly."""
    if isinstance(expected, bool) or not isinstance(expected, int) or expected <= 0:
        return True
    try:
        return path.stat().st_size == expected
    except OSError:
        return False


def signers_ok(signers: Path, identity: str) -> bool:
    # Only exact principals: a "*" or "?" pattern would let any key named anything sign updates.
    try:
        lines = [l.split() for l in signers.read_text(encoding="utf-8-sig").splitlines() if l.strip() and not l.lstrip().startswith("#")]
    except OSError:
        return False
    return bool(lines) and all(len(l) >= 3 and not any(c in l[0] for c in "*?!,") for l in lines) and any(l[0] == identity for l in lines)


def verify_signature(zip_path: Path, sig_path: Path, signers: Path, identity: str) -> bool:
    keygen = shutil.which("ssh-keygen")
    if not keygen or not signers.exists() or not signers_ok(signers, identity):
        return False
    # Notepad saves UTF-8 with a byte order mark, which ssh-keygen reads as part of the first principal's
    # name, so every update would fail. Verify against a clean copy of the same lines.
    clean = Path(tempfile.mkdtemp(prefix="sc-signers-")) / "allowed_signers"
    try:
        clean.write_text(signers.read_text(encoding="utf-8-sig"), encoding="utf-8")
        with open(zip_path, "rb") as fh:
            p = subprocess.run([keygen, "-Y", "verify", "-f", str(clean), "-I", identity, "-n", NAMESPACE, "-s", str(sig_path)],
                               stdin=fh, capture_output=True, text=True, timeout=60)
    finally:
        shutil.rmtree(clean.parent, ignore_errors=True)
    return p.returncode == 0


def safe_extract(zip_path: Path, dest: Path):
    root = dest.resolve()
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        if len(infos) > 5000 or sum(i.file_size for i in infos) > 200 * 1024 * 1024:
            raise RuntimeError("archive too large when unpacked")
        for info in infos:
            name = info.filename
            if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name) or ".." in re.split(r"[\\/]", name):
                raise RuntimeError(f"unsafe path in archive: {name!r}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise RuntimeError(f"symlink in archive: {name!r}")
            target = (dest / name).resolve()
            if root != target and root not in target.parents:
                raise RuntimeError(f"path escapes the folder: {name!r}")
        z.extractall(dest)


def find_installer(folder: Path) -> Path | None:
    hits = [p for p in folder.rglob("install-global.py") if len(p.relative_to(folder).parts) <= 3]
    return hits[0] if len(hits) == 1 else None


def check_and_update(cfg: dict, tok: str | None, *, fetch=None, workdir: Path | None = None) -> str:
    """Returns a short status. fetch(kind, url, dest) can be injected by tests."""
    repo, asset, identity = cfg.get("repo"), cfg.get("asset"), cfg.get("signer_identity")
    if not (repo and asset and identity and re.fullmatch(r"[\w.-]+/[\w.-]+", repo)):
        return "not-configured"
    try:
        if fetch is None:
            # tok may be None: fine for a public repo; a private repo then answers 404 and the check fails visibly.
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            try:
                with api(url, tok) as r:
                    rel = json.load(r)
            except urllib.error.HTTPError as e:
                if not (tok and retry_without_token(e)):
                    raise
                # A public repo needs no token, and a gh login for another account, an expired token or an SSO rule
                # answers 401, 403 or 404 for it. Ask once more as nobody; a private repo then fails visibly.
                log(f"release check with the gh login answered HTTP {e.code}; trying once without a token")
                tok = None
                with api(url, None) as r:
                    rel = json.load(r)
        else:
            rel = fetch("release", None, None)
    except urllib.error.HTTPError as e:
        until = rate_limit_until(e)
        if until:
            raise RateLimited(until) from None
        raise
    if not isinstance(rel, dict):
        return "bad-release-tag"
    LAST_RELEASE["tag"] = str(rel.get("tag_name", ""))[:40]   # only for the printed one-line result
    new = parse_version(rel.get("tag_name", ""))
    cur = installed_version()
    if not new:
        return "bad-release-tag"
    if not cur:
        return "installed-version-unknown"   # never guess: an unknown baseline would accept any old release
    if new <= cur:
        return "up-to-date"
    listed = [a for a in rel.get("assets", []) if isinstance(a, dict)] if isinstance(rel.get("assets"), list) else []
    assets = {a.get("name"): a.get("url") for a in listed}
    sizes = {a.get("name"): a.get("size") for a in listed}
    if asset not in assets or asset + ".sig" not in assets:
        return "release-missing-signed-asset"
    tmp = Path(workdir or tempfile.mkdtemp(prefix="orgappsec-upd-"))
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        zp, sp = tmp / asset, tmp / (asset + ".sig")
        for name, dest in ((asset, zp), (asset + ".sig", sp)):
            try:
                try:
                    (fetch or (lambda k, u, d: download(u, tok, d)))("asset", assets[name], dest)
                except urllib.error.HTTPError as e:
                    if not (tok and fetch is None and retry_without_token(e)):
                        raise
                    log(f"download of {name} with the gh login answered HTTP {e.code}; trying once without a token")
                    tok = None
                    download(assets[name], None, dest)
            except IncompleteDownload as e:
                log(f"download of {name} incomplete: {e}")
                return "download-incomplete"
            except urllib.error.HTTPError as e:
                until = rate_limit_until(e)
                if until:
                    raise RateLimited(until) from None
                raise
            if not size_matches(dest, sizes.get(name)):
                log(f"download of {name} incomplete: size differs from the release listing")
                return "download-incomplete"
        if not verify_signature(zp, sp, APP / "config" / "allowed_signers", identity):
            return "SIGNATURE-INVALID"
        ex = tmp / "x"; ex.mkdir()
        safe_extract(zp, ex)
        inst = find_installer(ex)
        if not inst:
            return "installer-not-found"
        # The tag is not signed, the zip is: the version inside the signed zip must match the tag and be
        # newer than what is installed, so an old signed zip re-published under a new tag is refused.
        m = re.search(r'VERSION\s*=\s*"(\d+\.\d+\.\d+)"', inst.read_text(encoding="utf-8", errors="ignore"))
        signed_ver = parse_version(m.group(1)) if m else None
        if signed_ver != new or signed_ver <= cur:
            return "VERSION-MISMATCH"
        py = sys.executable
        kept = org_owned_snapshot()
        try:
            p = subprocess.run([py, "-I", str(inst)], capture_output=True, text=True, timeout=600, encoding="utf-8", errors="replace")
        finally:
            org_owned_restore(kept)   # an update never renames the product or drops org files
        if p.returncode == INSTALL_SCHEDULE_ONLY:
            return "updated-schedule-warning"
        return "updated" if p.returncode == 0 else f"install-failed rc={p.returncode}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    for attempt in range(2):
        try:
            fd = os.open(str(LOCK), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            try:
                age = time.time() - LOCK.stat().st_mtime
                if 0 <= age < 3600 and attempt == 0:   # a real run in progress (a future mtime is not trusted)
                    log("update check skipped: another run holds the lock")
                    say(result_line("busy"))
                    return 0
                shutil.rmtree(LOCK) if LOCK.is_dir() else LOCK.unlink()
            except OSError as e:
                log(f"update check failed: cannot clear lock ({e})")
                say("cannot clear the update lock, nothing installed; see update.log")
                return 1
        except OSError as e:
            log(f"update check failed: cannot create lock ({e})")
            say("cannot create the update lock, nothing installed; see update.log")
            return 1
    else:
        say("cannot take the update lock, nothing installed")
        return 1
    try:
        until = backoff_active()
        if until:
            # GitHub said to wait: do not spend more of the rate limit until then. The state keeps the back-off.
            line = f"GitHub rate limit back-off until {time.strftime('%Y-%m-%d %H:%M', time.localtime(until))}, skipped"
            log(f"update check skipped: {line}")
            say(line)
            return 0
        cfg = json.loads((APP / "config" / "update.json").read_text(encoding="utf-8-sig"))
        status = check_and_update(cfg, token())
        log(f"update check: {status}")
        ok = status in ("updated", "updated-schedule-warning", "up-to-date", "not-configured")
        write_state(status, ok)
        say(result_line(status))
        return 0 if ok else 1
    except RateLimited as e:
        # Not a failure of this machine: log it, remember when to try again, exit cleanly.
        log(f"update check deferred: {e}")
        write_state("rate-limited", True, e.until)
        say(result_line(error=e))
        return 0
    except Exception as e:
        log(f"update check failed: {type(e).__name__}: {e}")
        write_state(result_line(error=e), False)
        say(result_line(error=e))
        return 1
    finally:
        LOCK.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
