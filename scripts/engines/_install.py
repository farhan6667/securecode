"""Install plans and the installer behind `securecode.py setup`.

Rules: nothing is installed without the caller's explicit yes; every download comes from the publisher's
official release over https and is checked against the SHA-256 pinned in engines.lock.json before anything is
extracted or made executable; a mismatch deletes the file and stops. Package-manager routes use exact versions
and are checked afterwards (pip: the wheel's SHA-256 before install; go: the module hash recorded in the
binary; npm: the integrity value in the lockfile). No curl | sh, ever.
"""
from __future__ import annotations
import hashlib, json, os, re, shutil, stat, sys, tarfile, tempfile, time, urllib.parse, urllib.request, zipfile
from pathlib import Path, PurePosixPath

from ._base import clean, execute, find_tool, inside, platform_key, tools_root

ALLOWED_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
                 "github-releases.githubusercontent.com"}
MAX_DOWNLOAD = 400_000_000
NPM_REGISTRY = "https://registry.npmjs.org/"


class ChecksumMismatch(Exception):
    pass


class InstallError(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(path, expected):
    """Raise ChecksumMismatch (after deleting the file) unless the file has the expected SHA-256."""
    allowed = {expected} if isinstance(expected, str) else set(expected or ())
    allowed = {a.lower() for a in allowed if a}
    if not allowed:
        raise ChecksumMismatch("no pinned checksum; refusing to install an unverified file")
    got = sha256_file(path)
    if got.lower() not in allowed:
        try:
            os.remove(path)
        except OSError:
            pass
        raise ChecksumMismatch(f"SHA-256 mismatch for {Path(path).name}: got {got}, pinned {', '.join(sorted(allowed))}. "
                               "The file was deleted and nothing was installed.")
    return got


def plan_for(engine):
    p = engine.pin()
    k = p.get("kind", "manual")
    dest = engine.install_dir()
    base = {"engine": engine.name, "version": str(p.get("version", "")), "licence": p.get("licence", ""),
            "kind": k, "source": p.get("source", ""), "dest": str(dest), "steps": [], "auto": False, "note": ""}
    if k == "download":
        art = (p.get("artifacts") or {}).get(platform_key()) or (p.get("artifacts") or {}).get("any")
        if not art:
            base["note"] = (f"Manual install: no pinned download for {platform_key()}. Get version {p.get('version')} "
                            f"from {p.get('source')} and check its published SHA-256.")
            return base
        base.update(auto=True, url=art["url"], sha256=art["sha256"])
        size = f" ({int(art['size']):,} bytes, checked)" if art.get("size") else ""
        base["steps"] = [f"download {art['url']}{size}", f"check SHA-256 {art['sha256']} (refuse and delete on mismatch)",
                         f"{'copy' if art['archive'] == 'raw' else 'extract'} into {dest}"]
    elif k == "pip":
        base.update(auto=True, sha256=list(p.get("wheel_sha256") or []))
        base["steps"] = [f"create a private virtual environment in {dest / 'venv'}",
                         f"pip download {p['package']}=={p['version']} (wheel only, no dependencies)",
                         "check the wheel's SHA-256 against the pinned PyPI hashes",
                         "pip install that wheel (its dependencies come from your package index, version-resolved by pip)"]
    elif k == "go":
        base.update(auto=True, h1=p.get("h1"))
        base["steps"] = [f"go install {p['package']}@{p['version']} into {dest / 'bin'} (checked by the Go checksum database)",
                         f"check the module hash recorded in the binary equals {p.get('h1')}"]
        if not find_tool("go"):
            base.update(auto=False, note="Needs Go on PATH (https://go.dev/dl/). Install Go first, then run setup again.")
    elif k == "npm":
        pk = p.get("packages") or {}
        base.update(auto=True, integrity={n: v["integrity"] for n, v in pk.items()})
        specs = " ".join(n + "@" + str(v["version"]) for n, v in pk.items())
        base["steps"] = [f"npm install --ignore-scripts {specs} into {dest}",
                         "check each package's integrity in the lockfile against the pinned registry value"]
        if not find_tool("npm"):
            base.update(auto=False, note="Needs Node.js and npm (https://nodejs.org/). Install them first, then run setup again.")
    else:
        base["note"] = p.get("manual", "Manual install.")
    return base


# ---------------------------------------------------------------- download kind

class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_url(url):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or (u.hostname or "").lower() not in ALLOWED_HOSTS:
        raise InstallError(f"refused download location: {clean(url, 200)}")
    return url


def fetch_https(url, dest, log=print):
    """Download an allow-listed https URL to dest with live progress. The caller verifies the hash."""
    check_url(url)
    opener = urllib.request.build_opener(_HttpsOnly())
    req = urllib.request.Request(url, headers={"User-Agent": "nexaforge-securecode-setup"})
    with opener.open(req, timeout=60) as r, open(dest, "wb") as f:  # nosec B310 - https and host allow-listed above
        total = int(r.headers.get("Content-Length") or 0)
        if total > MAX_DOWNLOAD:
            raise InstallError("download larger than the allowed size")
        done, start, last = 0, time.time(), 0.0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            done += len(chunk)
            if done > MAX_DOWNLOAD:
                raise InstallError("download larger than the allowed size")
            f.write(chunk)
            now = time.time()
            if total > 1_000_000 and (now - last > 1 or done == total):
                last = now
                speed = done / max(now - start, 0.001)
                left = (total - done) / speed if speed else 0
                log(f"  {done / 1e6:6.1f} / {total / 1e6:.1f} MB  {100 * done / total:5.1f}%  {speed / 1e6:5.1f} MB/s  {left:4.0f}s left")


def _safe_member(name):
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or (p.parts and ":" in p.parts[0]):
        raise InstallError(f"refused archive entry with an unsafe path: {clean(name, 120)}")
    return p


def extract(archive, kind, member, dest):
    """Extract either one named file (found by its base name) or everything, refusing links and paths that
    would land outside dest."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    if kind == "raw":
        return
    if kind == "zip":
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            for i in infos:
                _safe_member(i.filename)
                if stat.S_ISLNK(i.external_attr >> 16):
                    raise InstallError(f"refused link inside the archive: {clean(i.filename, 120)}")
            chosen = infos if member == "*" else [i for i in infos if PurePosixPath(i.filename).name == member]
            if member != "*" and len(chosen) != 1:
                raise InstallError(f"expected exactly one {member} in the archive, found {len(chosen)}")
            for i in chosen:
                target = dest / (_safe_member(i.filename) if member == "*" else member)
                if i.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(i) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        return
    if kind == "tar.gz":
        with tarfile.open(archive, "r:gz") as t:
            members = t.getmembers()
            for m in members:
                _safe_member(m.name)
                if not (m.isfile() or m.isdir()):
                    raise InstallError(f"refused link or device inside the archive: {clean(m.name, 120)}")
            chosen = members if member == "*" else [m for m in members if m.isfile() and PurePosixPath(m.name).name == member]
            if member != "*" and len(chosen) != 1:
                raise InstallError(f"expected exactly one {member} in the archive, found {len(chosen)}")
            for m in chosen:
                if m.isdir():
                    continue
                target = dest / (_safe_member(m.name) if member == "*" else member)
                target.parent.mkdir(parents=True, exist_ok=True)
                src = t.extractfile(m)
                with src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        return
    raise InstallError(f"unknown archive type {kind}")


def install_download(engine, fetch=fetch_https, log=print):
    p = engine.pin()
    art = (p.get("artifacts") or {}).get(platform_key()) or (p.get("artifacts") or {}).get("any")
    if not art:
        raise InstallError(f"no pinned download for {platform_key()}; install {engine.name} manually")
    dest = engine.install_dir()
    tmp = Path(tempfile.mkdtemp(prefix="nfsc-dl-"))
    try:
        name = PurePosixPath(urllib.parse.urlparse(art["url"]).path).name or "download"
        f = tmp / name
        log(f"Downloading {art['url']}")
        fetch(art["url"], f)
        if art.get("size") and f.stat().st_size != int(art["size"]):
            got = f.stat().st_size
            f.unlink()
            raise ChecksumMismatch(f"size mismatch for {name}: got {got} bytes, pinned {art['size']}. "
                                   "The file was deleted and nothing was installed.")
        verify_sha256(f, art["sha256"])           # before anything is extracted or made executable
        log(f"  SHA-256 OK {art['sha256']}")
        staging = Path(tempfile.mkdtemp(prefix="nfsc-stage-"))
        try:
            if art["archive"] == "raw":
                shutil.copyfile(f, staging / art["exe"])
            else:
                extract(f, art["archive"], art.get("member", "*"), staging)
            exe = staging / art["exe"]
            if not exe.is_file():
                raise InstallError(f"{art['exe']} not found after extraction")
            if os.name != "nt":
                exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
            if dest.exists():
                shutil.rmtree(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staging), str(dest))
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return engine.installed_path()


# ---------------------------------------------------------------- pip kind

def install_pip(engine, runner=execute, log=print):
    p = engine.pin()
    dest = engine.install_dir()
    venv = dest / "venv"
    py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    tmp = Path(tempfile.mkdtemp(prefix="nfsc-whl-"))
    try:
        rc, out, err = runner([sys.executable, "-m", "venv", str(venv)], dest, 600)
        if rc != 0:
            raise InstallError(f"could not create a virtual environment: {clean(err, 300)}")
        log(f"pip download {p['package']}=={p['version']}")
        rc, out, err = runner([str(py), "-I", "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
                               "--disable-pip-version-check", "--no-input", "-d", str(tmp), f"{p['package']}=={p['version']}"], dest, 900)
        wheels = list(tmp.glob("*.whl"))
        if rc != 0 or len(wheels) != 1:
            raise InstallError(f"pip download failed: {clean((err or out)[-300:], 300)}")
        verify_sha256(wheels[0], p.get("wheel_sha256"))
        log(f"  SHA-256 OK {wheels[0].name}")
        rc, out, err = runner([str(py), "-I", "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
                               str(wheels[0])], dest, 1800)
        if rc != 0:
            raise InstallError(f"pip install failed: {clean((err or out)[-300:], 300)}")
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return engine.installed_path()


# ---------------------------------------------------------------- go kind

def go_env(gobin):
    env = dict(os.environ)
    # The checksum database must stay on, and no private/insecure exceptions may switch it off.
    for k in ("GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE", "GONOPROXY", "GOINSECURE", "GOFLAGS"):
        env.pop(k, None)
    env.update({"GOBIN": str(gobin), "GOSUMDB": "sum.golang.org", "GOWORK": "off", "CGO_ENABLED": "0"})
    if env.get("GOPROXY", "").strip().lower() in ("", "off", "direct"):
        env["GOPROXY"] = "https://proxy.golang.org,direct"
    return env


def check_go_build_info(text, module, version, h1):
    for line in str(text).splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "mod" and parts[1] == module and parts[2] == version:
            return parts[3] == h1
    return False


def install_go(engine, runner=execute, log=print):
    p = engine.pin()
    go = find_tool("go")
    if not go:
        raise InstallError("Go is not on PATH; install Go from https://go.dev/dl/ first")
    dest = engine.install_dir()
    gobin = dest / "bin"
    if dest.exists():
        shutil.rmtree(dest)
    gobin.mkdir(parents=True)
    try:
        log(f"go install {p['package']}@{p['version']}")
        rc, out, err = runner([go, "install", f"{p['package']}@{p['version']}"], dest, 1800, env=go_env(gobin))
        exe = engine.installed_path()
        if rc != 0 or not exe or not exe.is_file():
            raise InstallError(f"go install failed: {clean((err or out)[-300:], 300)}")
        rc, out, err = runner([go, "version", "-m", str(exe)], dest, 120)
        if not check_go_build_info(out, p["module"], p["version"], p["h1"]):
            raise ChecksumMismatch(f"module hash in {exe.name} does not match the pinned {p['h1']}; removed")
        log(f"  module hash OK {p['h1']}")
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return engine.installed_path()


# ---------------------------------------------------------------- npm kind

def check_npm_lock(lock_text, packages):
    data = json.loads(lock_text)
    pk = data.get("packages") or {}
    bad = []
    for name, want in packages.items():
        got = (pk.get(f"node_modules/{name}") or {})
        if got.get("version") != want["version"] or got.get("integrity") != want["integrity"]:
            bad.append(name)
    return bad


def install_npm(engine, runner=execute, log=print):
    p = engine.pin()
    npm = find_tool("npm")
    if not npm:
        raise InstallError("npm is not on PATH; install Node.js LTS from https://nodejs.org/ first")
    dest = engine.install_dir()
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        (dest / "package.json").write_text(json.dumps({"name": f"nexaforge-tools-{engine.name}", "private": True}), encoding="utf-8")
        specs = [f"{n}@{v['version']}" for n, v in (p.get("packages") or {}).items()]
        registry = os.environ.get("SECGATE_NPM_REGISTRY", NPM_REGISTRY)
        log(f"npm install --ignore-scripts {' '.join(specs)}")
        # cwd is the tools folder, so no project .npmrc is read; scripts never run.
        rc, out, err = runner([npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact",
                               "--registry", registry, *specs], dest, 1800)
        if rc != 0:
            raise InstallError(f"npm install failed: {clean((err or out)[-300:], 300)}")
        bad = check_npm_lock((dest / "package-lock.json").read_text(encoding="utf-8"), p.get("packages") or {})
        if bad:
            raise ChecksumMismatch(f"integrity mismatch for {', '.join(bad)}; removed")
        log("  integrity OK")
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return engine.installed_path()


def install(engine, log=print):
    root = tools_root()
    if inside(root, os.getcwd()):
        raise InstallError(f"the tools folder {root} is inside the current project; set NEXAFORGE_TOOLS_DIR elsewhere")
    k = engine.kind
    if k == "download":
        return install_download(engine, log=log)
    if k == "pip":
        return install_pip(engine, log=log)
    if k == "go":
        return install_go(engine, log=log)
    if k == "npm":
        return install_npm(engine, log=log)
    raise InstallError(engine.pin().get("manual", "manual install"))
