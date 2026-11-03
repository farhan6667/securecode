#!/usr/bin/env python3
"""Local DAST: run an OWASP ZAP baseline (passive) or API scan against the developer's own app on this machine.

Hard rules:
- The target must be http(s) on a loopback address (127.0.0.0/8, ::1, or a name that resolves only to those).
  The name is resolved once, every answer must be loopback, and ZAP is given the pinned IP literal, so a DNS
  answer that changes later (rebinding) cannot move the scan to another host.
- Anything else is refused, unless a person set SECURITY_DAST_ALLOW=true and SECURITY_DAST_URL to exactly this
  URL, and the URL passes the staging checks of run-nuclei-authorized.py (the existing authorized flow).
- The app is never started from repository files. Only an explicit --start "<command>" typed by the person
  running this script is used, split into an argument list (no shell), with a timeout and a teardown that
  stops the whole process tree.
- Missing ZAP or Docker is a NOTE with an install hint, not a failure.

Results go to .security/dast-findings.json in the gate's findings schema; report.py picks them up.
"""
from __future__ import annotations

import argparse, importlib.util, ipaddress, json, os, re, shlex, shutil, signal, socket, subprocess, sys, time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # run with python -I
from secgate import find_tool  # noqa: E402
from report import clean  # noqa: E402

# zaproxy/zap-stable 2.17.0, multi-arch index digest (Docker Hub, pushed 2026-10-26).
ZAP_IMAGE = "zaproxy/zap-stable:2.17.0@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238"
INSTALL_HINT = ("Install Docker Desktop (https://docs.docker.com/get-docker/) or OWASP ZAP "
                "(https://www.zaproxy.org/download/), then run this again. Nothing was scanned.")
RISK = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
MAX_REPORT_BYTES = 50_000_000


class Refused(Exception):
    pass


def _load_check_url():
    spec = importlib.util.spec_from_file_location("run_nuclei_authorized", HERE / "run-nuclei-authorized.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.check_url


# --- host parsing ------------------------------------------------------------------------------------------

def _ipv4_part(p: str) -> int | None:
    """One part of an IPv4 address the way browsers and inet_aton read it: 0x hex, leading 0 octal, else decimal."""
    if not p:
        return None
    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]*", p):
            return int(p[2:] or "0", 16)
        if re.fullmatch(r"0[0-7]+", p):
            return int(p, 8)
        if re.fullmatch(r"[0-9]+", p):
            if len(p) > 1 and p.startswith("0"):
                return None            # 08, 09: not valid octal, refuse instead of guessing
            return int(p, 10)
    except ValueError:
        return None
    return None


def parse_ipv4_loose(host: str) -> ipaddress.IPv4Address | None:
    """WHATWG URL IPv4 parser: 1 to 4 dot-separated parts, the last part fills the remaining bytes.
    127.1, 2130706433, 0177.0.0.1 and 0x7f.1 are all 127.0.0.1. Returns None if the host is not numeric."""
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    if not parts or not re.fullmatch(r"(0[xX][0-9a-fA-F]*|[0-9]+)", parts[-1]):
        return None                     # last label is not a number: a DNS name
    if len(parts) > 4:
        raise Refused(f"'{host}' has a numeric last label but more than four parts")
    nums = [_ipv4_part(p) for p in parts]
    if any(n is None for n in nums):
        raise Refused(f"'{host}' looks like a numeric address but cannot be parsed safely")
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(nums)):
        raise Refused(f"'{host}' is out of range for an IPv4 address")
    value = last
    for i, n in enumerate(head):
        value += n << (8 * (3 - i))
    return ipaddress.IPv4Address(value)


def is_loopback(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped.is_loopback
        return ip == ipaddress.IPv6Address("::1")
    return ip.is_loopback


def default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [i[4][0] for i in infos]


def parse_target(url: str) -> dict:
    """Strict URL parsing. Returns scheme, host (as typed), port, path+query. Raises Refused."""
    if not isinstance(url, str) or not url or len(url) > 2000:
        raise Refused("a target URL is required")
    if re.search(r"[\x00-\x20\x7f\\]", url):
        raise Refused("the URL contains spaces, control characters or backslashes")
    try:
        u = urlsplit(url)
    except ValueError as e:
        raise Refused(f"the URL cannot be parsed ({e})")
    if u.scheme.lower() not in ("http", "https"):
        raise Refused("only http:// and https:// targets are allowed")
    if "@" in u.netloc:
        raise Refused("user names or passwords in the URL are refused (http://127.0.0.1@other.host tricks)")
    try:
        port = u.port
    except ValueError:
        raise Refused("the port is not a number between 0 and 65535")
    host = u.hostname or ""
    if not host:
        raise Refused("the URL has no host")
    if "%" in host:
        raise Refused("IPv6 zone ids are refused")
    if port == 0:
        raise Refused("port 0 is not a valid target")
    return {"scheme": u.scheme.lower(), "host": host.lower(), "port": port or (443 if u.scheme.lower() == "https" else 80),
            "bracketed": u.netloc.startswith("["), "rest": urlunsplit(("", "", u.path or "/", u.query, ""))}


def resolve_loopback(host: str, resolver=default_resolver) -> ipaddress._BaseAddress:
    """Resolve once. Every answer must be loopback; the first one is pinned. Raises Refused."""
    try:
        ip = ipaddress.ip_address(host)
        literal = True
    except ValueError:
        ip = parse_ipv4_loose(host)
        literal = ip is not None
    if literal:
        if ip.is_unspecified:
            raise Refused(f"{host} is the unspecified address; use 127.0.0.1 or ::1")
        if not is_loopback(ip):
            raise Refused(f"{host} ({ip}) is not a loopback address")
        return ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
    if not re.fullmatch(r"[a-z0-9]([a-z0-9\-]{0,62})(\.[a-z0-9]([a-z0-9\-]{0,62}))*\.?", host):
        raise Refused(f"'{host}' is not a valid host name")
    try:
        answers = resolver(host)
    except (OSError, UnicodeError) as e:
        raise Refused(f"{host} could not be resolved ({type(e).__name__})")
    ips = []
    for a in answers or []:
        try:
            ips.append(ipaddress.ip_address(str(a).split("%")[0]))
        except ValueError:
            raise Refused(f"{host} resolved to something that is not an IP address")
    if not ips:
        raise Refused(f"{host} did not resolve")
    bad = [str(x) for x in ips if not is_loopback(x)]
    if bad:
        raise Refused(f"{host} resolves to a non-loopback address ({', '.join(bad[:3])}); only this machine may be scanned")
    first = ips[0]
    return first.ipv4_mapped if isinstance(first, ipaddress.IPv6Address) and first.ipv4_mapped else first


def pinned_url(t: dict, ip) -> str:
    host = f"[{ip}]" if isinstance(ip, ipaddress.IPv6Address) else str(ip)
    return f"{t['scheme']}://{host}:{t['port']}{t['rest']}"


def authorize(url: str, resolver=default_resolver, env=None) -> dict:
    """Decide whether this URL may be scanned. Returns {'url', 'ip', 'mode'}; raises Refused."""
    env = os.environ if env is None else env
    t = parse_target(url)
    try:
        ip = resolve_loopback(t["host"], resolver)
        return {"url": pinned_url(t, ip), "ip": ip, "port": t["port"], "mode": "loopback", "scheme": t["scheme"]}
    except Refused as local_err:
        if env.get("SECURITY_DAST_ALLOW", "").lower() == "true" and env.get("SECURITY_DAST_URL", "") == url:
            err = _load_check_url()(url)
            if err:
                raise Refused(err)
            return {"url": url, "ip": None, "port": t["port"], "mode": "authorized-staging", "scheme": t["scheme"]}
        raise Refused(f"{local_err}. Local DAST scans only this machine. For an authorized staging host, a person must "
                      "set SECURITY_DAST_ALLOW=true and SECURITY_DAST_URL to exactly this URL.")


# --- starting the developer's app -------------------------------------------------------------------------

SHELL_TOKENS = {"&&", "||", "|", ";", "&", ">", ">>", "<", "2>", "2>&1", "`"}


def split_start(cmd: str) -> list[str]:
    if not cmd or len(cmd) > 2000 or re.search(r"[\x00-\x1f\x7f]", cmd):
        raise Refused("--start must be one line")
    try:
        argv = shlex.split(cmd, posix=True)
    except ValueError as e:
        raise Refused(f"--start could not be split into arguments ({e})")
    if not argv:
        raise Refused("--start is empty")
    if any(a in SHELL_TOKENS for a in argv) or any(re.search(r"[;&|<>`]|\$\(", a) for a in argv):
        raise Refused("--start runs one program without a shell; operators like &&, |, ; and > are not supported")
    if argv[0].startswith("-"):
        raise Refused("--start must begin with a program name")
    if os.name == "nt" and any(re.search(r"[&|<>^%!\"]", x) for x in argv[1:]):
        # Windows hands .bat/.cmd arguments to cmd.exe parsing; keep them free of its metacharacters.
        raise Refused("--start arguments may not contain & | < > ^ % ! or quotes on Windows")
    exe = argv[0]
    if os.sep in exe or "/" in exe:
        p = Path(exe).resolve()
        if not p.is_file():
            raise Refused(f"--start program not found: {exe}")
        argv[0] = str(p)
    else:
        found = find_tool(exe)      # PATH only, never the project folder (a planted npm.bat is not run)
        if not found:
            raise Refused(f"--start program '{exe}' is not on PATH")
        argv[0] = found
    return argv


def port_open(ip, port: int, timeout: float = 0.5) -> bool:
    fam = socket.AF_INET6 if isinstance(ip, ipaddress.IPv6Address) else socket.AF_INET
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((str(ip), port)) == 0
    except OSError:
        return False


def start_app(argv: list[str], log: Path, popen=subprocess.Popen):
    kw = {"stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
    else:
        kw["start_new_session"] = True
    with log.open("ab") as fh:          # the child keeps its own copy of the handle
        return popen(argv, stdout=fh, **kw)


def stop_app(proc, run=subprocess.run):
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            tk = find_tool("taskkill") or "taskkill"
            run([tk, "/T", "/F", "/PID", str(proc.pid)], capture_output=True, timeout=30, check=False)
        else:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except Exception:
        pass


# --- ZAP plan and command ----------------------------------------------------------------------------------

def zap_plan(target: str, report_dir: str, api: str | None, api_format: str, active: bool, minutes: int) -> dict:
    """ZAP Automation Framework plan. Written as JSON (valid YAML), so no value can break the structure."""
    jobs = []
    if api:
        key = "apiUrl" if api.startswith(("http://", "https://")) else "apiFile"
        jtype = {"openapi": "openapi", "graphql": "graphql", "soap": "soap"}[api_format]
        params = {key: api, "targetUrl": target} if jtype == "openapi" else ({"endpoint": target, "schemaFile" if key == "apiFile" else "schemaUrl": api}
                                                                            if jtype == "graphql" else {"wsdlFile" if key == "apiFile" else "wsdlUrl": api})
        jobs.append({"type": jtype, "parameters": params})
    jobs.append({"type": "spider", "parameters": {"context": "local", "maxDuration": max(1, minutes // 2)}})
    jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": max(1, minutes)}})
    if active:
        jobs.append({"type": "activeScan", "parameters": {"context": "local", "maxScanDurationInMins": max(1, minutes)}})
    jobs.append({"type": "report", "parameters": {"template": "traditional-json", "reportDir": report_dir,
                                                   "reportFile": "zap-report.json"}})
    return {"env": {"contexts": [{"name": "local", "urls": [target], "includePaths": [re.escape(target.rstrip("/")) + ".*"]}],
                    "parameters": {"failOnError": True, "progressToStdout": True}},
            "jobs": jobs}


def to_docker_host(url: str) -> str:
    return re.sub(r"^(https?://)(\[[^\]]+\]|[^/:]+)", r"\1host.docker.internal", url)


def docker_cmd(docker: str, workdir: Path, target_ip, scan_url: str) -> tuple[list[str], str]:
    """Docker cannot see the host's loopback from inside a container except with host networking (Linux) or
    Docker Desktop's fixed host.docker.internal name (Windows, macOS). Staging targets use the default network."""
    url = scan_url
    net: list[str] = []
    if target_ip is not None:
        if sys.platform == "linux":
            net = ["--network=host"]
        else:
            net = ["--add-host=host.docker.internal:host-gateway"]
            url = to_docker_host(scan_url)
    return [docker, "run", "--rm", "--pull=missing", "--name", f"nfsc-zap-{os.getpid()}", *net, "-v", f"{workdir}:/zap/wrk/:rw", ZAP_IMAGE,
            "zap.sh", "-cmd", "-autorun", "/zap/wrk/plan.yaml"], url


def find_zap() -> tuple[str, str] | None:
    docker = find_tool("docker")
    if docker:
        return "docker", docker
    for name in ("zap.sh", "zap.bat", "zap"):
        p = find_tool(name)
        if p:
            return "local", p
    for c in (Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "ZAP/Zed Attack Proxy/zap.bat",
              Path("/Applications/ZAP.app/Contents/Java/zap.sh"), Path("/opt/zaproxy/zap.sh"), Path("/usr/share/zaproxy/zap.sh")):
        if c.is_file():
            return "local", str(c)
    return None


# --- parsing ZAP JSON --------------------------------------------------------------------------------------

def _strip_html(s) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]{0,500}>", " ", str(s or ""))).strip()


def parse_zap(data) -> list[dict]:
    """ZAP traditional JSON report -> gate findings. Tolerates missing or wrong-typed fields."""
    out = []
    sites = data.get("site") if isinstance(data, dict) else None
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites if isinstance(sites, list) else []:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts")
        for a in alerts if isinstance(alerts, list) else []:
            if not isinstance(a, dict):
                continue
            if str(a.get("confidence", "")) == "0":          # ZAP's own "false positive" confidence
                continue
            sev = RISK.get(str(a.get("riskcode", "")).strip(), "INFO")
            inst = a.get("instances")
            inst = [i for i in inst if isinstance(i, dict)] if isinstance(inst, list) else []
            first = inst[0] if inst else {}
            name = _strip_html(a.get("name") or a.get("alert") or "ZAP alert")[:200]
            desc = _strip_html(a.get("desc"))[:800]
            plugin = re.sub(r"[^0-9A-Za-z\-]", "", str(a.get("pluginid") or a.get("alertRef") or "0"))[:20] or "0"
            cwe = re.sub(r"\D", "", str(a.get("cweid") or ""))[:6]
            out.append({"rule": f"ZAP-{plugin}", "severity": sev, "file": "", "line": 0,
                        "url": clean(first.get("uri") or site.get("@name") or "", 400),
                        "message": f"{name}. {desc}" if desc else name,
                        "code": clean(" ".join(x for x in (str(first.get("method") or ""), str(first.get("param") or ""),
                                                           str(first.get("evidence") or "")) if x), 300),
                        "solution": _strip_html(a.get("solution"))[:600], "cwe": cwe,
                        "count": len(inst), "engine": "zap"})
    return out


def read_zap_report(path: Path) -> list[dict]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
            return []
        return parse_zap(json.loads(path.read_text(encoding="utf-8", errors="replace")))
    except (OSError, ValueError, RecursionError):
        return []


# --- main --------------------------------------------------------------------------------------------------

def write_result(out: Path, result: dict) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")


def main(argv=None, resolver=default_resolver, runner=subprocess.run, popen=subprocess.Popen) -> int:
    ap = argparse.ArgumentParser(description="OWASP ZAP baseline or API scan of your own app on localhost only.")
    ap.add_argument("--target", required=True, help="for example http://127.0.0.1:8000")
    ap.add_argument("--api", help="OpenAPI/GraphQL/SOAP definition: a file in the project or a URL on the same loopback host")
    ap.add_argument("--api-format", choices=["openapi", "graphql", "soap"], default="openapi")
    ap.add_argument("--active", action="store_true", help="also run ZAP's active scan (it sends attack payloads to your local app)")
    ap.add_argument("--minutes", type=int, default=5, help="time budget per ZAP job (1 to 60)")
    ap.add_argument("--start", help='command that starts YOUR app, typed by you, e.g. --start "php artisan serve --port 8000". '
                                    "One program, no shell; use forward slashes in paths")
    ap.add_argument("--start-timeout", type=int, default=60, help="seconds to wait for the app to listen (5 to 600)")
    ap.add_argument("--out", default=".security/dast-findings.json")
    ap.add_argument("--dry-run", action="store_true", help="check the target and print the ZAP command without running it")
    a = ap.parse_args(argv)
    root = Path.cwd().resolve()
    out = (root / a.out).resolve()
    try:
        out.relative_to(root)
    except ValueError:
        print("refused: --out must be inside the project folder"); return 4
    minutes = min(60, max(1, a.minutes)); start_timeout = min(600, max(5, a.start_timeout))
    base = {"tool": "", "scan": "api" if a.api else ("active" if a.active else "baseline"), "target": clean(a.target, 400),
            "findings": []}
    try:
        auth = authorize(a.target, resolver)
        api = None
        if a.api:
            if a.api.startswith(("http://", "https://")):
                api_auth = authorize(a.api, resolver)
                if api_auth["mode"] != auth["mode"]:
                    raise Refused("the API definition URL must be on the same kind of target as the app")
                api = api_auth["url"]
            else:
                ap_path = (root / a.api).resolve()
                ap_path.relative_to(root)
                if not ap_path.is_file() or ap_path.stat().st_size > 20_000_000:
                    raise Refused("--api file not found or larger than 20 MB")
                api = ap_path
        start_argv = split_start(a.start) if a.start else None
        if start_argv and auth["mode"] != "loopback":
            raise Refused("--start is only for an app on this machine")
    except (Refused, ValueError) as e:
        msg = str(e) if isinstance(e, Refused) else "the --api file must be inside the project folder"
        print(f"REFUSED: {clean(msg, 400)}")
        write_result(out, {**base, "status": "refused", "note": clean(msg, 400)})
        return 4
    print(f"Target accepted ({auth['mode']}): {auth['url']}")
    zap = find_zap()
    if not zap:
        print(f"NOTE: OWASP ZAP is not available (no docker, zap.sh or zap.bat on PATH). {INSTALL_HINT}")
        write_result(out, {**base, "status": "not_run", "note": "OWASP ZAP and Docker are not installed. " + INSTALL_HINT})
        return 0
    kind, exe = zap
    work = out.parent / "dast"
    work.mkdir(parents=True, exist_ok=True)
    report_json = work / "zap-report.json"
    if report_json.exists():
        report_json.unlink()
    if kind == "docker":
        cmd, scan_url = docker_cmd(exe, work, auth["ip"], auth["url"])
        report_dir = "/zap/wrk"
        if isinstance(api, Path):
            shutil.copyfile(api, work / ("api" + api.suffix.lower()[:8]))
            api_ref = "/zap/wrk/api" + api.suffix.lower()[:8]
        else:
            api_ref = to_docker_host(api) if api and scan_url != auth["url"] else api
        tool = f"docker {ZAP_IMAGE}"
    else:
        scan_url = auth["url"]; report_dir = str(work)
        api_ref = str(api) if isinstance(api, Path) else api
        cmd = [exe, "-cmd", "-autorun", str(work / "plan.yaml")]
        tool = f"local ZAP ({Path(exe).name})"
    plan = zap_plan(scan_url, report_dir, api_ref, a.api_format, a.active, minutes)
    (work / "plan.yaml").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    base["tool"] = tool
    if a.dry_run:
        print("Dry run. ZAP command:", cmd)
        if start_argv:
            print("Would start the app with:", start_argv)
        write_result(out, {**base, "status": "not_run", "note": "dry run"})
        return 0
    proc = None
    try:
        if start_argv:
            if auth["ip"] is not None and port_open(auth["ip"], auth["port"]):
                print("REFUSED: something already listens on that port; stop it or leave out --start")
                write_result(out, {**base, "status": "refused", "note": "port already in use before --start"})
                return 4
            print("Starting your app:", start_argv)
            proc = start_app(start_argv, work / "app.log", popen)
            deadline = time.monotonic() + start_timeout
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise Refused(f"the app exited with code {proc.returncode} before it listened; see {work / 'app.log'}")
                if auth["ip"] is None or port_open(auth["ip"], auth["port"]):
                    break
                time.sleep(0.5)
            else:
                raise Refused(f"the app did not listen on port {auth['port']} within {start_timeout} s")
        elif auth["ip"] is not None and not port_open(auth["ip"], auth["port"]):
            raise Refused(f"nothing listens on {auth['url']}; start your app first or pass --start")
        print("Running OWASP ZAP:", cmd)
        try:
            rc = runner(cmd, cwd=str(work), timeout=minutes * 60 * 4 + 300, check=False).returncode
        except subprocess.TimeoutExpired:
            rc = 124
            if kind == "docker":     # killing the docker client does not stop the container
                runner([exe, "rm", "-f", cmd[cmd.index("--name") + 1]], capture_output=True, timeout=60, check=False)
        findings = read_zap_report(report_json)
        status = "ran" if report_json.is_file() else "failed"
        note = "" if status == "ran" else f"ZAP exited {rc} without a report; see the output above"
        write_result(out, {**base, "status": status, "note": note, "exit": rc, "findings": findings})
        print(f"ZAP {status}: {len(findings)} alert(s) written to {out}")
        return 0 if status == "ran" else 5
    except Refused as e:
        print(f"REFUSED: {clean(str(e), 400)}")
        write_result(out, {**base, "status": "refused", "note": clean(str(e), 400)})
        return 4
    finally:
        stop_app(proc, runner)


if __name__ == "__main__":
    raise SystemExit(main())
