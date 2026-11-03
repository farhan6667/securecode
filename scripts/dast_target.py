#!/usr/bin/env python3
"""Target checks shared by the DAST wrappers (local_dast.py, run-nuclei-authorized.py, run-zap-authorized.py).

A DAST scan sends traffic, so the target check is the security boundary. Hosts are parsed the way browsers
parse them (decimal, octal and hex IPv4 forms, IPv4-mapped and other IPv6 forms that carry an IPv4 address),
a DNS name is resolved once and every answer is checked, and:
- cloud metadata hosts and addresses and link-local, multicast and unspecified addresses are always refused;
- private and loopback addresses are refused for staging scans unless a person names the exact host in
  SECURITY_DAST_PRIVATE_HOSTS (comma separated). Local scans of this machine go through local_dast.py instead.
"""
from __future__ import annotations

import ipaddress, os, re, socket
from urllib.parse import urlsplit, urlunsplit


class Refused(Exception):
    pass


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
    if len(parts) > 4 or len(host) > 64:
        raise Refused(f"'{host[:80]}' has a numeric last label but more than four parts")
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


def literal_ip(host: str):
    """The IP a browser would use for this host string, or None for a DNS name. Raises Refused for numeric
    forms that cannot be parsed safely."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if ":" in h:
        raise Refused(f"'{host[:80]}' is not a valid IPv6 address")
    return parse_ipv4_loose(h)


# --- what a staging scan may reach -------------------------------------------------------------------------

# Cloud instance metadata: AWS, GCP, Azure, Oracle, DigitalOcean (169.254.169.254), AWS ECS task metadata
# (169.254.170.2), AWS IPv6 IMDS (fd00:ec2::254), Alibaba Cloud (100.100.100.200).
METADATA_IPS = {ipaddress.ip_address(x) for x in ("169.254.169.254", "169.254.170.2", "fd00:ec2::254", "100.100.100.200")}
# metadata.google.internal, metadata.goog, metadata.azure.com, instance-data.ec2.internal and friends.
METADATA_NAMES = re.compile(r"^(?:metadata|instance-data)(?:[.-]|$)|(?:^|\.)metadata\.(?:goog|google\.internal|azure(?:\.com)?)$")
LINK_LOCAL_TEXT = re.compile(r"(^|[.-])169[.-]254[.-]\d{1,3}[.-]\d{1,3}([.-]|$)")      # 169.254.169.254.nip.io
PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "::1/128", "fc00::/7", "fec0::/10")]
THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")      # "this host" addresses: never a real scan target
NAT64 = ipaddress.ip_network("64:ff9b::/96")


def embedded_ipv4(ip) -> list:
    """IPv4 addresses carried inside an IPv6 address (mapped, compatible, NAT64, 6to4, Teredo)."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    out = []
    if ip.ipv4_mapped is not None:
        out.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        out.append(ip.sixtofour)
    if ip.teredo is not None:
        out.append(ip.teredo[1])
    if ip in NAT64 or (int(ip) >> 32 == 0 and int(ip) > 1):          # 64:ff9b::a.b.c.d and ::a.b.c.d
        out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def ip_problem(ip, private_ok: bool) -> str | None:
    """Why this address may not be scanned, or None."""
    for x in [ip, *embedded_ipv4(ip)]:
        if x in METADATA_IPS:
            return f"{x} is a cloud metadata address"
        if x.is_link_local or x.is_multicast or x.is_unspecified or (isinstance(x, ipaddress.IPv4Address) and
                                                                       (x.is_reserved or x in THIS_NETWORK)):
            return f"{x} is a link-local, multicast, reserved or unspecified address"
        if not private_ok and (any(x in n for n in PRIVATE_NETS if n.version == x.version) or is_loopback(x)):
            return (f"{x} is a private or loopback address; name the host in SECURITY_DAST_PRIVATE_HOSTS if a person "
                    "approved scanning it (local scans of this machine use local_dast.py)")
    return None


def check_staging(url: str, resolver=default_resolver, env=None) -> tuple[dict, list]:
    """Full staging-target check. Returns (parsed target, list of checked IPs); raises Refused.
    The name is resolved once here and every answer must pass."""
    env = os.environ if env is None else env
    t = parse_target(url)
    host = t["host"].rstrip(".")
    if not host:
        raise Refused("the URL has no host")
    if METADATA_NAMES.search(host) or LINK_LOCAL_TEXT.search(host):
        raise Refused("that host is a cloud metadata or link-local name; refused")
    if re.search(r"(^|[.-])(prod|production|live)([.-]|$)", host) and env.get("SECURITY_DAST_PROD_OK") != "yes":
        raise Refused("the host looks like production; set SECURITY_DAST_PROD_OK=yes only with written approval")
    allowed = {h.strip().lower().rstrip(".").strip("[]") for h in str(env.get("SECURITY_DAST_PRIVATE_HOSTS", "")).split(",") if h.strip()}
    private_ok = host.strip("[]") in allowed
    ip = literal_ip(host)
    if ip is not None:
        ips = [ip]
    else:
        if not re.fullmatch(r"[a-z0-9_]([a-z0-9_\-]{0,62})(\.[a-z0-9_]([a-z0-9_\-]{0,62}))*", host) or len(host) > 253:
            raise Refused(f"'{host[:80]}' is not a valid host name")
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
    for x in ips:
        why = ip_problem(x, private_ok)
        if why:
            raise Refused(f"{host}: {why}; refused")
    return t, ips
