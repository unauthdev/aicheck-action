"""Target validation + SSRF guard.

Only public, globally-reachable unicast IPv4 targets may be scanned. The
guard is an ALLOWLIST on `is_global` (not a blocklist of known-bad flags):
anything not allocated for public routing — private, loopback, link-local,
CGNAT (100.64.0.0/10), documentation ranges, benchmarking, reserved — is
rejected, both as literal IPs and as the result of DNS resolution.
"""

from __future__ import annotations

import ipaddress
import re
import socket


class TargetRejected(ValueError):
    pass


_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")

# Explicitly blocked on top of the is_global allowlist, belt and braces:
# is_global depends on the Python version's IANA registry snapshot.
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "100.64.0.0/10",  # CGNAT shared address space (RFC 6598) — Tailscale etc.
        "192.0.0.0/24",   # IETF protocol assignments
        "198.18.0.0/15",  # benchmarking (RFC 2544)
    )
)


def normalize_target(raw: str) -> str:
    """Turn user input into a bare hostname or IPv4 literal."""
    t = (raw or "").strip().lower()
    if not t:
        raise TargetRejected("empty target")
    if t.startswith("curl "):  # pasted the whole example command — extract the target
        m = re.search(r"(?:-d\s*|--data(?:-raw)?\s*)target=([^\s&]+)", t)
        if m:
            t = m.group(1)
    t = re.sub(r"^https?://", "", t)
    t = t.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    t = t.split("@")[-1]  # strip any userinfo
    if t.startswith("["):  # IPv6 literals unsupported in Gate 1
        raise TargetRejected("IPv6 targets are not supported yet")
    if ":" in t:  # strip user-supplied port; we probe our own candidate ports
        t = t.split(":", 1)[0]
    t = t.rstrip(".")
    if not t or ".." in t or not _HOST_RE.match(t):
        raise TargetRejected(f"invalid target: {raw!r}")
    return t


def ensure_public(host: str) -> list[str]:
    """Resolve host and reject it if ANY resolved address is non-public.

    Returns the sorted list of resolved IPs.
    """
    try:
        literal = ipaddress.ip_address(host)
        ips = [str(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise TargetRejected(f"could not resolve {host!r}")
        ips = sorted({info[4][0] for info in infos})
        if not ips:
            raise TargetRejected(f"could not resolve {host!r}")
    for s in ips:
        ip = ipaddress.ip_address(s)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or not ip.is_global
            or any(ip in net for net in _BLOCKED_NETWORKS)
        ):
            raise TargetRejected(
                f"{host!r} resolves to a non-public address ({s}) — "
                "only public targets you own may be scanned"
            )
    return ips


def validate_target(raw: str) -> tuple[str, list[str]]:
    host = normalize_target(raw)
    return host, ensure_public(host)
