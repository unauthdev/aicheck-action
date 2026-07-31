"""CLI entrypoint: python -m aicheck.scan <target> [options]

CI-shaped wrapper over the live-probe pipeline (recon → checkers → grade).
Answers one question in a build job: "did we just ship an AI service with no
auth?" Runs entirely against the given target — no database, no emails, no
phone-home of any kind.

  python -m aicheck.scan localhost --allow-private
  python -m aicheck.scan example.com --format sarif --fail-grade C > results.sarif

Exit codes: 0 = pass, 1 = grade at or worse than --fail-grade, 2 = target,
usage, or engine error (an engine crash is never reported as a grade).
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import sys

import httpx

from . import __version__, recon, sarif, ssrf
from .scoring import grade, run_checkers

_BADNESS = {"A": 0, "C": 1, "D": 2, "F": 3}


def resolve_internal(raw: str) -> tuple[str, list[str]]:
    """--allow-private path: normalize + resolve WITHOUT the public-address
    guard. CI targets are deliberately internal (localhost, docker service
    names). We still pin the resolved IPs, so even here nothing is re-resolved
    at connect time."""
    host = ssrf.normalize_target(raw)
    try:
        literal = ipaddress.ip_address(host)
        return host, [str(literal)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ssrf.TargetRejected(f"could not resolve {host!r}")
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise ssrf.TargetRejected(f"could not resolve {host!r}")
    return host, ips


async def scan(target: str, allow_private: bool = False,
               services: list[str] | None = None,
               transport: httpx.AsyncBaseTransport | None = None) -> tuple[str, list[dict]]:
    """Returns (grade, findings). Raises ssrf.TargetRejected on bad targets."""
    if allow_private:
        host, ips = resolve_internal(target)
    else:
        host, ips = ssrf.validate_target(target)
    facts = await recon.gather_facts(host, transport=transport, pinned_ips=ips)
    findings = run_checkers(facts, host)
    if services:
        wanted = [s.lower() for s in services]
        findings = [f for f in findings
                    if any(w in f.product.lower() for w in wanted)]
    return grade(findings), [f.to_dict() for f in findings]


def render_text(target: str, g: str, findings: list[dict]) -> str:
    lines = [f"aicheck — {target} → grade {g} ({len(findings)} findings)"]
    for f in findings:
        lines.append(f"  {f['severity']:8} {f['product']}: {f['title']}")
        lines.append(f"           fix: https://unauth.dev/fixes/{f['fix_card_id']}")
    if not findings:
        lines.append("  clean — no exposed AI services found")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m aicheck.scan",
        description="Live-probe a target for exposed self-hosted AI services.")
    ap.add_argument("target", help="host to probe (no port — we probe the well-known ones)")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--fail-grade", choices=["A", "C", "D", "F"], default="F",
                    help="exit 1 if the grade is this or worse (default: F)")
    ap.add_argument("--services", default="",
                    help="comma-separated product filter, e.g. ollama,n8n")
    ap.add_argument("--allow-private", action="store_true",
                    help="allow internal targets (localhost, docker service names) — "
                         "for CI jobs probing their own services")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    services = [s.strip() for s in args.services.split(",") if s.strip()] or None
    try:
        g, findings = asyncio.run(
            scan(args.target, allow_private=args.allow_private, services=services))
    except ssrf.TargetRejected as exc:
        print(f"target rejected: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # engine error — never report as a grade
        print(f"aicheck engine error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps({"target": args.target, "grade": g, "findings": findings}, indent=2))
    elif args.format == "sarif":
        print(json.dumps(sarif.to_sarif(args.target, g, findings), indent=2))
    else:
        print(render_text(args.target, g, findings), end="")
    return 1 if _BADNESS[g] >= _BADNESS[args.fail_grade] else 0


if __name__ == "__main__":
    sys.exit(main())
