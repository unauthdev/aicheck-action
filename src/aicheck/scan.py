"""CLI entrypoint: python -m aicheck.scan <target> [options]

CI-shaped wrapper over the live-probe pipeline (recon → checkers → grade).
Answers one question in a build job: "did we just ship an AI service with no
auth?" Runs entirely against the given target — no database, no emails, no
phone-home of any kind.

  python -m aicheck.scan localhost --allow-private
  python -m aicheck.scan example.com --format sarif --fail-grade C > results.sarif

Trust-surface flags:
  --dry-run   print every request the scan would send (sorted, one per line)
              and exit 0 — no sockets, no DNS, works for any target string.
  --verbose   log every outbound connection to stderr as it happens, with the
              pinned IP actually dialed, plus a closing summary line.

Text output ends with one door line: fix cards + a playground deep link on
findings, the CI-action link when clean (grade/slugs only, never the target).
After a successful scan it checks PyPI weekly for a newer version — disable
with --no-version-check or AICHECK_NO_VERSION_CHECK=1.

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

from . import __version__, recon, sarif, ssrf, versioncheck
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
    # Prefer IPv4 — unbracketed IPv6 URLs break httpx; dual-stack docker
    # names often return AAAA first under sorted(str).
    v4 = [s for s in ips
          if isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)]
    return host, (sorted(v4) if v4 else ips)


def _services_wanted(finding, wanted: set[str]) -> bool:
    """Exact match on check_id or product (case-insensitive), not substring."""
    return (
        finding.check_id.lower() in wanted
        or finding.product.lower() in wanted
    )


async def scan(target: str, allow_private: bool = False,
               services: list[str] | None = None,
               transport: httpx.AsyncBaseTransport | None = None,
               log: recon.ConnectLog | None = None) -> tuple[str, list[dict]]:
    """Returns (grade, findings). Raises ssrf.TargetRejected on bad targets.
    `log`, when given, receives (method, logical_url, dialed_address) before
    every outbound request — the --verbose connection log."""
    if allow_private:
        host, ips = resolve_internal(target)
    else:
        host, ips = ssrf.validate_target(target)
    facts = await recon.gather_facts(host, transport=transport, pinned_ips=ips, log=log)
    findings = run_checkers(facts, host)
    if services:
        wanted = {s.lower() for s in services}
        findings = [f for f in findings if _services_wanted(f, wanted)]
    return grade(findings), [f.to_dict() for f in findings]


CLEAN_DOOR = ("clean. keep it that way: the CI action watches every PR → "
              "https://github.com/unauthdev/aicheck-scan")


def _door_line(g: str, findings: list[dict]) -> str:
    """The one line every text output ends with. Findings → first fix card +
    the playground deep link; clean → the CI action. Grade, count and product
    slugs only — never the target."""
    if not findings:
        return CLEAN_DOOR
    # late import: aicheck.render imports render_text from this module
    from .render import deep_link
    return (f"fix cards: https://unauth.dev/fixes/{findings[0]['fix_card_id']} — "
            f"see your stack the way the internet sees it: "
            f"{deep_link(g, findings, source='cli')}")


def render_text(target: str, g: str, findings: list[dict],
                services_filter: list[str] | None = None) -> str:
    lines = [f"aicheck — {target} → grade {g} ({len(findings)} findings)"]
    for f in findings:
        lines.append(f"  {f['severity']:8} {f['product']}: {f['title']}")
        lines.append(f"           fix: https://unauth.dev/fixes/{f['fix_card_id']}")
    if not findings:
        if services_filter:
            lines.append(
                f"  no findings in filtered services ({', '.join(services_filter)}) "
                "— other products were not graded"
            )
        else:
            lines.append("  clean — no exposed AI services found")
    lines.append(_door_line(g, findings))
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
    ap.add_argument("--dry-run", action="store_true",
                    help="print every request the scan would send and exit — "
                         "no sockets, no DNS")
    ap.add_argument("--verbose", action="store_true",
                    help="log every outbound connection (with the pinned IP dialed) "
                         "to stderr as it happens")
    ap.add_argument("--no-version-check", action="store_true",
                    help="skip the weekly PyPI version check "
                         "(also: AICHECK_NO_VERSION_CHECK=1)")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if args.dry_run:
        # Trust surface: the full request list, sent to no one. No target
        # validation, no DNS, no sockets — any string is a fine target here.
        urls = sorted(
            f"{'https' if port == 443 else 'http'}://{args.target}:{port}{path}"
            for port, path in recon.probe_plan()
        )
        print(f"# aicheck would send these {len(urls)} read-only GET requests to {args.target}:")
        print("\n".join(urls))
        return 0

    dialed: list[str] = []
    log = None
    if args.verbose:
        def log(method: str, url: str, pinned: str) -> None:
            dialed.append(pinned)
            print(f"→ {method} {url} (pinned {pinned})", file=sys.stderr)

    services = [s.strip() for s in args.services.split(",") if s.strip()] or None
    try:
        g, findings = asyncio.run(
            scan(args.target, allow_private=args.allow_private, services=services, log=log))
    except ssrf.TargetRejected as exc:
        print(f"target rejected: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # engine error — never report as a grade
        print(f"aicheck engine error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.verbose:
        print(f"# {len(dialed)} connections, all to {args.target} "
              f"(IPs: {', '.join(sorted(set(dialed)))})", file=sys.stderr)

    payload = {"target": args.target, "grade": g, "findings": findings}
    if services:
        payload["services_filter"] = services
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    elif args.format == "sarif":
        print(json.dumps(sarif.to_sarif(args.target, g, findings), indent=2))
    else:
        print(render_text(args.target, g, findings, services_filter=services), end="")
    # weekly PyPI version check — after output, failure-invisible, off on
    # --dry-run (returns above) and --version (exits in argparse)
    versioncheck.check_for_update(disabled=args.no_version_check)
    return 1 if _BADNESS[g] >= _BADNESS[args.fail_grade] else 0


if __name__ == "__main__":
    sys.exit(main())
