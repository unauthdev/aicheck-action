"""CLI entrypoint: python -m aicheck.scan <target> [options]

CI-shaped wrapper over the live-probe pipeline (recon → checkers → grade).
Answers one question in a build job: "did we just ship an AI service with no
auth?" Runs entirely against the given target — no database, no emails, zero
network calls beyond the target by default. An optional weekly PyPI update
check exists but stays off unless explicitly enabled (--version-check or
AICHECK_VERSION_CHECK=1; inventory mode never performs it).

  python -m aicheck.scan localhost --allow-private
  python -m aicheck.scan example.com --format sarif --fail-grade C > results.sarif

Trust-surface flags:
  --dry-run   print every request the scan would send (sorted, one per line)
              and exit 0 — no sockets, no DNS, works for any target string.
  --verbose   log every outbound connection to stderr as it happens, with the
              pinned IP actually dialed, plus a closing summary line.

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
from .probe_class import ProbeClassError, ProbeMode, resolve_probe_mode
from .scoring import grade, run_checkers

_BADNESS = {"A": 0, "C": 1, "D": 2, "F": 3}

CLEAN_DOOR = ("clean. keep it that way: the CI action watches every PR → "
              "https://github.com/unauthdev/aicheck-scan")


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
               log: recon.ConnectLog | None = None,
               probe_mode: ProbeMode | None = None) -> tuple[str, list[dict], list[dict], dict]:
    """Returns (grade, findings, observations, coverage). Raises
    ssrf.TargetRejected on bad targets. coverage (recon.coverage_stats) tells
    the caller how much of the probe plan was answered — a dead/filtered host
    grades A on partial facts. observations are fingerprinted-but-auth-walled
    services (severity INFO): reported, never graded. `log`, when given,
    receives (method, logical_url, dialed_address) before every outbound
    request — the --verbose connection log.

    `probe_mode` is the resolved Class A/B gate (probe_class.resolve_probe_
    mode). Only when it carries the "data-plane" pack does the scan also send
    zero-byte TCP connects to the vector-store data-plane ports and let the
    connect-aware checkers conjoin them with the Class A fingerprints."""
    if allow_private:
        host, ips = resolve_internal(target)
    else:
        host, ips = ssrf.validate_target(target)
    facts = await recon.gather_facts(host, transport=transport, pinned_ips=ips, log=log)
    coverage = recon.coverage_stats(facts)
    connects = None
    if probe_mode is not None and "data-plane" in probe_mode.deep_packs:
        connects = await recon.gather_connects(
            host, recon.connect_plan(), pinned_ips=ips, log=log
        )
    findings, observations = run_checkers(facts, host, connects=connects)
    if services:
        wanted = {s.lower() for s in services}
        findings = [f for f in findings if _services_wanted(f, wanted)]
        observations = [o for o in observations if _services_wanted(o, wanted)]
    return (
        grade(findings),
        [f.to_dict() for f in findings],
        [o.to_dict() for o in observations],
        coverage,
    )


def _door_line(g: str, findings: list[dict]) -> str:
    """Closing line for text output. Uses playground deep link when the
    Action-only render module is present; otherwise a plain fix-card line."""
    if not findings:
        return CLEAN_DOOR
    try:
        from .render import deep_link
        return (f"fix cards: https://unauth.dev/fixes/{findings[0]['fix_card_id']} — "
                f"see your stack the way the internet sees it: "
                f"{deep_link(g, findings, source='cli')}")
    except ImportError:
        return f"fix cards: https://unauth.dev/fixes/{findings[0]['fix_card_id']}"


def render_text(target: str, g: str, findings: list[dict],
                services_filter: list[str] | None = None,
                coverage: dict | None = None,
                observations: list[dict] | None = None) -> str:
    lines = [f"aicheck — {target} → grade {g} ({len(findings)} findings)"]
    if coverage and coverage.get("partial"):
        lines.append(
            f"note: partial scan — {coverage['probes_answered']}/{coverage['probes_total']} "
            "probes answered (host may be filtered)"
        )
    for f in findings:
        lines.append(f"  {f['severity']:8} {f['product']}: {f['title']}")
        known = (f.get("details") or {}).get("known_cves")
        if known:
            lines.append(f"           {known}")
        lines.append(f"           fix: https://unauth.dev/fixes/{f['fix_card_id']}")
    if not findings:
        if services_filter:
            lines.append(
                f"  no findings in filtered services ({', '.join(services_filter)}) "
                "— other products were not graded"
            )
        else:
            lines.append("  clean — no exposed AI services found")
    if observations:
        # Structurally separate channel: fingerprinted-but-auth-walled services
        # are reported for visibility and NEVER graded.
        lines.append(
            f"  observed (auth-walled): {len(observations)} services — "
            "present but not graded"
        )
        for o in observations:
            lines.append(f"  {o['severity']:8} {o['product']}: {o['title']}")
    lines.append(_door_line(g, findings))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="aicheck scan",
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
    ap.add_argument("--version-check", action="store_true",
                    help="opt in to a weekly PyPI update check after results "
                         "print (also: AICHECK_VERSION_CHECK=1) — off by default")
    ap.add_argument("--no-version-check", action="store_true",
                    help="deprecated no-op kept for backcompat: the update "
                         "check is opt-in since it flipped from opt-out; this "
                         "flag still silences it (also: AICHECK_NO_VERSION_CHECK=1)")
    ap.add_argument("--deep", action="store_true",
                    help="Class B gate: customer-run estate mode (requires "
                         "--i-own-these-targets); enables opt-in deep packs")
    ap.add_argument("--i-own-these-targets", action="store_true",
                    help="required with --deep: you authorize probing this "
                         "target beyond Class A")
    ap.add_argument("--deep-packs", default="",
                    help="comma-separated Class B packs (available: data-plane — "
                         "zero-byte TCP connects to vector-store data-plane ports)")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    packs = [s.strip() for s in args.deep_packs.split(",") if s.strip()]
    try:
        probe_mode = resolve_probe_mode(
            deep=args.deep,
            i_own_these_targets=args.i_own_these_targets,
            deep_packs=packs,
        )
    except ProbeClassError as exc:
        print(f"probe class error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        urls = sorted(
            f"{'https' if port == 443 else 'http'}://{args.target}:{port}{path}"
            for port, path in recon.probe_plan()
        )
        print(f"# aicheck would send these {len(urls)} read-only GET requests to {args.target}:")
        print("\n".join(urls))
        if "data-plane" in probe_mode.deep_packs:
            connects = [
                f"CONNECT tcp://{args.target}:{port} (0 bytes)"
                for port in recon.connect_plan()
            ]
            print(f"# plus these {len(connects)} zero-byte TCP connects "
                  "(Class B data-plane pack — connect-and-close, nothing sent):")
            print("\n".join(connects))
        return 0

    dialed: list[str] = []
    log = None
    if args.verbose:
        def log(method: str, url: str, pinned: str) -> None:
            dialed.append(pinned)
            print(f"→ {method} {url} (pinned {pinned})", file=sys.stderr)

    services = [s.strip() for s in args.services.split(",") if s.strip()] or None
    try:
        g, findings, observations, coverage = asyncio.run(
            scan(args.target, allow_private=args.allow_private, services=services,
                 log=log, probe_mode=probe_mode))
    except ssrf.TargetRejected as exc:
        print(f"target rejected: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # engine error — never report as a grade
        print(f"aicheck engine error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    if args.verbose:
        print(f"# {len(dialed)} connections, all to {args.target} "
              f"(IPs: {', '.join(sorted(set(dialed)))})", file=sys.stderr)

    payload = {"target": args.target, "grade": g, "findings": findings,
               "observations": observations, "coverage": coverage}
    if services:
        payload["services_filter"] = services
    if probe_mode.probe_class != "A":
        # Class B is customer-run-only; the payload must say which traffic
        # produced these findings (docs/PROBES.md).
        payload["probe_mode"] = probe_mode.to_dict()
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    elif args.format == "sarif":
        print(json.dumps(sarif.to_sarif(args.target, g, findings, coverage=coverage,
                                        observations=observations), indent=2))
    else:
        print(render_text(args.target, g, findings, services_filter=services,
                          coverage=coverage, observations=observations), end="")

    try:
        from . import versioncheck
        versioncheck.check_for_update(enabled=args.version_check,
                                      disabled=args.no_version_check)
    except ImportError:
        pass
    return 1 if _BADNESS[g] >= _BADNESS[args.fail_grade] else 0


if __name__ == "__main__":
    sys.exit(main())
