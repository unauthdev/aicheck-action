"""Re-render a saved aicheck JSON artifact as json / sarif / text / summary.

The action scans once (--format json) and derives every output from that one
artifact — the probe pipeline never runs twice in a job:

  python -m aicheck.scan "$TARGET" --allow-private --format json > aicheck.json
  python -m aicheck.render aicheck.json --format sarif > aicheck.sarif
  python -m aicheck.render aicheck.json --format text
  python -m aicheck.render aicheck.json --format summary >> "$GITHUB_STEP_SUMMARY"

--redact scrubs the scan target (hostname/IP) from the output: CI artifacts,
the job summary and the deep link carry grade, finding counts and product
names only — never an internal hostname the user did not consent to publish.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from . import sarif
from .scan import render_text

REDACTED_TARGET = "ci-scan-target"
BASE_URL = "https://unauth.dev"
PLAYGROUND_URL = f"{BASE_URL}/playground"
ACTION_URL = "https://github.com/unauthdev/aicheck-action"
MAX_ROWS = 20

# Privacy/scope disclaimer — also the pitch. Keep verbatim.
FOOTER = (
    "---\n"
    f"[aicheck]({ACTION_URL}) by [unauth.dev]({BASE_URL}) · "
    "grade A = clean · this scan probed only the services in this job — "
    "your production firewall is invisible from CI"
)


def _url_host(url: str) -> str | None:
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:]+)", url or "")
    return m.group(1) if m else None


# Fields that never get redacted: identifiers and references, not hosts.
_NEVER_REDACT_KEYS = {"check_id", "fix_card_id", "product", "cve",
                      "reference_url"}


def _redact_host_context(text: str, host: str) -> str:
    """Replace `host` only in URL/host context — immediately followed by a
    port (:11434) or a path (/api) — never as a bare substring, so a target
    like 'ollama' can't corrupt check_id/fix_card_id ('ollama-exposed')."""
    if not host:
        return text
    return re.sub(re.escape(host) + r"(?=:\d|/)", REDACTED_TARGET, text)


def _redact_value(value, hosts: list[str]):
    if isinstance(value, str):
        for h in hosts:
            value = _redact_host_context(value, h)
        return value
    if isinstance(value, list):
        return [_redact_value(v, hosts) for v in value]
    if isinstance(value, dict):
        return {k: (v if k in _NEVER_REDACT_KEYS else _redact_value(v, hosts))
                for k, v in value.items()}
    return value


def redact(data: dict) -> dict:
    """Scrub the scan target structurally: data['target'], the host portion
    of finding URLs, and host-context occurrences inside evidence/details
    strings. check_id, fix_card_id, product and CVE references are never
    touched — a target that equals a product slug must not corrupt them."""
    host = str(data.get("target") or "")
    url_hosts = {h for h in
                 (_url_host(f.get("url", "")) for f in data.get("findings", []))
                 if h}
    hosts = sorted(({host} | url_hosts) - {""}, key=len, reverse=True)
    findings = []
    for f in data.get("findings", []):
        f = dict(f)
        url = f.get("url", "")
        if _url_host(url):
            # the host portion of a finding URL is always the scan target
            f["url"] = re.sub(
                r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/:]+",
                r"\g<1>" + REDACTED_TARGET, url)
        for key, value in f.items():
            if key in _NEVER_REDACT_KEYS or key == "url":
                continue
            f[key] = _redact_value(value, hosts)
        findings.append(f)
    return {**data, "target": REDACTED_TARGET if host else data.get("target"),
            "findings": findings}


def _slug(product: str) -> str:
    return re.sub(r"\s+", "-", product.strip().lower())


def deep_link(g: str, findings: list[dict]) -> str:
    """Playground deep link: grade, finding count, product names only —
    never the target."""
    services: list[str] = []
    for f in findings:
        s = _slug(f["product"])
        if s not in services:
            services.append(s)
    url = f"{PLAYGROUND_URL}?from=ci&grade={g}&findings={len(findings)}"
    if services:
        url += "&services=" + ",".join(services)
    return url


def render_summary(g: str, findings: list[dict]) -> str:
    """Markdown for GITHUB_STEP_SUMMARY — the action's main output surface."""
    lines: list[str] = []
    if g == "A":
        lines.append("## aicheck — grade A ✓ clean")
        lines.append("")
    else:
        n = len(findings)
        noun = "service" if n == 1 else "services"
        pronoun = "it" if n == 1 else "them"
        lines.append(f"## aicheck — grade {g}")
        lines.append("")
        lines.append(
            f"Your PR ships **{n} exposed AI {noun}** — "
            f"anyone who can reach {pronoun} can use {pronoun}.")
        lines.append("")
        lines.append("| severity | service | finding | fix |")
        lines.append("|---|---|---|---|")
        for f in findings[:MAX_ROWS]:
            product = f["product"].replace("|", "\\|")
            title = f["title"].replace("|", "\\|")
            fix = f"{BASE_URL}/fixes/{f['fix_card_id']}"
            lines.append(f"| {f['severity']} | {product} | {title} | [fix card]({fix}) |")
        if n > MAX_ROWS:
            lines.append("")
            lines.append(f"…and {n - MAX_ROWS} more — full list in the code-scanning tab.")
        lines.append("")
    lines.append(f"[See your stack the way the internet sees it →]({deep_link(g, findings)})")
    lines.append("")
    lines.append(FOOTER)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m aicheck.render",
        description="Re-render a saved aicheck JSON artifact (no re-scan).")
    ap.add_argument("artifact",
                    help="JSON written by python -m aicheck.scan --format json")
    ap.add_argument("--format", choices=["json", "text", "sarif", "summary"],
                    default="text")
    ap.add_argument("--redact", action="store_true",
                    help="scrub the scan target (hostname/IP) from the output")
    args = ap.parse_args(argv)

    try:
        with open(args.artifact, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"aicheck render error: cannot read {args.artifact}: {exc}",
              file=sys.stderr)
        return 2

    if args.redact:
        data = redact(data)
    target, g, findings = data["target"], data["grade"], data["findings"]

    if args.format == "json":
        print(json.dumps(data, indent=2))
    elif args.format == "sarif":
        print(json.dumps(sarif.to_sarif(target, g, findings), indent=2))
    elif args.format == "summary":
        print(render_summary(g, findings), end="")
    else:
        print(render_text(target, g, findings), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
