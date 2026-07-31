"""Re-render a saved aicheck JSON artifact as json / sarif / text.

The action scans once (--format json) and derives every output from that one
artifact — the probe pipeline never runs twice in a job:

  python -m aicheck.scan "$TARGET" --allow-private --format json > aicheck.json
  python -m aicheck.render aicheck.json --format sarif > aicheck.sarif
  python -m aicheck.render aicheck.json --format text

--redact scrubs the scan target (hostname/IP) from the output: CI artifacts
carry grade, finding counts and product names only — never an internal
hostname the user did not consent to publish.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from . import sarif
from .scan import render_text

REDACTED_TARGET = "ci-scan-target"


def _url_host(url: str) -> str | None:
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:]+)", url or "")
    return m.group(1) if m else None


def redact(data: dict) -> dict:
    """Replace every occurrence of the scan target (raw or as it appears in
    finding URLs) with a placeholder."""
    targets = {str(data.get("target") or "")}
    for f in data.get("findings", []):
        host = _url_host(f.get("url", ""))
        if host:
            targets.add(host)
    raw = json.dumps(data)
    for t in sorted(targets, key=len, reverse=True):
        if t:
            raw = raw.replace(t, REDACTED_TARGET)
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m aicheck.render",
        description="Re-render a saved aicheck JSON artifact (no re-scan).")
    ap.add_argument("artifact",
                    help="JSON written by python -m aicheck.scan --format json")
    ap.add_argument("--format", choices=["json", "text", "sarif"],
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
    else:
        print(render_text(target, g, findings), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
