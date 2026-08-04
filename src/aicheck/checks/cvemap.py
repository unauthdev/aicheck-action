"""Version→CVE matching against content/cve_map.yaml.

Checkers that extract a version string call `cve_findings(product, version, url)`;
every map entry whose affected range matches yields one extra Finding whose
severity and fix card (cve-<id>) come from the curated map. Only what the
target actually reported is used — no version guessing.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import yaml

from ..models import Finding

MAP_PATH = Path(__file__).parent.parent / "content" / "cve_map.yaml"

_CLAUSE_RE = re.compile(r"^(>=|<=|==|>|<)\s*(\S+)$")

# Mappings older than this render as "stale — check the upstream advisory"
# instead of "verified" (auto-downgrade, STRATEGY §6.5).
STALE_DAYS = 180


def verification_state(entry: dict) -> str:
    """verified | stale | unreviewed — provenance label for rendering."""
    if not entry.get("human_approved"):
        return "unreviewed"
    lv = entry.get("last_verified")
    if isinstance(lv, str):
        try:
            lv = date.fromisoformat(lv[:10])
        except ValueError:
            return "unreviewed"
    if not isinstance(lv, date):
        return "unreviewed"
    return "stale" if (date.today() - lv).days > STALE_DAYS else "verified"


def entry_for_card(card_id: str) -> dict | None:
    """Fix-card id ('cve-2026-21858') -> its cve_map entry, if any."""
    if not card_id.startswith("cve-"):
        return None
    cve = "CVE-" + card_id[4:].upper()
    for entry in all_entries():
        if str(entry.get("cve", "")).upper() == cve:
            return entry
    return None


def all_entries() -> list[dict]:
    """Load the map fresh on every call — the file is small, and a cached
    copy would never pick up edits in a long-running process."""
    with open(MAP_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


_PRE_RE = re.compile(
    r"^(?P<release>[\d.]+?)(?P<pre>a|alpha|b|beta|rc|pre|preview)(?P<num>\d*)$",
    re.IGNORECASE,
)


def parse_version(v: str) -> tuple[tuple[int, ...], int, int] | None:
    """'v2.95.11' -> ((2, 95, 11), 0, 0).

    A pre-release suffix (rc/a/b/alpha/beta/pre/preview + optional number)
    is split off and marked with a -1 flag so it sorts BEFORE the release:
    '1.2rc1' -> ((1, 2), -1, 1) < ((1, 2), 0, 0) = '1.2'. Keeping the
    suffix digits in the numeric runs (the old behaviour) sorted '1.2rc1'
    as (1, 2, 1) — after '1.2' — letting a pre-release of a fixed version
    escape a '<fixed' range.
    """
    raw = (v or "").strip().lstrip("vV")
    m = _PRE_RE.match(raw)
    if m:
        release, pre = m.group("release"), (-1, int(m.group("num") or 0))
    else:
        release, pre = raw, (0, 0)
    parts = re.findall(r"\d+", release)
    if not parts:
        return None
    return (tuple(int(p) for p in parts), *pre)


_Version = tuple[tuple[int, ...], int, int]


def _cmp(a: _Version, b: _Version) -> int:
    (ra, pa, na), (rb, pb, nb) = a, b
    n = max(len(ra), len(rb))
    ra += (0,) * (n - len(ra))
    rb += (0,) * (n - len(rb))
    x, y = (ra, pa, na), (rb, pb, nb)
    return (x > y) - (x < y)


def in_range(version: _Version, expr: str) -> bool:
    for clause in expr.split(","):
        m = _CLAUSE_RE.match(clause.strip())
        if not m:
            return False
        op, raw = m.groups()
        bound = parse_version(raw)
        if bound is None:
            return False
        c = _cmp(version, bound)
        if op == ">=" and c < 0:
            return False
        if op == "<=" and c > 0:
            return False
        if op == ">" and c <= 0:
            return False
        if op == "<" and c >= 0:
            return False
        if op == "==" and c != 0:
            return False
    return True


# Private aliases kept for callers that imported the old names.
_parse_version = parse_version
_in_range = in_range


def match(product: str, version_str: str) -> list[dict]:
    """All cve_map entries for `product` whose affected range covers `version_str`."""
    version = parse_version(version_str)
    if version is None:
        return []
    product = product.lower()  # hand-typed checker literals must match case-insensitively
    hits = []
    for entry in all_entries():
        if str(entry.get("product", "")).lower() != product:
            continue
        affected = entry.get("affected") or []
        ranges = affected if isinstance(affected, list) else [affected]
        if any(isinstance(r, str) and in_range(version, r) for r in ranges):
            hits.append(entry)
    return hits


def cve_findings(product: str, version_str: str, url: str) -> list[Finding]:
    """Build one Finding per matching CVE. `url` keeps the TARGET placeholder —
    engine.run_checkers binds the real target afterwards."""
    out = []
    for entry in match(product, version_str):
        cve = entry["cve"]
        card_id = cve.lower()  # e.g. cve-2026-21858
        ranges = entry["affected"]
        range_str = " or ".join(ranges) if isinstance(ranges, list) else str(ranges)
        title = f"{product} {version_str} is vulnerable to {cve}"
        if entry.get("aka"):
            title += f" ({entry['aka']})"
        out.append(
            Finding(
                check_id=card_id,
                product=product,
                title=title,
                severity=entry["severity"],
                url=url,
                evidence=(
                    f"detected version {version_str} matches affected range "
                    f"{range_str}; {entry['summary'].strip()}"
                ),
                fix_card_id=card_id,
                details={
                    "cve": cve,
                    "affected": ranges,
                    "fixed_in": entry["fixed_in"],
                    "reference_url": entry["reference_url"],
                    "last_verified": str(entry.get("last_verified") or "") or None,
                    "verification": verification_state(entry),
                },
            )
        )
    return out
