"""Version→CVE matching against content/cve_map.yaml.

Checkers that extract a version string call `cve_findings(product, version, url)`;
every map entry whose affected range matches yields one extra Finding whose
severity and fix card (cve-<id>) come from the curated map. Only what the
target actually reported is used — no version guessing.
"""

from __future__ import annotations

import re
from datetime import date
from functools import lru_cache
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


@lru_cache(maxsize=1)
def all_entries() -> list[dict]:
    with open(MAP_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


def _parse_version(v: str) -> tuple[int, ...] | None:
    """'v2.95.11' -> (2, 95, 11). Numeric runs are kept ('1.2rc1' -> (1, 2, 1))."""
    parts = re.findall(r"\d+", v or "")
    if not parts:
        return None
    return tuple(int(p) for p in parts)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)


def _in_range(version: tuple[int, ...], expr: str) -> bool:
    for clause in expr.split(","):
        m = _CLAUSE_RE.match(clause.strip())
        if not m:
            return False
        op, raw = m.groups()
        bound = _parse_version(raw)
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


def match(product: str, version_str: str) -> list[dict]:
    """All cve_map entries for `product` whose affected range covers `version_str`."""
    version = _parse_version(version_str)
    if version is None:
        return []
    hits = []
    for entry in all_entries():
        if entry.get("product") != product:
            continue
        affected = entry.get("affected") or []
        ranges = affected if isinstance(affected, list) else [affected]
        if any(isinstance(r, str) and _in_range(version, r) for r in ranges):
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
