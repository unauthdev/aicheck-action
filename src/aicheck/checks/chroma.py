"""Chroma :8000 — vector database exposed.

Shares :8000 with vLLM: fingerprint strictly by content. Chroma's heartbeat
(/api/v1/heartbeat or /api/v2/heartbeat) returns
{"nanosecond heartbeat": ...}. If /api/v1/collections or /api/v2/collections
answers 200, every stored embedding is readable and writable by anyone —
CRITICAL. Chroma has no auth by default.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

CHECK_ID = "chroma"
FIX_CARD_ID = "chroma-exposed"


def _first_ok(*keys: str, facts: dict[str, ProbeResult]) -> ProbeResult | None:
    """Pick the first ProbeResult that answered 200 — never truthiness of the
    dataclass itself (every probed key exists in facts, including errors)."""
    for key in keys:
        p = facts.get(key)
        if p is not None and p.ok:
            return p
    return None


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    hb = _first_ok(
        "8000:/api/v2/heartbeat", "8000:/api/v1/heartbeat", facts=facts,
    )
    cols = _first_ok(
        "8000:/api/v2/collections", "8000:/api/v1/collections", facts=facts,
    )

    hb_j = hb.json() if hb is not None else None
    hb_hit = isinstance(hb_j, dict) and any("heartbeat" in str(k).lower() for k in hb_j)
    if not hb_hit:
        return []

    cols_j = cols.json() if cols is not None else None
    if isinstance(cols_j, list):
        names = [str(c.get("name", "?")) if isinstance(c, dict) else str(c) for c in cols_j[:5]]
        col_bit = f"; {len(cols_j)} collection(s) readable ({', '.join(names)})" if names else "; collection list readable"
        return [
            Finding(
                check_id=CHECK_ID,
                product="Chroma",
                title="Chroma vector database open without authentication",
                severity="CRITICAL",
                url="http://TARGET:8000/",
                evidence=(
                    f"GET {hb.url} → 200 (heartbeat); GET {cols.url} → 200{col_bit} — "
                    "no auth required. Anyone can read or delete every embedding you stored"
                ),
                fix_card_id=FIX_CARD_ID,
                details={"collections": names},
            )
        ]
    return [
        Finding(
            check_id=CHECK_ID,
            product="Chroma",
            title="Chroma instance exposed to the internet",
            severity="HIGH",
            url="http://TARGET:8000/",
            evidence=f"GET {hb.url} → 200 (Chroma heartbeat answers anyone)",
            fix_card_id=FIX_CARD_ID,
            details={},
        )
    ]
