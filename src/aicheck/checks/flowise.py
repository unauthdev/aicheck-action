"""Flowise :3000 — drag-and-drop LLM flow builder exposed.

Shares :3000 with Langfuse: fingerprint strictly by content. GET /api/v1/ping
returns {"ping": "pong"} on Flowise, or the page carries Flowise markers.
An unauthenticated Flowise exposes chatflows, credentials and model API keys.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

CHECK_ID = "flowise"
FIX_CARD_ID = "flowise-exposed"


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    ping = facts.get("3000:/api/v1/ping")
    root = facts.get("3000:/")

    ping_j = ping.json() if ping is not None and ping.ok else None
    ping_hit = isinstance(ping_j, dict) and ping_j.get("ping") == "pong"
    root_hit = root is not None and root.ok and "flowise" in root.body.lower()
    if not (ping_hit or root_hit):
        return []

    bits = []
    if root is not None and root.ok:
        bits.append(f"GET {root.url} → 200 (Flowise UI)")
    if ping_hit:
        bits.append(f"GET {ping.url} → 200, ping/pong")
    return [
        Finding(
            check_id=CHECK_ID,
            product="Flowise",
            title="Flowise instance exposed to the internet",
            severity="HIGH",
            url="http://TARGET:3000/",
            evidence="; ".join(bits) + " — chatflows, stored credentials and model API keys sit behind it",
            fix_card_id=FIX_CARD_ID,
            details={},
        )
    ]
