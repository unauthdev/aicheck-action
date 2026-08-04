"""AnythingLLM :3001 — all-in-one LLM app exposed.

Fingerprint: the index page names AnythingLLM. GET /api/ping answering
{"online": true} is a generic ping shape shared by many apps — it
corroborates but never identifies, so ping alone yields NO finding.
Default single-user mode has NO auth at all: anyone who reaches the UI can
use your models, read your uploaded documents and change settings. CRITICAL
when the app identifies itself unauthenticated.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

CHECK_ID = "anythingllm"
FIX_CARD_ID = "anythingllm-exposed"


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("3001:/")
    ping = facts.get("3001:/api/ping")

    root_hit = root is not None and root.ok and "anythingllm" in root.body.lower()
    ping_j = ping.json() if ping is not None and ping.ok else None
    ping_ok = isinstance(ping_j, dict) and ping_j.get("online") is True
    if not root_hit:
        # {"online": true} alone is a generic ping shape — no finding.
        return []

    bits = []
    if root is not None and root.ok:
        bits.append(f"GET {root.url} → 200 (AnythingLLM UI)")
    if ping_ok:
        bits.append(f"GET {ping.url} → 200, online=true")
    evidence = (
        "; ".join(bits)
        + " — the app answers without any login: anyone can chat with your models, "
        "read the documents you uploaded, and change settings"
    )

    return [
        Finding(
            check_id=CHECK_ID,
            product="AnythingLLM",
            title="AnythingLLM open without authentication",
            severity="CRITICAL",
            url="http://TARGET:3001/",
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details={},
        )
    ]
