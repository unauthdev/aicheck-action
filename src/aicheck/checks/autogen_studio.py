"""AutoGen Studio — Microsoft AutoGen multi-agent web UI.

Exposes team orchestration, sessions, and debugging for multi-agent workflows.
Defaults are demo-oriented; an open API is remote control of agent teams.

Fingerprint (GET-only), AIG autogen-studio parity:
- GET /api/version → body contains "AutoGen Studio API"
- GET /api/health → "Service is healthy" (supporting signal with version hit)

Common ports: 8080, 8000, 8081 (+ 443 via alias). Content decides — never port alone.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .risk_classes import AGENT_RUNTIME, with_risk

CHECK_ID = "autogen-studio"
FIX_CARD_ID = "autogen-studio-exposed"

_PORTS = ("8080", "8000", "8081", "443")


def _version_hit(p: ProbeResult | None) -> bool:
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False
    return "autogen studio api" in p.body.lower()


def _health_hit(p: ProbeResult | None) -> bool:
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False
    return "service is healthy" in p.body.lower()


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    for port in _PORTS:
        ver = facts.get(f"{port}:/api/version")
        health = facts.get(f"{port}:/api/health")
        if not _version_hit(ver):
            continue
        # Health alone is too generic — require version fingerprint
        probe = ver
        assert probe is not None
        health_bit = ""
        if _health_hit(health):
            health_bit = f"; GET {health.url} → {health.status_code} (healthy)"

        return [
            Finding(
                check_id=CHECK_ID,
                product="AutoGen Studio",
                title="AutoGen Studio agent API exposed without authentication",
                severity="CRITICAL",
                url=probe.url,
                evidence=(
                    f"GET {probe.url} → {probe.status_code} (AutoGen Studio API)"
                    f"{health_bit} — multi-agent teams, sessions and debugging "
                    "are reachable by strangers"
                ),
                fix_card_id=FIX_CARD_ID,
                details=with_risk({"port": port, "auth": "none"}, AGENT_RUNTIME),
            )
        ]
    return []
