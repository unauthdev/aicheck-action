"""CrewAI Studio — multi-agent orchestration control plane.

CrewAI Studio login/UI is built for operators; a public login page means the
control plane is on the internet (credentials + crew definitions + model keys
behind it). Headless CrewAI library deploys without Studio are out of scope.

Fingerprint (GET-only), AIG crewai parity:
- GET /auth/login → body contains both "CrewAI Studio" and "app.crewai.com"
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .risk_classes import AGENT_RUNTIME, with_risk

CHECK_ID = "crewai"
FIX_CARD_ID = "crewai-exposed"

_PORTS = ("8000", "8080", "8501", "3000", "443")
_LOGIN = "/auth/login"


def _studio_hit(p: ProbeResult | None) -> bool:
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False
    body = p.body
    # Keep case-sensitive product strings from the AIG fingerprint, then
    # fall back to case-insensitive for HTML variants.
    if "CrewAI Studio" in body and "app.crewai.com" in body:
        return True
    low = body.lower()
    return "crewai studio" in low and "app.crewai.com" in low


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    for port in _PORTS:
        login = facts.get(f"{port}:{_LOGIN}")
        if not _studio_hit(login):
            continue
        assert login is not None
        return [
            Finding(
                check_id=CHECK_ID,
                product="CrewAI Studio",
                title="CrewAI Studio exposed to the internet",
                severity="HIGH",
                url=login.url,
                evidence=(
                    f"GET {login.url} → {login.status_code} — CrewAI Studio login "
                    "is reachable; crews, flows, and model credentials sit behind "
                    "this control plane"
                ),
                fix_card_id=FIX_CARD_ID,
                details=with_risk({"port": port, "auth": "login-page"}, AGENT_RUNTIME),
            )
        ]
    return []
