"""Langfuse :3000 — instance exposed / signup page open.

:3000 is shared by many products — fingerprint strictly by content:
GET / mentions Langfuse, or GET /api/public/health answers its JSON health
blob. HIGH when the sign-up page is reachable, MEDIUM otherwise.
The health blob also discloses the exact server version.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .cvemap import cve_findings
from .risk_classes import AGENT_TRACES, with_risk

CHECK_ID = "langfuse"
FIX_CARD_ID = "langfuse-exposed"


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("3000:/")
    health = facts.get("3000:/api/public/health")
    signup = facts.get("3000:/auth/sign-up")

    health_j = health.json() if health is not None and health.ok else None
    fingerprinted = (root is not None and root.ok and "langfuse" in root.body.lower()) or (
        isinstance(health_j, dict) and "status" in health_j and "version" in health_j
    )
    if not fingerprinted:
        return []

    ver_str = str(health_j.get("version", "")) if isinstance(health_j, dict) else ""
    version_bit = f"; version {ver_str}" if ver_str else ""

    signup_open = signup is not None and signup.ok and "langfuse" in signup.body.lower()
    if signup_open:
        severity = "HIGH"
        title = "Langfuse exposed with open sign-up — agent traces readable"
        evidence = (
            f"GET {signup.url} → 200{version_bit} — the sign-up page is reachable, "
            "so anyone on the internet can create an account and read traces "
            "(prompts, tool calls, and often agent memory/state)"
        )
    else:
        severity = "MEDIUM"
        title = "Langfuse instance exposed to the internet"
        bits = []
        if health is not None and health.ok:
            bits.append(f"GET {health.url} → {health.status_code}{version_bit}")
        if root is not None and root.ok:
            bits.append("Langfuse fingerprint on /")
        evidence = (
            ("; ".join(bits) or "Langfuse fingerprint matched on :3000")
            + " — traces often retain prompts, tool calls, and agent session state"
        )

    findings = [
        Finding(
            check_id=CHECK_ID,
            product="Langfuse",
            title=title,
            severity=severity,
            url=f"http://TARGET:3000/",
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details=with_risk(
                {"version": ver_str, "signup_open": signup_open},
                AGENT_TRACES,
            ),
        )
    ]
    if ver_str:
        findings += cve_findings("Langfuse", ver_str, "http://TARGET:3000/")
    return findings
