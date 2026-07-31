"""Dify — self-hosted AI app platform exposed.

Dify Community Edition serves its web console on :80 (redirects to /signin)
and its API on :5001. Two distinct risks:
1. GET /console/api/setup → {"step": "not_started"} means the instance was
   never initialized: the FIRST visitor becomes admin. CRITICAL, same shape
   as the n8n owner-setup takeover.
2. A finished setup with the sign-in page reachable is still an exposed
   management console (apps, prompts, API keys, model credentials) — HIGH.
Fingerprint strictly by content (Dify markers in the signin page or the
setup JSON) — never by port alone.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

CHECK_ID = "dify"
FIX_CARD_ID = "dify-exposed"


def _setup_state(p: ProbeResult | None) -> tuple[bool, str]:
    """Returns (is_dify, step) from /console/api/setup."""
    if p is None or not p.ok:
        return False, ""
    j = p.json()
    if not isinstance(j, dict) or "step" not in j:
        return False, ""
    return True, str(j.get("step", ""))


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    signin = facts.get("80:/signin")
    setup = facts.get("5001:/console/api/setup")

    is_dify_setup, step = _setup_state(setup)
    signin_dify = signin is not None and signin.ok and "dify" in signin.body.lower()
    if not (is_dify_setup or signin_dify):
        return []

    if is_dify_setup and step.lower() in ("not_started", "not-started", "init"):
        severity = "CRITICAL"
        title = "Dify setup page exposed — no admin account, anyone can take over the instance"
        evidence = (
            f"GET {setup.url} → 200, step={step!r} — the instance was never initialized, "
            "so the first visitor to reach it becomes admin and owns every app, prompt and API key"
        )
    else:
        severity = "HIGH"
        title = "Dify console exposed to the internet"
        bits = []
        if signin is not None and signin.ok:
            bits.append(f"GET {signin.url} → 200 (sign-in page reachable)")
        if is_dify_setup:
            bits.append(f"GET {setup.url} → 200, step={step!r}")
        evidence = "; ".join(bits) or "Dify fingerprint matched"
        evidence += " — your apps, prompts and model credentials sit behind that login page"

    return [
        Finding(
            check_id=CHECK_ID,
            product="Dify",
            title=title,
            severity=severity,
            url="http://TARGET:80/signin",
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details={"setup_step": step},
        )
    ]
