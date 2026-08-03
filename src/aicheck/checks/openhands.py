"""OpenHands Agent Server — coding-agent control plane.

Default agent-server port 8000 (also seen on 3000 behind Agent Canvas).
Unauthenticated exposure lets strangers start agent sessions, run tools,
and burn LLM budget.

Fingerprint (GET-only), from OpenHands software-agent-sdk ServerInfo:
- GET / or /server_info → JSON with title \"OpenHands Agent Server\"
  and/or openhands-* version fields
- GET /health alone is too generic (status ok) — not sufficient
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .risk_classes import AGENT_RUNTIME, with_risk

CHECK_ID = "openhands"
FIX_CARD_ID = "openhands-exposed"

_PORTS = ("8000", "3000", "8080", "443")
_PATHS = ("/", "/server_info")


def _info_hit(p: ProbeResult | None) -> tuple[bool, str]:
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False, ""
    data = p.json()
    if not isinstance(data, dict):
        # SPA HTML for Agent Canvas
        low = p.body.lower()
        if "openhands" in low or "assets.openhands.dev" in low:
            return True, ""
        return False, ""
    title = str(data.get("title") or "")
    version = str(
        data.get("version")
        or data.get("sdk_version")
        or data.get("tools_version")
        or ""
    )
    blob = " ".join(
        str(data.get(k) or "")
        for k in (
            "title",
            "version",
            "sdk_version",
            "tools_version",
            "workspace_version",
            "build_git_ref",
        )
    ).lower()
    hit = (
        title == "OpenHands Agent Server"
        or "openhands agent server" in title.lower()
        or "openhands" in blob
        or "openhands-agent-server" in blob
        or "openhands-sdk" in blob
    )
    return hit, version


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    for port in _PORTS:
        for path in _PATHS:
            probe = facts.get(f"{port}:{path}")
            hit, version = _info_hit(probe)
            if not hit:
                continue
            assert probe is not None
            version_bit = f"; version {version}" if version else ""
            return [
                Finding(
                    check_id=CHECK_ID,
                    product="OpenHands",
                    title="OpenHands agent server exposed to the internet",
                    severity="CRITICAL",
                    url=probe.url,
                    evidence=(
                        f"GET {probe.url} → {probe.status_code}{version_bit} — "
                        "OpenHands Agent Server answers strangers; they can drive "
                        "coding agents, tools, and LLM spend"
                    ),
                    fix_card_id=FIX_CARD_ID,
                    details=with_risk(
                        {"port": port, "version": version},
                        AGENT_RUNTIME,
                    ),
                )
            ]
    return []
