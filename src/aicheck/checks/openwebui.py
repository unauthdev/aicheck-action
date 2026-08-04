"""Open WebUI :8080 — instance exposed / open signup.

Fingerprint: GET /api/config returns JSON naming "Open WebUI", or the index
page title says Open WebUI. HIGH when open signup is enabled, MEDIUM when the
instance is merely reachable. /api/config also discloses the exact version.

Auth-walled (observation, INFO — never graded): an Open WebUI probe answering
401/403 whose own body or Server header names Open WebUI (e.g. an auth proxy
in front of the SPA). A bare 401 on :8080 is NOT evidence (the port is
shared with Weaviate, MCP servers and arbitrary apps).
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .auth_wall import observation, walled_and_marked
from .cvemap import cve_findings

CHECK_ID = "openwebui"
FIX_CARD_ID = "open-webui-exposed"


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("8080:/")
    config = facts.get("8080:/api/config")

    cfg = config.json() if config is not None and config.ok else None
    fingerprinted = (isinstance(cfg, dict) and "open webui" in str(cfg.get("name", "")).lower()) or (
        root is not None and root.ok and "open webui" in root.body.lower()
    )
    if not fingerprinted:
        hit = walled_and_marked((root, config), "open webui")
        if hit is None:
            return []
        return [
            observation(
                check_id=CHECK_ID,
                product="Open WebUI",
                title="Open WebUI instance present but auth-walled",
                url="http://TARGET:8080/",
                evidence=(
                    f"GET {hit.url} → {hit.status_code} — the walled response itself "
                    "carries an Open WebUI marker; the instance is present but "
                    "demands authentication (present, not graded)"
                ),
                fix_card_id=FIX_CARD_ID,
            )
        ]

    signup_enabled = False
    ver_str = ""
    if isinstance(cfg, dict):
        features = cfg.get("features", {})
        if isinstance(features, dict):
            signup_enabled = bool(features.get("enable_signup"))
        if isinstance(cfg.get("version"), str):
            ver_str = cfg["version"]

    version_bit = f"; version {ver_str}" if ver_str else ""
    if signup_enabled:
        severity = "HIGH"
        title = "Open WebUI exposed with open signup — anyone on the internet can create an account"
        evidence = (
            f"GET {config.url} → 200{version_bit}; features.enable_signup=true "
            "— strangers can register and use your models at your expense"
        )
    else:
        severity = "MEDIUM"
        title = "Open WebUI instance exposed to the internet"
        evidence = f"Open WebUI fingerprint matched on :8080{version_bit}; signup is disabled"

    findings = [
        Finding(
            check_id=CHECK_ID,
            product="Open WebUI",
            title=title,
            severity=severity,
            url=f"http://TARGET:8080/",
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details={"version": ver_str, "signup_enabled": signup_enabled},
        )
    ]
    if ver_str:
        findings += cve_findings("Open WebUI", ver_str, "http://TARGET:8080/")
    return findings
