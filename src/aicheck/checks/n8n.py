"""n8n :5678 — owner-setup page exposed / settings readable.

Fingerprint: GET / serves the n8n web app. Exposure is only reported when
GET /rest/settings answers 200 without auth (auth-required 401 → no finding).
CRITICAL if no owner account exists yet (anyone can claim the instance),
HIGH if settings are simply readable.

Version: n8n ships its release in the index HTML as a base64-encoded
`n8n:config:sentry` meta tag ({"release": "n8n@<version>", ...}). We decode
that — it is what the server actually sent, not a guess.

Auth-walled (observation, INFO — never graded): the n8n web app answers on /
(the SPA serves even when auth is on — a product-unique marker) while
/rest/settings demands auth, or a walled probe's own body/Server header
names n8n. A bare 401 on :5678 is NOT evidence.
"""

from __future__ import annotations

import base64
import json
import re

from ..models import Finding, ProbeResult
from .auth_wall import observation, walled, walled_and_marked
from .cvemap import cve_findings

CHECK_ID = "n8n"
FIX_CARD_ID = "n8n-exposed"

_SENTRY_META_RE = re.compile(r'<meta name="n8n:config:sentry" content="([^"]+)"')


def _version_from_html(body: str) -> str:
    m = _SENTRY_META_RE.search(body or "")
    if not m:
        return ""
    try:
        payload = json.loads(base64.b64decode(m.group(1)).decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return ""
    release = str(payload.get("release", ""))  # e.g. "n8n@2.32.5"
    if release.startswith("n8n@"):
        return release.split("@", 1)[1]
    return ""


def _settings_data(settings: ProbeResult) -> dict | None:
    j = settings.json()
    if not isinstance(j, dict):
        return None
    data = j.get("data", j)
    return data if isinstance(data, dict) else None


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("5678:/")
    settings = facts.get("5678:/rest/settings")

    data = _settings_data(settings) if settings is not None and settings.ok else None
    root_hit = root is not None and root.ok and "n8n" in root.body.lower()
    # Proxied n8n (TLS on 443): the root HTML isn't reachable, but the settings
    # JSON shape is itself a definitive n8n fingerprint.
    settings_hit = isinstance(data, dict) and (
        "userManagement" in data or "settingsMode" in data
    )
    if not (root_hit or settings_hit):
        hit = walled_and_marked((root, settings), "n8n")
        if hit is None:
            return []
        return [
            observation(
                check_id=CHECK_ID,
                product="n8n",
                title="n8n instance present but auth-walled",
                url="http://TARGET:5678/",
                evidence=(
                    f"GET {hit.url} → {hit.status_code} — the walled response itself "
                    "carries an n8n marker; the instance is present but demands "
                    "authentication (present, not graded)"
                ),
                fix_card_id=FIX_CARD_ID,
            )
        ]
    if settings is None or not settings.ok or data is None:
        if walled(settings):
            # The n8n web app answered on / (product-unique) while the settings
            # API demands auth — the standard auth'd n8n deployment.
            return [
                observation(
                    check_id=CHECK_ID,
                    product="n8n",
                    title="n8n instance present but auth-walled",
                    url="http://TARGET:5678/",
                    evidence=(
                        f"GET {root.url if root is not None else settings.url} → 200 "
                        f"(n8n web app); GET {settings.url} → {settings.status_code} "
                        "— the instance is present but its settings API demands "
                        "authentication (present, not graded)"
                    ),
                    fix_card_id=FIX_CARD_ID,
                )
            ]
        return []

    ver_str = _version_from_html(root.body) if root is not None else ""

    owner_setup = data.get("userManagement", {})
    if not isinstance(owner_setup, dict):
        owner_setup = {}
    # n8n 1.x: userManagement.isInstanceOwnerSetUp=false
    # n8n 2.x: userManagement.showSetupOnFirstLoad=true (verified live against n8n 2.32.x)
    no_owner = owner_setup.get("isInstanceOwnerSetUp") is False or (
        owner_setup.get("showSetupOnFirstLoad") is True
        or data.get("showSetupOnFirstLoad") is True
    )

    version_bit = f"; version {ver_str}" if ver_str else ""
    if no_owner:
        severity = "CRITICAL"
        title = "n8n owner-setup page exposed — no owner account, anyone can take over the instance"
        evidence = (
            f"GET {settings.url} → 200{version_bit}; owner-setup exposed "
            "(isInstanceOwnerSetUp=false or showSetupOnFirstLoad=true) — the first visitor becomes admin"
        )
    else:
        severity = "HIGH"
        title = "n8n settings endpoint readable without authentication"
        evidence = f"GET {settings.url} → 200{version_bit} (instance settings disclosed)"

    findings = [
        Finding(
            check_id=CHECK_ID,
            product="n8n",
            title=title,
            severity=severity,
            url=f"http://TARGET:5678/",
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details={"version": ver_str, "owner_setup_exposed": no_owner},
        )
    ]
    if ver_str:
        findings += cve_findings("n8n", ver_str, "http://TARGET:5678/")
    return findings
