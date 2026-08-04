"""OpenClaw / Clawdbot / Moltbot — personal AI agent control plane.

Default gateway port 18789. Control UI ships for local use; internet exposure
lets strangers drive the agent (tools, skills, gateway). Escalate when the
config advertises auth_mode none.

Fingerprint (GET-only), AIG openclaw/clawdbot parity:
- GET / → OpenClaw/Clawdbot/Moltbot control UI markers
- GET /__openclaw/control-ui-config.json → serverVersion; auth_mode
"""

from __future__ import annotations

import re

from ..models import Finding, ProbeResult
from .risk_classes import AGENT_RUNTIME, with_risk

CHECK_ID = "openclaw"
FIX_CARD_ID = "openclaw-exposed"

_PORTS = ("18789", "443", "8080")
_CONFIG_PATH = "/__openclaw/control-ui-config.json"
_VERSION_RE = re.compile(r'"serverVersion"\s*:\s*"([^"]+)"')


def _ui_hit(p: ProbeResult | None) -> bool:
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False
    body = p.body.lower()
    return (
        "<openclaw-app>" in body
        or "<clawdbot-app>" in body
        or "<moltbot-app>" in body
        or "<title>openclaw control</title>" in body
        or "<title>clawdbot control</title>" in body
        or "<title>moltbot control</title>" in body
    )


def _config_info(p: ProbeResult | None) -> tuple[bool, str, bool]:
    """Return (is_openclaw_config, version, auth_none)."""
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False, "", False
    body = p.body
    low = body.lower()
    data = p.json()
    version = ""
    auth_none = False
    if isinstance(data, dict):
        version = str(data.get("serverVersion") or data.get("version") or "")
        mode = str(data.get("auth_mode") or data.get("authMode") or "").lower()
        auth_none = mode in ("none", "disabled", "off", "false")
    if not version:
        m = _VERSION_RE.search(body)
        if m:
            version = m.group(1)
    if not auth_none and "auth_mode" in low and "none" in low:
        auth_none = True
    hit = bool(version) or "serverversion" in low or "openclaw" in low or "clawdbot" in low
    return hit, version, auth_none


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    for port in _PORTS:
        root = facts.get(f"{port}:/")
        cfg = facts.get(f"{port}:{_CONFIG_PATH}")
        ui = _ui_hit(root)
        cfg_hit, version, auth_none = _config_info(cfg)
        if not (ui or cfg_hit):
            continue

        probe = root if ui and root is not None else cfg
        assert probe is not None
        version_bit = f"; version {version}" if version else ""

        if auth_none:
            severity = "CRITICAL"
            title = "OpenClaw control plane exposed with auth disabled"
            evidence = (
                f"GET {probe.url} → {probe.status_code}{version_bit} — "
                "OpenClaw/Clawdbot control UI or config answers without auth "
                "(`auth_mode: none`); strangers can drive the agent and its tools"
            )
        elif ui:
            severity = "CRITICAL"
            title = "OpenClaw control plane exposed to the internet"
            evidence = (
                f"GET {probe.url} → {probe.status_code}{version_bit} — "
                "OpenClaw/Clawdbot control UI is reachable; strangers can drive "
                "the agent and its tools"
            )
        else:
            severity = "HIGH"
            title = "OpenClaw control plane exposed to the internet"
            evidence = (
                f"GET {probe.url} → {probe.status_code}{version_bit} — "
                "OpenClaw config endpoint answers strangers; treat as an agent "
                "runtime on the public internet"
            )

        return [
            Finding(
                check_id=CHECK_ID,
                product="OpenClaw",
                title=title,
                severity=severity,
                url=probe.url,
                evidence=evidence,
                fix_card_id=FIX_CARD_ID,
                details=with_risk(
                    {
                        "port": port,
                        "version": version,
                        "auth": "none" if auth_none else "unknown",
                    },
                    AGENT_RUNTIME,
                ),
            )
        ]
    return []
