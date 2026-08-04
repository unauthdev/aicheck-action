"""Flowise :3000 — drag-and-drop LLM agent/chatflow builder exposed.

Shares :3000 with Langfuse and half the Node dev ecosystem: fingerprint
strictly by content. GET /api/v1/ping returning {"ping": "pong"} is a generic
health shape and is NOT enough on its own. A Flowise-unique marker is
required in conjunction:
- "flowise" in the root page, or
- GET /api/v1/public-chatflows answering a list of flows (product-unique
  path), or
- ping/pong AND /api/v1/version answering a version (two exact Flowise
  API paths answering together).

Agent-runtime surface (GET-only, whitelisted by Flowise by design):
- GET /api/v1/public-chatflows → list of publicly callable chatflows/agentflows
  (CRITICAL — strangers can discover flows that /api/v1/prediction/{id} runs)
- Otherwise an open builder UI is HIGH (credentials + model keys behind it).
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .risk_classes import AGENT_RUNTIME, with_risk

CHECK_ID = "flowise"
FIX_CARD_ID = "flowise-exposed"


def _public_flows(p: ProbeResult | None) -> list[str]:
    if p is None or p.status_code in (401, 403) or not p.ok:
        return []
    data = p.json()
    items: list = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("data", "chatflows", "agentflows"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
    names: list[str] = []
    for item in items[:8]:
        if isinstance(item, dict):
            name = item.get("name") or item.get("id") or item.get("chatflowId")
            if name:
                names.append(str(name))
        elif isinstance(item, str) and item:
            names.append(item)
    return names


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    ping = facts.get("3000:/api/v1/ping")
    root = facts.get("3000:/")
    public = facts.get("3000:/api/v1/public-chatflows")
    version = facts.get("3000:/api/v1/version")

    ping_j = ping.json() if ping is not None and ping.ok else None
    ping_hit = isinstance(ping_j, dict) and ping_j.get("ping") == "pong"
    root_hit = root is not None and root.ok and "flowise" in root.body.lower()
    flow_names = _public_flows(public)
    # Version alone is weak; only use with other Flowise signals
    ver_j = version.json() if version is not None and version.ok else None
    ver_str = ""
    if isinstance(ver_j, dict) and ver_j.get("version"):
        ver_str = str(ver_j["version"])
    elif isinstance(ver_j, str) and ver_j.strip():
        ver_str = ver_j.strip().strip('"')
    elif version is not None and version.ok and version.body.strip().startswith('"'):
        ver_str = version.body.strip().strip('"')

    if not (root_hit or flow_names or (ping_hit and ver_str)):
        # ping/pong alone is a generic health shape — no Flowise evidence.
        return []

    bits = []
    if root is not None and root.ok and root_hit:
        bits.append(f"GET {root.url} → 200 (Flowise UI)")
    if ping_hit:
        bits.append(f"GET {ping.url} → 200, ping/pong")
    if ver_str:
        bits.append(f"version {ver_str}")

    if flow_names:
        shown = ", ".join(flow_names[:5])
        extra = len(flow_names) - 5
        catalog = shown + (f" (+{extra} more)" if extra > 0 else "")
        bits.append(
            f"GET {public.url} → 200 — public chatflows/agentflows listed ({catalog})"
        )
        return [
            Finding(
                check_id=CHECK_ID,
                product="Flowise",
                title="Flowise agent chatflows publicly callable without authentication",
                severity="CRITICAL",
                url="http://TARGET:3000/",
                evidence=(
                    "; ".join(bits)
                    + " — Flowise whitelists public chatflows and /api/v1/prediction/; "
                    "strangers can discover and run your agent flows on your models and keys"
                ),
                fix_card_id=FIX_CARD_ID,
                details=with_risk(
                    {"public_chatflows": flow_names[:8], "version": ver_str},
                    AGENT_RUNTIME,
                ),
            )
        ]

    return [
        Finding(
            check_id=CHECK_ID,
            product="Flowise",
            title="Flowise agent builder exposed to the internet",
            severity="HIGH",
            url="http://TARGET:3000/",
            evidence=(
                "; ".join(bits)
                + " — chatflows, agentflows, stored credentials and model API keys sit behind it"
            ),
            fix_card_id=FIX_CARD_ID,
            details=with_risk({"version": ver_str}, AGENT_RUNTIME),
        )
    ]
