"""Gradio vs Langflow on :7860 — same default port, content decides.

Langflow fingerprints: GET /api/v1/version or /health returns Langflow JSON,
or the page names Langflow. Versions < 1.9.0 match CVE-2026-33017
(CRITICAL, already in the CVE map).
Gradio fingerprints: the page carries Gradio markers (window.gradio_config,
"gradio" assets), or GET /config returns a Gradio-shaped app config — a JSON
object with at least two of Gradio's config keys (components, dependencies,
mode, layout, blocks). Any JSON object at /config is NOT enough on its own.
An exposed Gradio app is your ML demo on the public internet, often with
file upload. HIGH.
"""

from __future__ import annotations

import re

from ..models import Finding, ProbeResult
from .cvemap import cve_findings
from .risk_classes import AGENT_RUNTIME, with_risk

CHECK_ID = "gradio-langflow"
# Both cards this module can emit — loop_qa crawls FIX_CARD_ID* attributes.
FIX_CARD_ID = "gradio-exposed"
FIX_CARD_IDS = ("gradio-exposed", "langflow-exposed")

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _langflow_version(facts: dict[str, ProbeResult]) -> str:
    for key in ("7860:/api/v1/version", "7860:/health"):
        p = facts.get(key)
        if p is None or not p.ok:
            continue
        j = p.json()
        if isinstance(j, dict):
            v = str(j.get("version", ""))
            if v and _VERSION_RE.search(v):
                return v
            if j.get("status") == "ok" and "langflow" in str(j).lower():
                return ""
    return ""


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("7860:/")
    root_body = root.body.lower() if root is not None and root.ok else ""

    langflow_hit = "langflow" in root_body
    version = _langflow_version(facts)
    if langflow_hit or version:
        bits = []
        if root is not None and root.ok:
            bits.append(f"GET {root.url} → 200 (Langflow UI)")
        if version:
            bits.append(f"version {version}")
        findings = [
            Finding(
                check_id="langflow",
                product="Langflow",
                title="Langflow instance exposed to the internet",
                severity="HIGH",
                url="http://TARGET:7860/",
                evidence="; ".join(bits) + " — flows, credentials and API keys sit behind it",
                fix_card_id="langflow-exposed",
                details=with_risk({"version": version}, AGENT_RUNTIME),
            )
        ]
        if version:
            findings += cve_findings("Langflow", version, "http://TARGET:7860/")
        return findings

    config = facts.get("7860:/config")
    config_j = config.json() if config is not None and config.ok else None
    # Any JSON object at /config is too weak — require Gradio's config shape.
    gradio_config_keys = ("components", "dependencies", "mode", "layout", "blocks")
    config_gradio = (
        isinstance(config_j, dict)
        and sum(1 for k in gradio_config_keys if k in config_j) >= 2
    )
    gradio_hit = "gradio" in root_body or config_gradio
    if gradio_hit:
        bits = []
        if root is not None and root.ok:
            bits.append(f"GET {root.url} → 200 (Gradio app)")
        if config_gradio:
            bits.append("GET /config → 200 (Gradio app config)")
        return [
            Finding(
                check_id="gradio",
                product="Gradio",
                title="Gradio app exposed to the internet",
                severity="HIGH",
                url="http://TARGET:7860/",
                evidence="; ".join(bits) + " — your ML demo, its inputs and any file uploads are public",
                fix_card_id="gradio-exposed",
                details={},
            )
        ]
    return []
