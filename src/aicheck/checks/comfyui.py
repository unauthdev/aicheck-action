"""ComfyUI :8188 — UI + system stats exposed.

Fingerprint: GET / serves the ComfyUI front-end, or GET /system_stats returns
its system/devices JSON. That stats endpoint is a hardware leak: it discloses
GPU model, VRAM, driver/CUDA runtime and Python version to anyone. An open
ComfyUI accepts workflow uploads that execute arbitrary pipelines → CRITICAL.

Also fingerprints the ComfyUI-Manager extension via GET /api/manager/version
(versioned, and versions < 3.38 are CVE-2025-67303 unauth RCE).
"""

from __future__ import annotations

import re

from ..models import Finding, ProbeResult
from .cvemap import cve_findings

CHECK_ID = "comfyui"
FIX_CARD_ID = "comfyui-exposed"

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _manager_version(probe: ProbeResult | None) -> str:
    """Parse ComfyUI-Manager's version response — JSON {"version": ...} or a
    plain-text version string. Only returns what the response contained."""
    if probe is None or not probe.ok:
        return ""
    j = probe.json()
    if isinstance(j, dict):
        for key in ("version", "manager_version"):
            if isinstance(j.get(key), str):
                return j[key]
        data = j.get("data")
        if isinstance(data, dict) and isinstance(data.get("version"), str):
            return data["version"]
        return ""
    m = _VERSION_RE.search(probe.body.strip())
    return m.group(0) if m and len(probe.body.strip()) < 64 else ""


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("8188:/")
    stats = facts.get("8188:/system_stats")
    manager = facts.get("8188:/api/manager/version")

    stats_j = stats.json() if stats is not None and stats.ok else None
    stats_match = isinstance(stats_j, dict) and "system" in stats_j and "devices" in stats_j
    fingerprinted = (root is not None and root.ok and "comfyui" in root.body.lower()) or stats_match
    if not fingerprinted:
        return []

    evidence_bits = []
    hw: dict = {}
    if stats_match:
        devices = stats_j.get("devices") or []
        gpus = [str(d.get("name", "")) for d in devices if isinstance(d, dict) and d.get("name")]
        system = stats_j.get("system") or {}
        if isinstance(system, dict):
            hw = {
                k: str(system[k])
                for k in ("comfyui_version", "python_version", "pytorch_version", "os")
                if system.get(k)
            }
        leak = f"hardware leak — GPU: {', '.join(gpus) or 'n/a'}"
        if hw:
            leak += "; " + ", ".join(f"{k} {v}" for k, v in hw.items())
        evidence_bits.append(f"GET {stats.url} → 200 ({leak})")
    if root is not None and root.ok:
        evidence_bits.append("ComfyUI web UI reachable on /")

    findings = [
        Finding(
            check_id=CHECK_ID,
            product="ComfyUI",
            title="ComfyUI exposed — workflow upload and system stats open without authentication",
            severity="CRITICAL",
            url=f"http://TARGET:8188/",
            evidence="; ".join(evidence_bits),
            fix_card_id=FIX_CARD_ID,
            details={"hardware": hw},
        )
    ]

    manager_ver = _manager_version(manager)
    if manager_ver:
        findings[0].details["manager_version"] = manager_ver
        findings += cve_findings("ComfyUI-Manager", manager_ver, "http://TARGET:8188/")
    return findings
