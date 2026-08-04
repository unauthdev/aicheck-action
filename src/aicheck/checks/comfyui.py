"""ComfyUI :8188 — UI + system stats exposed.

Fingerprint (a page merely mentioning ComfyUI is NOT enough for the top
grade — :8188 is not exclusive and the string appears in docs/tutorials):
- GET /system_stats returns ComfyUI's {"system": ..., "devices": ...} shape,
  or GET /api/manager/version answers a ComfyUI-Manager version → CRITICAL.
  The stats endpoint is also a hardware leak: GPU model, VRAM, driver/CUDA
  runtime and Python version to anyone. An open ComfyUI accepts workflow
  uploads that execute arbitrary pipelines.
- Only the "comfyui" string in the root page, with no stats/manager
  corroboration → MEDIUM (exposed UI, thin evidence).

ComfyUI-Manager versions < 3.38 are CVE-2025-67303 unauth RCE (CVE map).
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
    root_hit = root is not None and root.ok and "comfyui" in root.body.lower()
    manager_ver = _manager_version(manager)
    # Strong identity: ComfyUI-shaped /system_stats or the ComfyUI-Manager
    # version endpoint answering. The bare "comfyui" string is only MEDIUM.
    strong = stats_match or bool(manager_ver)
    if not (strong or root_hit):
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
    if root_hit:
        evidence_bits.append("ComfyUI web UI reachable on /")

    if strong:
        if manager_ver and not stats_match:
            evidence_bits.append(
                f"GET {manager.url} → 200 (ComfyUI-Manager version {manager_ver})"
            )
        title = (
            "ComfyUI exposed — workflow upload and system stats open without authentication"
            if stats_match
            else "ComfyUI exposed — ComfyUI-Manager answers without authentication"
        )
        findings = [
            Finding(
                check_id=CHECK_ID,
                product="ComfyUI",
                title=title,
                severity="CRITICAL",
                url=f"http://TARGET:8188/",
                evidence="; ".join(evidence_bits),
                fix_card_id=FIX_CARD_ID,
                details={"hardware": hw},
            )
        ]
    else:
        findings = [
            Finding(
                check_id=CHECK_ID,
                product="ComfyUI",
                title="ComfyUI web UI exposed to the internet",
                severity="MEDIUM",
                url=f"http://TARGET:8188/",
                evidence=(
                    "; ".join(evidence_bits)
                    + " — page names ComfyUI but /system_stats and /api/manager/version "
                    "did not corroborate; likely an exposed UI, evidence is thin"
                ),
                fix_card_id=FIX_CARD_ID,
                details={"hardware": hw},
            )
        ]

    if manager_ver:
        findings[0].details["manager_version"] = manager_ver
        findings += cve_findings("ComfyUI-Manager", manager_ver, "http://TARGET:8188/")
    return findings
