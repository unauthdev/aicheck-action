"""Ray dashboard :8265 — unauthenticated dashboard / Jobs API.

Fingerprint (content-based): GET /api/version returns Ray's version JSON, or
GET / serves the Ray Dashboard HTML. Exposure is only reported when an
unauthenticated API also answers data — GET /api/jobs/ (job list) or
GET /nodes (cluster nodes). An open Ray Jobs API is unauthenticated remote
code execution: anyone can submit a job that runs arbitrary code on the
cluster → CRITICAL.
"""

from __future__ import annotations

import re

from ..models import Finding, ProbeResult

CHECK_ID = "ray"
FIX_CARD_ID = "ray-exposed"

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _version_from(probe: ProbeResult | None) -> str:
    """Ray /api/version: JSON (flat or under "data") or a bare version string."""
    if probe is None or not probe.ok:
        return ""
    j = probe.json()
    if isinstance(j, dict):
        for container in (j, j.get("data") if isinstance(j.get("data"), dict) else {}):
            for key in ("version", "ray_version"):
                if isinstance(container.get(key), str) and _VERSION_RE.search(container[key]):
                    return container[key]
        return ""
    m = _VERSION_RE.fullmatch(probe.body.strip().lstrip("v"))
    return m.group(0) if m else ""


def _has_data(probe: ProbeResult | None) -> bool:
    """True when an API endpoint answered 200 with an actual JSON payload."""
    if probe is None or not probe.ok:
        return False
    j = probe.json()
    if isinstance(j, (list, dict)) and j:
        return True
    return False


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("8265:/")
    version = facts.get("8265:/api/version")
    jobs = facts.get("8265:/api/jobs/")
    nodes = facts.get("8265:/nodes")

    ver_str = _version_from(version)
    dashboard_html = root is not None and root.ok and "ray dashboard" in root.body.lower()
    fingerprinted = bool(ver_str) or dashboard_html
    if not fingerprinted:
        return []

    jobs_open = _has_data(jobs)
    nodes_open = _has_data(nodes)
    if not (jobs_open or nodes_open):
        return []  # fingerprinted but APIs demand auth / return nothing

    version_bit = f"version {ver_str}; " if ver_str else ""
    open_bits = []
    if jobs_open:
        open_bits.append(f"GET {jobs.url} → 200 (job list returned without credentials)")
    if nodes_open:
        open_bits.append(f"GET {nodes.url} → 200 (cluster node data returned without credentials)")

    return [
        Finding(
            check_id=CHECK_ID,
            product="Ray",
            title="Ray dashboard exposed — unauthenticated RCE via job submission",
            severity="CRITICAL",
            url=f"http://TARGET:8265/",
            evidence=(
                f"{version_bit}" + "; ".join(open_bits)
                + "; the Ray Jobs API accepts job submissions without authentication, "
                "and a submitted job runs arbitrary code on the cluster"
            ),
            fix_card_id=FIX_CARD_ID,
            details={
                "version": ver_str,
                "jobs_api_open": jobs_open,
                "nodes_api_open": nodes_open,
            },
        )
    ]
