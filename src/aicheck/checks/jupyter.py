"""Jupyter :8888 — notebook server exposed.

Two states:
1. /api/status or /api/kernels answering 200 without a token means FULL
   unauthenticated access: anyone can open a terminal and run code as your
   user. That is RCE, not a leak. CRITICAL.
2. Only the login page reachable is still an exposed notebook server,
   brute-forceable and often protected by a weak password. MEDIUM.
Fingerprint by Jupyter markers in the page or the API JSON.

Auth-walled (observation, INFO — never graded): a Jupyter probe answering
401/403 whose own body or Server header names Jupyter (e.g. an auth proxy
in front). A bare 403 on :8888 is NOT evidence.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .auth_wall import observation, walled_and_marked

CHECK_ID = "jupyter"
FIX_CARD_ID = "jupyter-exposed"


def _walled_observation(probes) -> list[Finding]:
    hit = walled_and_marked(probes, "jupyter")
    if hit is None:
        return []
    return [
        observation(
            check_id=CHECK_ID,
            product="Jupyter",
            title="Jupyter notebook server present but auth-walled",
            url="http://TARGET:8888/",
            evidence=(
                f"GET {hit.url} → {hit.status_code} — the walled response itself "
                "carries a Jupyter marker; the server is present but demands "
                "authentication (present, not graded)"
            ),
            fix_card_id=FIX_CARD_ID,
        )
    ]


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("8888:/")
    status = facts.get("8888:/api/status")
    kernels = facts.get("8888:/api/kernels")

    root_jupyter = root is not None and root.ok and "jupyter" in root.body.lower()
    status_j = status.json() if status is not None and status.ok else None
    kernels_j = kernels.json() if kernels is not None and kernels.ok else None

    # Shape-check: real Jupyter /api/status has connections+kernels keys;
    # other products (e.g. Ollama) also serve JSON on /api/status.
    status_hit = isinstance(status_j, dict) and "kernels" in status_j and "connections" in status_j
    kernels_hit = (
        isinstance(kernels_j, list)
        and bool(kernels_j)
        and all(isinstance(k, dict) and "id" in k and "name" in k for k in kernels_j)
    )
    open_api = status_hit or kernels_hit
    if open_api:
        evidence_bits = []
        if isinstance(status_j, dict):
            evidence_bits.append(f"GET {status.url} → 200")
        if isinstance(kernels_j, list):
            evidence_bits.append(f"GET {kernels.url} → 200 ({len(kernels_j)} kernel(s) listed)")
        return [
            Finding(
                check_id=CHECK_ID,
                product="Jupyter",
                title="Jupyter notebook server open without authentication — remote code execution",
                severity="CRITICAL",
                url="http://TARGET:8888/",
                evidence=(
                    "; ".join(evidence_bits)
                    + " without a token. Anyone can open a terminal and run code as your user"
                ),
                fix_card_id=FIX_CARD_ID,
                details={"kernels": len(kernels_j) if isinstance(kernels_j, list) else None},
            )
        ]

    if root_jupyter:
        return [
            Finding(
                check_id=CHECK_ID,
                product="Jupyter",
                title="Jupyter login page exposed to the internet",
                severity="MEDIUM",
                url="http://TARGET:8888/",
                evidence=(
                    f"GET {root.url} → 200 (Jupyter login page) — reachable for password "
                    "guessing; most real-world Jupyter compromises are weak passwords"
                ),
                fix_card_id=FIX_CARD_ID,
                details={},
            )
        ]
    return _walled_observation((root, status, kernels))
