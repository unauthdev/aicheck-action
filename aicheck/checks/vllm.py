"""vLLM :8000 — unauthenticated OpenAI-compatible API.

Fingerprint (content-based, :8000 is shared): GET /version returns
{"version": ...} AND GET /v1/models returns an OpenAI-style model list.
Both must match to avoid false positives on other :8000 services.
Unauthenticated inference + model list readable → HIGH.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .cvemap import cve_findings

CHECK_ID = "vllm"
FIX_CARD_ID = "vllm-exposed"


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    models = facts.get("8000:/v1/models")
    version = facts.get("8000:/version")

    models_j = models.json() if models is not None and models.ok else None
    version_j = version.json() if version is not None and version.ok else None

    models_match = (
        isinstance(models_j, dict)
        and models_j.get("object") == "list"
        and isinstance(models_j.get("data"), list)
        and all(isinstance(m, dict) and "id" in m for m in models_j["data"])
    )
    version_match = isinstance(version_j, dict) and "version" in version_j
    if not (models_match and version_match):
        return []

    ver_str = str(version_j.get("version", ""))
    model_ids = [str(m["id"]) for m in models_j["data"]][:5]
    evidence = (
        f"GET {version.url} → 200 (version {ver_str}); "
        f"GET {models.url} → 200 (models: {', '.join(model_ids) or 'none listed'} "
        "— anyone can run inference on your GPU)"
    )

    findings = [
        Finding(
            check_id=CHECK_ID,
            product="vLLM",
            title="vLLM OpenAI-compatible API exposed without authentication",
            severity="HIGH",
            url=f"http://TARGET:8000/v1/models",
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details={"version": ver_str, "models": model_ids},
        )
    ]
    if ver_str:
        findings += cve_findings("vLLM", ver_str, "http://TARGET:8000/v1/models")
    return findings
