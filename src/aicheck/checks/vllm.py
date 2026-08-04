"""vLLM :8000 — unauthenticated OpenAI-compatible API.

Fingerprint (content-based, :8000 is shared): GET /version returns
{"version": ...} AND GET /v1/models returns an OpenAI-style model list.
Both must match to avoid false positives on other :8000 services.
Unauthenticated inference + model list readable → HIGH.

Auth-walled (observation, INFO — never graded): BOTH canonical endpoints
answer 401/403 AND at least one carries product-class evidence — a "vllm"
marker (body/Server) or an OpenAI-style error envelope ({"error": {...}}),
which is how vLLM answers a missing/invalid API key. A bare 401 on :8000
(or a proxy HTML wall) is NOT evidence.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .auth_wall import mentions, observation, walled
from .cvemap import cve_findings

CHECK_ID = "vllm"
FIX_CARD_ID = "vllm-exposed"


def _openai_error_envelope(p: ProbeResult | None) -> bool:
    """vLLM's auth wall speaks the OpenAI error shape: a JSON object whose
    "error" value is itself an object. FastAPI's generic {"detail": ...}
    does NOT count — any FastAPI app with global auth emits that."""
    j = p.json() if p is not None else None
    return isinstance(j, dict) and isinstance(j.get("error"), dict)


def _walled_observation(models, version) -> list[Finding]:
    if not (walled(models) and walled(version)):
        return []
    marked = any(mentions(p, "vllm") for p in (models, version))
    envelope = any(_openai_error_envelope(p) for p in (models, version))
    if not (marked or envelope):
        return []
    hit = models if walled(models) else version
    return [
        observation(
            check_id=CHECK_ID,
            product="vLLM",
            title="vLLM OpenAI-compatible API present but auth-walled",
            url="http://TARGET:8000/v1/models",
            evidence=(
                f"GET {models.url} → {models.status_code}; "
                f"GET {version.url} → {version.status_code} — both canonical "
                "endpoints demand auth and the wall carries vLLM/OpenAI-style "
                "markers (present, not graded)"
            ),
            fix_card_id=FIX_CARD_ID,
        )
    ]


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
        return _walled_observation(models, version)

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
