"""Generic OpenAI-compatible /v1/models surface.

Catches anonymous model-list APIs that are not already claimed by a product
checker (vLLM needs /version too; Ollama/LiteLLM/LM Studio have their own
paths). Includes OpenRouter-shaped model ids when present.

Fingerprint (GET-only):
- GET /v1/models → {"object":"list","data":[{"id":...}, ...]}
- Exclude when the same port clearly fingerprints as vLLM (/version match),
  LiteLLM (body/title), LM Studio greeting, or OpenHands server info
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

CHECK_ID = "openai-compat"
FIX_CARD_ID = "openai-compat-exposed"

# Ports we already probe for /v1/models (recon) plus common proxy ports.
_PORTS = ("8000", "8080", "4000", "5000", "3000", "1234", "443")


def _openai_models(p: ProbeResult | None) -> tuple[bool, list[str]]:
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False, []
    data = p.json()
    if not isinstance(data, dict):
        return False, []
    if data.get("object") != "list" or not isinstance(data.get("data"), list):
        return False, []
    ids: list[str] = []
    for m in data["data"]:
        if not isinstance(m, dict) or "id" not in m:
            return False, []
        ids.append(str(m["id"]))
    return True, ids[:8]


def _claimed_by_primary(facts: dict[str, ProbeResult], port: str) -> bool:
    """Skip when a more specific product fingerprint owns this port."""
    version = facts.get(f"{port}:/version")
    if version is not None and version.ok:
        vj = version.json()
        if isinstance(vj, dict) and "version" in vj and port == "8000":
            # vLLM dual-probe; leave that checker to fire
            models = facts.get(f"{port}:/v1/models")
            ok, _ = _openai_models(models)
            if ok:
                return True

    for path in ("/", "/health", "/health/readiness", "/openapi.json"):
        p = facts.get(f"{port}:{path}")
        if p is None or not p.ok:
            continue
        low = p.body.lower()
        if "litellm" in low:
            return True

    greet = facts.get(f"{port}:/lmstudio-greeting")
    if greet is not None and greet.ok and "lm studio" in greet.body.lower():
        return True

    for path in ("/", "/server_info"):
        p = facts.get(f"{port}:{path}")
        if p is None or not p.ok:
            continue
        data = p.json() if p.body.strip().startswith("{") else None
        if isinstance(data, dict) and (
            str(data.get("title") or "") == "OpenHands Agent Server"
            or "openhands" in str(data).lower()
        ):
            return True
        if "openhands" in p.body.lower():
            return True
    return False


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    for port in _PORTS:
        models = facts.get(f"{port}:/v1/models")
        ok, ids = _openai_models(models)
        if not ok:
            continue
        if _claimed_by_primary(facts, port):
            continue
        assert models is not None
        openrouter = any(
            "openrouter" in i.lower() or i.lower().startswith("openrouter/")
            for i in ids
        )
        product = "OpenRouter proxy" if openrouter else "OpenAI-compatible API"
        title = (
            "OpenRouter-shaped OpenAI-compatible API exposed without authentication"
            if openrouter
            else "OpenAI-compatible API exposed without authentication"
        )
        id_bit = ", ".join(ids) if ids else "none listed"
        return [
            Finding(
                check_id=CHECK_ID,
                product=product,
                title=title,
                severity="HIGH",
                url=models.url,
                evidence=(
                    f"GET {models.url} → {models.status_code} — OpenAI-style "
                    f"model list readable without auth (models: {id_bit}); "
                    "strangers can inventory models and usually burn inference"
                ),
                fix_card_id=FIX_CARD_ID,
                details={
                    "port": port,
                    "models": ids,
                    "openrouter": openrouter,
                },
            )
        ]
    return []
