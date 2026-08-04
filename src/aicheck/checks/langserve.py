"""LangServe — exposed LangChain runnable HTTP API.

LangServe wraps LCEL/agent chains in FastAPI with /invoke, /stream, and a
/playground/ UI. Defaults ship without auth. An open playground is remote
prompt execution against your models and tools.

Fingerprint (GET-only):
- GET /openapi.json mentions langserve, or lists /playground/ + /invoke paths
- GET /docs HTML mentions langserve / playground
Common ports: 8000, 8080 (+ 443 via shared alias).
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .risk_classes import AGENT_RUNTIME, with_risk

CHECK_ID = "langserve"
FIX_CARD_ID = "langserve-exposed"

_PORTS = ("8000", "8080", "443")


def _openapi_hit(p: ProbeResult | None) -> tuple[bool, bool]:
    """Return (is_langserve, has_invoke_surface)."""
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False, False
    body = p.body.lower()
    data = p.json()
    paths: list[str] = []
    if isinstance(data, dict) and isinstance(data.get("paths"), dict):
        paths = [str(k).lower() for k in data["paths"]]
    joined = " ".join(paths)
    named = "langserve" in body or "langserve" in str(
        (data or {}).get("info", {}) if isinstance(data, dict) else ""
    ).lower()
    surface = (
        "/playground" in joined
        and ("/invoke" in joined or "/stream" in joined or "/batch" in joined)
    )
    return (named or surface), surface


def _docs_hit(p: ProbeResult | None) -> bool:
    if p is None or p.status_code in (401, 403) or not p.ok:
        return False
    body = p.body.lower()
    return "langserve" in body or ("playground" in body and "swagger" in body and "invoke" in body)


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    for port in _PORTS:
        openapi = facts.get(f"{port}:/openapi.json")
        docs = facts.get(f"{port}:/docs")
        is_ls, has_surface = _openapi_hit(openapi)
        docs_ls = _docs_hit(docs)
        if not (is_ls or docs_ls):
            continue

        probe = openapi if (openapi is not None and openapi.ok and is_ls) else docs
        assert probe is not None
        if has_surface or (docs_ls and "playground" in (docs.body.lower() if docs else "")):
            severity = "CRITICAL"
            title = "LangServe chain API exposed without authentication"
            evidence = (
                f"GET {probe.url} → {probe.status_code} — LangServe /invoke and "
                "/playground surface answer strangers; anyone can run your chain"
            )
        else:
            severity = "HIGH"
            title = "LangServe instance exposed to the internet"
            evidence = (
                f"GET {probe.url} → {probe.status_code} — LangServe API docs/schema "
                "are public (auth not required)"
            )
        return [
            Finding(
                check_id=CHECK_ID,
                product="LangServe",
                title=title,
                severity=severity,
                url=probe.url,
                evidence=evidence,
                fix_card_id=FIX_CARD_ID,
                details=with_risk(
                    {"port": port, "auth": "none", "invoke_surface": has_surface},
                    AGENT_RUNTIME,
                ),
            )
        ]
    return []
