"""Ollama :11434 — unauthenticated API.

Fingerprint (content-based): GET / returns "Ollama is running", or
GET /api/version returns {"version": ...}. If the API answers without auth,
pull/push/delete endpoints are open too → CRITICAL.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .cvemap import cve_findings

CHECK_ID = "ollama"
FIX_CARD_ID = "ollama-exposed"
MAX_MODEL_NAMES = 5


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("11434:/")
    version = facts.get("11434:/api/version")
    tags = facts.get("11434:/api/tags")

    fingerprinted = (root is not None and root.ok and "ollama is running" in root.body.lower()) or (
        version is not None and version.ok and isinstance(version.json(), dict) and "version" in version.json()
    )
    if not fingerprinted:
        return []

    ver_str = ""
    if version is not None and version.ok and isinstance(version.json(), dict):
        ver_str = str(version.json().get("version", ""))

    tags_j = tags.json() if tags is not None and tags.ok else None
    models_readable = isinstance(tags_j, dict) and "models" in tags_j
    model_entries = tags_j.get("models", []) if models_readable else []
    model_names = [
        str(m["name"]) for m in model_entries if isinstance(m, dict) and m.get("name")
    ][:MAX_MODEL_NAMES]

    evidence_bits = [f"GET {version.url if version else ''} → 200"]
    if ver_str:
        evidence_bits.append(f"version {ver_str}")
    if models_readable:
        count = len(model_entries)
        if model_names:
            evidence_bits.append(
                f"we can see your {count} model(s): {', '.join(model_names)}"
                + ("…" if count > MAX_MODEL_NAMES else "")
                + " — anyone can use or delete them"
            )
        else:
            evidence_bits.append("/api/tags readable (no models pulled yet — but pull/delete is open to anyone)")

    findings = [
        Finding(
            check_id=CHECK_ID,
            product="Ollama",
            title="Ollama API exposed without authentication",
            severity="CRITICAL",
            url=f"http://TARGET:11434/",
            evidence="; ".join(evidence_bits),
            fix_card_id=FIX_CARD_ID,
            details={"version": ver_str, "model_count": len(model_entries), "models": model_names},
        )
    ]
    if ver_str:
        findings += cve_findings("Ollama", ver_str, "http://TARGET:11434/")
    return findings
