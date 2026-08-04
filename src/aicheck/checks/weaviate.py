"""Weaviate :8080 — vector database exposed.

Shares :8080 with Open WebUI: fingerprint strictly by content. GET /v1/meta
must answer the full Weaviate meta shape — hostname + version + modules
together (modules is Weaviate's distinctive key; version+modules alone is
too thin for a shared port). GET /v1/schema answering 200 means the schema
(and effectively the data plane) is open to anyone.

Finding class: agent-memory (OWASP ASI06) — grades unchanged vs prior severity.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .risk_classes import AGENT_MEMORY, with_risk

CHECK_ID = "weaviate"
FIX_CARD_ID = "weaviate-exposed"


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    meta = facts.get("8080:/v1/meta")
    schema = facts.get("8080:/v1/schema")

    meta_j = meta.json() if meta is not None and meta.ok else None
    # Real /v1/meta: {"hostname": ..., "version": ..., "modules": {...}}.
    # Require the full conjunction — version+modules alone is too generic.
    meta_hit = (
        isinstance(meta_j, dict)
        and "hostname" in meta_j
        and "version" in meta_j
        and "modules" in meta_j
    )
    if not meta_hit:
        return []

    version = str(meta_j.get("version", ""))
    version_bit = f"; version {version}" if version else ""

    schema_j = schema.json() if schema is not None and schema.ok else None
    if isinstance(schema_j, dict) and "classes" in schema_j:
        raw_classes = schema_j.get("classes")
        if not isinstance(raw_classes, list):
            raw_classes = []
        classes = [
            str(c.get("class", "?")) if isinstance(c, dict) else str(c)
            for c in raw_classes[:5]
        ]
        class_bit = f"; {len(raw_classes)} class(es) readable ({', '.join(classes)})" if classes else "; schema readable"
        return [
            Finding(
                check_id=CHECK_ID,
                product="Weaviate",
                title="Weaviate vector database open without authentication",
                severity="CRITICAL",
                url="http://TARGET:8080/",
                evidence=(
                    f"GET {meta.url} → 200{version_bit}; GET {schema.url} → 200{class_bit} — "
                    "no auth required. Anyone can read, poison, or delete your vectors "
                    "(this store may hold agent memory — see OWASP ASI06 memory poisoning)"
                ),
                fix_card_id=FIX_CARD_ID,
                details=with_risk({"version": version, "classes": classes}, AGENT_MEMORY),
            )
        ]
    return [
        Finding(
            check_id=CHECK_ID,
            product="Weaviate",
            title="Weaviate instance exposed to the internet",
            severity="HIGH",
            url="http://TARGET:8080/",
            evidence=(
                f"GET {meta.url} → 200{version_bit} — Weaviate meta answers anyone; "
                "vector stores like this often hold agent memory (OWASP ASI06)"
            ),
            fix_card_id=FIX_CARD_ID,
            details=with_risk({"version": version}, AGENT_MEMORY),
        )
    ]
