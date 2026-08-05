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
from ..recon import DATA_PLANE_PORTS
from .risk_classes import AGENT_MEMORY, with_risk

CHECK_ID = "weaviate"
FIX_CARD_ID = "weaviate-exposed"

# Class B data-plane pack (docs/deep-pack-data-plane.md): separate finding,
# gated on the Class A fingerprint AND a zero-byte TCP accept on the gRPC
# data-plane port. recon.DATA_PLANE_PORTS owns the probe topology.
DATA_PLANE_CHECK_ID = "weaviate-dataplane"
DATA_PLANE_FIX_CARD_ID = "weaviate-dataplane-exposed"
DATA_PLANE_PORT = next(p for p, name in DATA_PLANE_PORTS.items() if name == "weaviate")


def _product_fingerprinted(facts: dict[str, ProbeResult]) -> bool:
    """Class A leg of the data-plane conjunction: /v1/meta answered the full
    Weaviate meta shape (hostname + version + modules together) — the same
    conjunction detect() requires on this shared port."""
    meta = facts.get("8080:/v1/meta")
    meta_j = meta.json() if meta is not None and meta.ok else None
    return (
        isinstance(meta_j, dict)
        and "hostname" in meta_j
        and "version" in meta_j
        and "modules" in meta_j
    )


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    meta = facts.get("8080:/v1/meta")
    schema = facts.get("8080:/v1/schema")

    meta_j = meta.json() if meta is not None and meta.ok else None
    # Real /v1/meta: {"hostname": ..., "version": ..., "modules": {...}} —
    # one fingerprint rule, shared with the data-plane conjunction leg.
    meta_hit = _product_fingerprinted(facts)
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


def detect_with_connects(
    facts: dict[str, ProbeResult], connects: dict[int, str]
) -> list[Finding]:
    """Class B entrypoint (data-plane pack): detect(facts) plus a SEPARATE
    data-plane finding when the conjunction holds — Weaviate identified by
    Class A on this host AND the gRPC port accepted a zero-byte connect.

    Evidence doctrine: the finding claims reachability ONLY ("accepts
    connections from the prober's position"). Connect-only cannot know
    whether gRPC auth/TLS is required or vector data is readable, so the
    evidence never claims either — CRITICAL stays reserved for proven
    unauthenticated data access, which this probe can never prove."""
    findings = detect(facts)
    if _product_fingerprinted(facts) and connects.get(DATA_PLANE_PORT) == "accepted":
        findings.append(
            Finding(
                check_id=DATA_PLANE_CHECK_ID,
                product="Weaviate",
                title="Weaviate gRPC data plane (:50051) accepts connections",
                severity="HIGH",
                url="tcp://TARGET:50051/",
                evidence=(
                    "TCP connect accepted — 0 bytes sent to the Weaviate gRPC "
                    "data plane (:50051), and the same host was fingerprinted "
                    "as Weaviate by the Class A HTTP probes (:8080 /v1/meta) — "
                    "the data plane accepts connections from the prober's "
                    "position. Reachability only: connect-only cannot tell "
                    "whether gRPC auth or TLS is required or whether vector "
                    "data is readable"
                ),
                fix_card_id=DATA_PLANE_FIX_CARD_ID,
                details=with_risk(
                    {"data_plane_port": DATA_PLANE_PORT, "method": "tcp-connect-0-bytes"},
                    AGENT_MEMORY,
                ),
            )
        )
    return findings
