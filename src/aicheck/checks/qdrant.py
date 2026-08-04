"""Qdrant :6333 — vector database exposed without authentication.

Fingerprint: GET / returns Qdrant's own JSON banner
{"title": "qdrant - vector search engine", "version": ...}. That same banner
leaks the exact version. If GET /collections answers 200 with the collection
list, the database is fully open: anyone can read, modify or delete every
stored embedding (which often contains raw document text from your RAG app).
Qdrant ships with NO authentication by default — exposure is a config choice
the docs warn about, not a bug.

Finding class: agent-memory (OWASP ASI06) — grades unchanged vs prior severity.

Auth-walled (observation, INFO — never graded): a Qdrant probe answering
401/403 whose own body or Server header names Qdrant (API key configured).
A bare 401 on :6333 is NOT evidence.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .auth_wall import observation, walled_and_marked
from .risk_classes import AGENT_MEMORY, with_risk

CHECK_ID = "qdrant"
FIX_CARD_ID = "qdrant-exposed"


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("6333:/")
    collections = facts.get("6333:/collections")

    root_j = root.json() if root is not None and root.ok else None
    fingerprinted = isinstance(root_j, dict) and "qdrant" in str(root_j.get("title", "")).lower()
    if not fingerprinted:
        hit = walled_and_marked((root, collections), "qdrant")
        if hit is None:
            return []
        return [
            observation(
                check_id=CHECK_ID,
                product="Qdrant",
                title="Qdrant vector database present but auth-walled",
                url="http://TARGET:6333/",
                evidence=(
                    f"GET {hit.url} → {hit.status_code} — the walled response itself "
                    "carries a Qdrant marker; the database is present but demands "
                    "an API key (present, not graded)"
                ),
                fix_card_id=FIX_CARD_ID,
            )
        ]

    version = str(root_j.get("version", ""))
    version_bit = f"; version {version}" if version else ""

    cols_j = collections.json() if collections is not None and collections.ok else None
    col_names: list[str] = []
    if isinstance(cols_j, dict):
        try:
            col_names = [
                c.get("name", "?")
                for c in cols_j["result"]["collections"]
                if isinstance(c, dict)
            ][:5]
        except (KeyError, TypeError):
            col_names = []

    if isinstance(cols_j, dict) and col_names is not None and "result" in cols_j:
        severity = "CRITICAL"
        title = "Qdrant vector database open without authentication"
        col_bit = (
            f"; {len(col_names)} collection(s) readable ({', '.join(col_names)})"
            if col_names
            else "; collection list readable"
        )
        evidence = (
            f"GET {root.url} → 200{version_bit}; GET {collections.url} → 200{col_bit} — "
            "no API key required. Anyone can read, poison, or delete every embedding "
            "(this store may hold agent memory — see OWASP ASI06 memory poisoning)"
        )
    else:
        severity = "HIGH"
        title = "Qdrant instance exposed to the internet"
        evidence = (
            f"GET {root.url} → 200{version_bit} — Qdrant banner answers anyone; "
            "vector stores like this often hold agent memory (OWASP ASI06)"
        )

    return [
        Finding(
            check_id=CHECK_ID,
            product="Qdrant",
            title=title,
            severity=severity,
            url="http://TARGET:6333/",
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details=with_risk({"version": version, "collections": col_names}, AGENT_MEMORY),
        )
    ]
