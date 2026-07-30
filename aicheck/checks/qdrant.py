"""Qdrant :6333 — vector database exposed without authentication.

Fingerprint: GET / returns Qdrant's own JSON banner
{"title": "qdrant - vector search engine", "version": ...}. That same banner
leaks the exact version. If GET /collections answers 200 with the collection
list, the database is fully open: anyone can read, modify or delete every
stored embedding (which often contains raw document text from your RAG app).
Qdrant ships with NO authentication by default — exposure is a config choice
the docs warn about, not a bug.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

CHECK_ID = "qdrant"
FIX_CARD_ID = "qdrant-exposed"


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    root = facts.get("6333:/")
    collections = facts.get("6333:/collections")

    root_j = root.json() if root is not None and root.ok else None
    fingerprinted = isinstance(root_j, dict) and "qdrant" in str(root_j.get("title", "")).lower()
    if not fingerprinted:
        return []

    version = str(root_j.get("version", ""))
    version_bit = f"; version {version}" if version else ""

    cols_j = collections.json() if collections is not None and collections.ok else None
    col_names: list[str] = []
    if isinstance(cols_j, dict):
        try:
            col_names = [c.get("name", "?") for c in cols_j["result"]["collections"]][:5]
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
            "no API key required. Anyone can read or delete every embedding you stored"
        )
    else:
        severity = "HIGH"
        title = "Qdrant instance exposed to the internet"
        evidence = f"GET {root.url} → 200{version_bit} — Qdrant banner answers anyone"

    return [
        Finding(
            check_id=CHECK_ID,
            product="Qdrant",
            title=title,
            severity=severity,
            url="http://TARGET:6333/",
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details={"version": version, "collections": col_names},
        )
    ]
