"""Stable finding IDs and buyer-facing enrichment for local inventory runs.

IDs are deterministic across runs so drift (new / fixed / still_open) works
without a central server. Enrichment surfaces version, CVE, and risk-class
fields already produced by checkers — it does not change severity or grade.
"""

from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlparse


def finding_id(host: str, finding: dict[str, Any]) -> str:
    """Stable id: check_id + host + url shape (scheme/host/port/path)."""
    host_n = (host or "").strip().lower().rstrip(".")
    check = str(finding.get("check_id") or "").strip().lower()
    url = str(finding.get("url") or "")
    parsed = urlparse(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/"
    material = f"{check}|{host_n}|{parsed.scheme}|{port}|{path}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def enrich_finding(
    finding: dict[str, Any],
    *,
    host: str,
    owner: str | None = None,
    env: str | None = None,
) -> dict[str, Any]:
    """Return a SIEM/ticket-friendly finding dict (does not mutate input)."""
    details = dict(finding.get("details") or {})
    fix_card = finding.get("fix_card_id") or ""
    cve = details.get("cve")
    cves: list[str] = []
    if cve:
        cves.append(str(cve).upper())
    worst = details.get("known_cve_worst")
    if worst and str(worst).upper() not in cves:
        cves.append(str(worst).upper())

    how = (
        "Live GET-only metadata probe; content fingerprint matched. "
        "No login, POST, exploit verification, or model pull."
    )
    if details.get("version"):
        how += f" Version reported by target: {details['version']}."
    if cves:
        how += f" Correlated CVE(s): {', '.join(cves)}."
    if details.get("risk_class") == "agent-memory":
        how += (
            " Data-sensitivity: vector/memory store may hold embeddings or "
            "agent state (OWASP ASI06)."
        )
    elif details.get("risk_class") == "agent-traces":
        how += " Data-sensitivity: traces may retain prompts and session state."
    elif details.get("risk_class") == "agent-runtime":
        how += " Runtime may allow unauthenticated chain/chatflow invocation."

    fid = finding_id(host, finding)
    title = finding.get("title")
    severity = finding.get("severity")
    product = finding.get("product")
    version = details.get("version") or None
    fix_url = f"https://unauth.dev/fixes/{fix_card}" if fix_card else None

    # Ticket / SIEM aliases — same values, names teams already map in workflows.
    description_parts = [
        str(title or ""),
        f"Asset: {host}",
        f"Product: {product}" + (f" {version}" if version else ""),
        f"Evidence: {finding.get('evidence') or ''}",
        f"How produced: {how}",
    ]
    if owner:
        description_parts.append(f"Owner: {owner}")
    if env:
        description_parts.append(f"Environment: {env}")
    if cves:
        description_parts.append(f"CVEs: {', '.join(cves)}")
    if fix_url:
        description_parts.append(f"Remediation: {fix_url}")

    out: dict[str, Any] = {
        "finding_id": fid,
        "id": fid,
        "check_id": finding.get("check_id"),
        "product": product,
        "title": title,
        "severity": severity,
        "host": host,
        "asset": host,
        "url": finding.get("url"),
        "evidence": finding.get("evidence"),
        "how_produced": how,
        "description": "\n".join(description_parts),
        "fix_card_id": fix_card,
        "fix_url": fix_url,
        "references": [u for u in (fix_url, details.get("reference_url")) if u],
        "owner": owner,
        "env": env,
        "environment": env,
        "version": version,
        "cves": cves,
        "risk_class": details.get("risk_class"),
        "tool": "aicheck-inventory",
        "status": "open",
        "details": details,
    }
    return out
