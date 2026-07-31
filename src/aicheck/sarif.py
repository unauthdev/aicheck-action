"""SARIF 2.1.0 output for the CI action (python -m aicheck.scan --format sarif).

One rule per check_id; one result per finding. Severity maps to SARIF levels:
CRITICAL → error, HIGH → warning, MEDIUM → note. Every rule links the fix
card (helpUri) — the annotation in the PR points straight at the remediation
guidance on unauth.dev. GitHub code scanning consumes this via
github/codeql-action/upload-sarif.
"""

from __future__ import annotations

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"CRITICAL": "error", "HIGH": "warning", "MEDIUM": "note"}
# Numeric severity: GitHub orders results by it; GitLab needs it to render
# CRITICAL as Critical (its level mapping alone caps at High).
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0"}
BASE_URL = "https://unauth.dev"


def _rule(f: dict) -> dict:
    props = {
        "severity": f["severity"],
        "product": f["product"],
        "security-severity": SECURITY_SEVERITY.get(f["severity"], "5.0"),
    }
    cid = f["check_id"]
    if cid.startswith("cve-"):
        # GitLab's dependency-scanning typer matches rule.properties.tags[]
        # against the cve-YYYY-N pattern (lowercase) — the ruleId pattern it
        # checks is uppercase, so the tags carry the typing.
        props["tags"] = [cid, f["product"].lower()]
    return {
        "id": cid,
        "name": f["product"],
        "shortDescription": {"text": f["title"]},
        "fullDescription": {"text": f.get("evidence") or f["title"]},
        "helpUri": f"{BASE_URL}/fixes/{f['fix_card_id']}",
        "properties": props,
    }


def to_sarif(target: str, grade: str, findings: list[dict], version: str | None = None) -> dict:
    if version is None:
        from . import __version__  # local import: no circulars at module load
        version = __version__
    rules = {}
    for f in findings:
        cid = f["check_id"]
        if cid not in rules:
            rules[cid] = _rule(f)
    results = []
    for f in findings:
        msg = f"{f['severity']}: {f['title']} — {f.get('evidence', '')}".strip(" —")
        results.append({
            "ruleId": f["check_id"],
            "level": LEVEL.get(f["severity"], "note"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["url"]},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f["product"], "kind": "service"}],
            }],
        })
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aicheck",
                    "version": version,
                    "semanticVersion": version,
                    "informationUri": BASE_URL,
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "properties": {"target": target, "grade": grade},
        }],
    }
