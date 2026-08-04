"""SARIF 2.1.0 output for the CI action (python -m aicheck.scan --format sarif).

One rule per check_id; one result per finding. Severity maps to SARIF levels:
CRITICAL → error, HIGH → warning, MEDIUM → note. Every rule links the fix
card (helpUri) — the annotation in the PR points straight at the remediation
guidance on unauth.dev. GitHub code scanning consumes this via
github/codeql-action/upload-sarif.

Observations (fingerprinted-but-auth-walled, severity INFO) map to note-level
results under a separate `<check_id>-observed` rule id — visible in the code
scanning UI, but structurally distinct from exposure rules and never at a
level that gates a build.
"""

from __future__ import annotations

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"CRITICAL": "error", "HIGH": "warning", "MEDIUM": "note", "INFO": "note"}
BASE_URL = "https://unauth.dev"


def to_sarif(target: str, grade: str, findings: list[dict], version: str = "0.1.0",
             coverage: dict | None = None, observations: list[dict] | None = None) -> dict:
    rules = {}
    for f in findings:
        cid = f["check_id"]
        if cid not in rules:
            rules[cid] = {
                "id": cid,
                "name": f["product"],
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f.get("evidence") or f["title"]},
                "helpUri": f"{BASE_URL}/fixes/{f['fix_card_id']}",
                "properties": {"severity": f["severity"], "product": f["product"]},
            }
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
    for o in observations or []:
        rid = f"{o['check_id']}-observed"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f"{o['product']} (auth-walled)",
                "shortDescription": {"text": o["title"]},
                "fullDescription": {"text": o.get("evidence") or o["title"]},
                "helpUri": f"{BASE_URL}/fixes/{o['fix_card_id']}",
                "properties": {"severity": "INFO", "product": o["product"],
                               "auth": "present"},
            }
        msg = f"INFO: {o['title']} — {o.get('evidence', '')}".strip(" —")
        results.append({
            "ruleId": rid,
            "level": "note",
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": o["url"]},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": o["product"], "kind": "service"}],
            }],
        })
    properties = {"target": target, "grade": grade}
    if coverage is not None:
        properties["coverage"] = coverage
    if observations:
        properties["observation_count"] = len(observations)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aicheck",
                    "version": version,
                    "informationUri": BASE_URL,
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "properties": properties,
        }],
    }
