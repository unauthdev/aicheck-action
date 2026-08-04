"""Scoring: checker orchestration + grading. Pure and dependency-free (no DB,
no notify) — this module is the shareable core of the engine.

Severity model (SPEC): CRITICAL = unauth write/exec, HIGH = unauth read,
MEDIUM = version/info leak. Grade: any CRITICAL → F, any HIGH → D,
any MEDIUM → C, clean → A.
"""

from __future__ import annotations

from .checks import ALL_CHECKERS
from .models import Finding

_GRADE_BY_SEVERITY = {"CRITICAL": "F", "HIGH": "D", "MEDIUM": "C"}
_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}


def grade(findings: list[Finding]) -> str:
    worst = "A"
    worst_rank = 0
    for f in findings:
        rank = _SEVERITY_RANK.get(f.severity, 0)
        if rank > worst_rank:
            worst_rank = rank
            worst = _GRADE_BY_SEVERITY[f.severity]
    return worst


def run_checkers(facts: dict, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for checker in ALL_CHECKERS:
        try:
            findings.extend(checker.detect(facts))
        except Exception:
            continue  # one broken checker must never kill a scan
    # Annotation only — never touches severity / grade inputs.
    from .checks.vuln_lookup import annotate_known_cves
    try:
        annotate_known_cves(findings)
    except Exception:
        pass  # a broken CVE annotation must never kill a scan
    for f in findings:  # checkers emit TARGET placeholder; bind real target here
        f.url = f.url.replace("TARGET", target)
    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f.severity, 0))
    return findings
