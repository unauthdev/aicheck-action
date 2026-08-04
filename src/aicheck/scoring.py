"""Scoring: checker orchestration + grading. Pure and dependency-free (no DB,
no notify) — this module is the shareable core of the engine.

Severity model (SPEC): CRITICAL = unauth write/exec, HIGH = unauth read,
MEDIUM = version/info leak. Grade: any CRITICAL → F, any HIGH → D,
any MEDIUM → C, clean → A. INFO is the non-grading observation level
(auth-walled-but-fingerprinted) — run_checkers returns those on a separate
channel and grade() ignores them even if handed one directly.
"""

from __future__ import annotations

import logging

from .checks import ALL_CHECKERS
from .models import Finding

log = logging.getLogger(__name__)

_GRADE_BY_SEVERITY = {"CRITICAL": "F", "HIGH": "D", "MEDIUM": "C"}
# INFO ranks 0: observations never move the grade, even on a mixed list.
_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}


def grade(findings: list[Finding]) -> str:
    worst = "A"
    worst_rank = 0
    for f in findings:
        rank = _SEVERITY_RANK.get(f.severity, 0)
        if rank > worst_rank:
            worst_rank = rank
            worst = _GRADE_BY_SEVERITY[f.severity]
    return worst


def run_checkers(facts: dict, target: str) -> tuple[list[Finding], list[Finding]]:
    """Returns (findings, observations). Checkers emit graded severities and
    may also emit INFO observations (auth-walled-but-fingerprinted); the two
    are partitioned here so no downstream consumer can grade an observation
    by accident."""
    findings: list[Finding] = []
    observations: list[Finding] = []
    for checker in ALL_CHECKERS:
        try:
            for f in checker.detect(facts):
                (observations if f.severity == "INFO" else findings).append(f)
        except Exception as exc:
            # One broken checker must never kill a scan — but it must not be
            # invisible either: a silently dead checker reads as "clean".
            log.warning(
                "checker %s failed: %s: %s",
                getattr(checker, "CHECK_ID", None) or checker.__name__,
                type(exc).__name__, exc,
            )
            continue
    # Annotation only — never touches severity / grade inputs. Observations
    # are deliberately not annotated (no version was disclosed by the wall).
    from .checks.vuln_lookup import annotate_known_cves
    try:
        annotate_known_cves(findings)
    except Exception:
        pass  # a broken CVE annotation must never kill a scan
    for f in findings + observations:  # checkers emit TARGET placeholder; bind real target here
        f.url = f.url.replace("TARGET", target)
    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f.severity, 0))
    # Deterministic order for a non-graded channel: product, then check_id.
    observations.sort(key=lambda f: (f.product.lower(), f.check_id))
    return findings, observations
