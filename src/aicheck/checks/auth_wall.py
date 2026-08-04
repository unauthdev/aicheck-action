"""Shared support for auth-walled observations (INFO, never graded).

Three-state model for every product probe: the answer either proves an
exposure (a graded finding), proves the product is present but demands
authentication (an observation built here), or says nothing. The design
partner's risk question is not only "zero-auth Ollama" — it is "what shadow
AI exists, even behind a login".

Evidence rule (same bar as exposures): a bare 401/403 on a well-known port
is NEVER an observation — any app can sit behind a basic-auth proxy. The
walled response itself must carry a product-unique marker (Server header or
body token), or the checker must have already fingerprinted the product
from a sibling probe before hitting the wall (that case lives in the
checker's own code, not here).

Observations are Finding objects with severity "INFO" and
details["auth"] == "present". scoring.grade ignores INFO by construction;
run_checkers returns them on a separate channel so no consumer can mistake
them for exposures.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

WALLED_STATUSES = (401, 403)


def walled(p: ProbeResult | None) -> bool:
    """True when a probe answered 401/403 — something is there and demands auth."""
    return p is not None and p.status_code in WALLED_STATUSES


def mentions(p: ProbeResult | None, *tokens: str) -> bool:
    """Product marker in the response body or Server header (case-insensitive).
    This is the FP guard: a walled port becomes an observation only when the
    answer itself names the product."""
    if p is None:
        return False
    hay = f"{p.body}\n{p.server}".lower()
    return any(t.lower() in hay for t in tokens)


def walled_and_marked(probes, *tokens: str) -> ProbeResult | None:
    """First probe that is BOTH auth-walled AND self-identifying as the
    product — the tightest observation bar (one response carries both facts)."""
    for p in probes:
        if walled(p) and mentions(p, *tokens):
            return p
    return None


def observation(
    *,
    check_id: str,
    product: str,
    title: str,
    url: str,
    evidence: str,
    fix_card_id: str,
    details: dict | None = None,
) -> Finding:
    """Build an INFO observation. details["auth"] = "present" is the contract
    consumers key on; severity INFO is excluded from the grade by scoring."""
    d = dict(details or {})
    d["auth"] = "present"
    return Finding(
        check_id=check_id,
        product=product,
        title=title,
        severity="INFO",
        url=url,
        evidence=evidence,
        fix_card_id=fix_card_id,
        details=d,
    )
