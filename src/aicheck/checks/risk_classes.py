"""Shared finding-class markers (deterministic, grade-neutral).

`risk_class` is additive metadata for reports/census/fix cards. It must not
change severity ranks used by the grader unless a checker intentionally
raises the exposure class.
"""

from __future__ import annotations

# Vector / RAG stores that may hold long-lived agent state (OWASP ASI06).
AGENT_MEMORY = "agent-memory"

# Observability / trace backends that retain prompts, tools, and session state.
AGENT_TRACES = "agent-traces"

# Agent builders / runtimes that let strangers invoke chains or chatflows.
AGENT_RUNTIME = "agent-runtime"

ASI06_REF = "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"


def with_risk(details: dict | None, risk_class: str, **extra) -> dict:
    out = dict(details or {})
    out["risk_class"] = risk_class
    if risk_class == AGENT_MEMORY:
        out.setdefault("owasp", "ASI06")
    out.update(extra)
    return out
