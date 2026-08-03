"""Redis HTTP management UIs — agent-memory kin (OWASP ASI06).

Raw Redis is RESP/TCP (:6379) and outside our GET-only probe set. What we
can fingerprint safely is the HTTP console people put in front of it:

- RedisInsight (default :5540, older :8001) — /api/health + optional /api/databases
- Redis Commander (:8081 and kin) — HTML title fingerprint

Finding class: agent-memory. Grades follow open-console vs console-with-DB-list;
we do not claim TCP Redis itself was fingerprinted.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult
from .risk_classes import AGENT_MEMORY, with_risk

CHECK_ID = "redis"
FIX_CARD_ID = "redis-exposed"

_INSIGHT_PORTS = (5540, 8001)
_COMMANDER_PORTS = (8081, 8082)


def _body(p: ProbeResult | None) -> str:
    if p is None or not p.ok or p.body is None:
        return ""
    if isinstance(p.body, bytes):
        return p.body.decode("utf-8", "replace")
    return str(p.body)


def _insight_healthy(health: ProbeResult, root: ProbeResult | None) -> bool:
    hj = health.json()
    body = _body(health).lower()
    if isinstance(hj, dict):
        status = str(hj.get("status", "")).lower()
        if status in ("pass", "healthy", "ok"):
            return True
    if "redisinsight" in body:
        return True
    if root is not None and root.ok and "redisinsight" in _body(root).lower():
        return True
    return False


def _db_names(dbs: ProbeResult) -> list[str]:
    dj = dbs.json()
    rows: list = []
    if isinstance(dj, list):
        rows = dj
    elif isinstance(dj, dict):
        for key in ("data", "databases", "items"):
            maybe = dj.get(key)
            if isinstance(maybe, list):
                rows = maybe
                break
    names: list[str] = []
    for row in rows[:5]:
        if isinstance(row, dict):
            names.append(str(row.get("name") or row.get("host") or "?"))
        else:
            names.append(str(row))
    return names


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    for port in _INSIGHT_PORTS:
        health = facts.get(f"{port}:/api/health") or facts.get(f"{port}:/api/health/")
        if health is None or not health.ok:
            continue
        root = facts.get(f"{port}:/")
        if not _insight_healthy(health, root):
            continue
        dbs = facts.get(f"{port}:/api/databases") or facts.get(f"{port}:/api/databases/")
        if dbs is not None and dbs.ok:
            names = _db_names(dbs)
            bit = (
                f"; {len(names)} database(s) listed ({', '.join(names)})"
                if names else "; database list readable"
            )
            return [
                Finding(
                    check_id=CHECK_ID,
                    product="Redis",
                    title="RedisInsight console open — Redis databases browsable without authentication",
                    severity="CRITICAL",
                    url=f"http://TARGET:{port}/",
                    evidence=(
                        f"GET {health.url} → 200 (RedisInsight health); "
                        f"GET {dbs.url} → 200{bit} — no auth required. Anyone can browse "
                        "keys that may hold agent memory / session state (OWASP ASI06)"
                    ),
                    fix_card_id=FIX_CARD_ID,
                    details=with_risk(
                        {"ui": "redisinsight", "databases": names}, AGENT_MEMORY
                    ),
                )
            ]
        return [
            Finding(
                check_id=CHECK_ID,
                product="Redis",
                title="RedisInsight console exposed to the internet",
                severity="HIGH",
                url=f"http://TARGET:{port}/",
                evidence=(
                    f"GET {health.url} → 200 (RedisInsight answers anyone) — "
                    "this console manages Redis stores that often hold agent memory "
                    "(OWASP ASI06)"
                ),
                fix_card_id=FIX_CARD_ID,
                details=with_risk({"ui": "redisinsight"}, AGENT_MEMORY),
            )
        ]

    for port in _COMMANDER_PORTS:
        root = facts.get(f"{port}:/")
        if root is None or not root.ok:
            continue
        low = _body(root).lower()
        if "redis commander" not in low and "redis-commander" not in low:
            continue
        return [
            Finding(
                check_id=CHECK_ID,
                product="Redis",
                title="Redis Commander console exposed to the internet",
                severity="CRITICAL",
                url=f"http://TARGET:{port}/",
                evidence=(
                    f"GET {root.url} → 200 (Redis Commander UI) — key browser "
                    "reachable without auth; Redis often holds agent memory / sessions "
                    "(OWASP ASI06)"
                ),
                fix_card_id=FIX_CARD_ID,
                details=with_risk({"ui": "redis-commander"}, AGENT_MEMORY),
            )
        ]
    return []
