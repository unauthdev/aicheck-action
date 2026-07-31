"""MCP server — exposed Model Context Protocol endpoint.

MCP servers built for local use ship with NO authentication by default, and
people deploy them publicly. An unauthenticated MCP endpoint is worse than a
data leak: strangers can enumerate and CALL your tools (file access, shell,
database queries — whatever the server exposes).

Fingerprint (GET-only, no JSON-RPC initialize):
- GET /sse or /mcp/sse → 200 with an SSE stream (event: endpoint / text/event-stream)
- GET /mcp → 200/4xx with a JSON-RPC-shaped body, or MCP-ish server header
- GET /.well-known/mcp or /healthz naming MCP
Port-agnostic: MCP has no standard port, so we probe the common ones
(3000, 8000, 8080) plus TLS on 443 via the shared alias layer.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

CHECK_ID = "mcp"
FIX_CARD_ID = "mcp-exposed"

_SSE_PATHS = ("/sse", "/mcp/sse")
_HTTP_PATHS = ("/mcp",)
_PORTS = ("3000", "3001", "5000", "8000", "8080", "443")


def _sse_hit(p: ProbeResult | None) -> bool:
    if p is None or not p.ok:
        return False
    body = p.body.lower()
    return "event: endpoint" in body or "text/event-stream" in body or "event: message" in body


def _jsonrpc_hit(p: ProbeResult | None) -> bool:
    if p is None or p.status_code not in (200, 400, 404, 405, 406):
        return False
    body = p.body.lower()
    return "jsonrpc" in body and ("method" in body or "mcp" in body or "server error" in body)


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    for port in _PORTS:
        for path in _SSE_PATHS + _HTTP_PATHS:
            probe = facts.get(f"{port}:{path}")
            if probe is None:
                continue
            sse = path in _SSE_PATHS and _sse_hit(probe)
            rpc = path in _HTTP_PATHS and _jsonrpc_hit(probe)
            if not (sse or rpc):
                continue
            kind = "SSE transport" if sse else "HTTP transport"
            return [
                Finding(
                    check_id=CHECK_ID,
                    product="MCP server",
                    title="MCP server exposed without authentication",
                    severity="CRITICAL",
                    url=probe.url,
                    evidence=(
                        f"GET {probe.url} → {probe.status_code} ({kind} answers unauthenticated) — "
                        "anyone can enumerate and call the tools this server exposes"
                    ),
                    fix_card_id=FIX_CARD_ID,
                    details={"transport": kind, "port": port},
                )
            ]
    return []
