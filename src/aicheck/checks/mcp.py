"""MCP server — exposed Model Context Protocol endpoint.

MCP servers built for local use ship with NO authentication by default, and
people deploy them publicly. An unauthenticated MCP endpoint is worse than a
data leak: strangers can enumerate and CALL your tools (file access, shell,
database queries — whatever the server exposes).

Fingerprint (GET-only — no JSON-RPC tools/list POST):
- GET /sse or /mcp/sse → SSE stream, or 406 "must accept text/event-stream"
  (CRITICAL — tool transport open; nuclei exposed-mcp-sse-server parity)
- GET /mcp → JSON-RPC-shaped body without auth (CRITICAL)
- GET /messages/ → "session_id is required" (HIGH — MCP session surface)
- GET /.well-known/mcp*, /.well-known/mcp-server → discovery card/manifest
  (MEDIUM alone; CRITICAL if the card ships a static tools catalog — that is
  the GET equivalent of unauthenticated tools/list)

Auth required (401/403) on a path is not a finding for that path.
Port-agnostic: common local ports + TLS on 443 via the shared alias layer.
"""

from __future__ import annotations

from ..models import Finding, ProbeResult

CHECK_ID = "mcp"
FIX_CARD_ID = "mcp-exposed"

_SSE_PATHS = ("/sse", "/mcp/sse")
_HTTP_PATHS = ("/mcp", "/mcp/")
_SESSION_PATHS = ("/messages/",)
_WELLKNOWN_PATHS = (
    "/.well-known/mcp",
    "/.well-known/mcp.json",
    "/.well-known/mcp/server-card.json",
    "/.well-known/mcp-server",
)
_PORTS = ("3000", "3001", "5000", "8000", "8080", "443")
_MAX_TOOL_NAMES = 8


def _auth_wall(p: ProbeResult | None) -> bool:
    return p is not None and p.status_code in (401, 403)


def _sse_hit(p: ProbeResult | None) -> bool:
    """Open SSE transport, including 406 Accept negotiation (nuclei parity)."""
    if p is None or _auth_wall(p) or p.status_code is None:
        return False
    body = p.body.lower()
    if p.status_code == 406 and (
        "must accept text/event-stream" in body
        or "client must accept text/event-stream" in body
        or "text/event-stream" in body
    ):
        return True
    if not p.ok:
        return False
    return (
        "event: endpoint" in body
        or "event: message" in body
        or "text/event-stream" in body
        or ("session_id=" in body and "event:" in body)
    )


def _jsonrpc_hit(p: ProbeResult | None) -> bool:
    if p is None or _auth_wall(p):
        return False
    if p.status_code not in (200, 400, 404, 405, 406):
        return False
    body = p.body.lower()
    return "jsonrpc" in body and ("method" in body or "mcp" in body or "server error" in body)


def _session_hit(p: ProbeResult | None) -> bool:
    """AIG / nuclei GET fingerprint — MCP SSE session endpoint without auth."""
    if p is None or _auth_wall(p) or p.status_code not in (200, 400, 422):
        return False
    return "session_id is required" in p.body.lower()


def _tool_names_from_payload(data: dict) -> list[str]:
    """Static tool catalog from a server card / manifest (GET tools/list stand-in)."""
    names: list[str] = []

    def _from_list(items) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
            elif isinstance(item, str) and item and item != "dynamic":
                names.append(item)

    tools = data.get("tools")
    if tools == "dynamic":
        return []
    _from_list(tools)

    caps = data.get("capabilities")
    if isinstance(caps, dict):
        _from_list(caps.get("tools"))

    server = data.get("server")
    if isinstance(server, dict):
        _from_list(server.get("tools"))

    # Dedupe, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _wellknown_hit(p: ProbeResult | None) -> tuple[bool, list[str]]:
    """Return (is_mcp_discovery, static_tool_names)."""
    if p is None or _auth_wall(p) or not p.ok:
        return False, []
    data = p.json()
    tools: list[str] = []
    if isinstance(data, dict):
        tools = _tool_names_from_payload(data)
        keys = set(data.keys())
        if keys & {"mcp_version", "endpoints", "remotes", "packages", "transports", "protocolVersion"}:
            return True, tools
        server = data.get("server")
        if isinstance(server, dict) and (
            "name" in server or "version" in server or "remotes" in server or "tools" in server
        ):
            return True, tools
        if "serverInfo" in data and ("transport" in data or "capabilities" in data):
            return True, tools
        if "name" in data and ("remotes" in data or "transport" in data or "url" in data or "tools" in data):
            return True, tools
    body = p.body.lower()
    hit = (
        "mcp_version" in body
        or "protocolversion" in body
        or "model context protocol" in body
        or "server-card" in body
        or ('"remotes"' in body and "mcp" in body)
        or ("serverinfo" in body and "transport" in body)
    )
    return hit, tools


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    best: Finding | None = None
    rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}

    for port in _PORTS:
        open_transport: ProbeResult | None = None
        transport_kind = ""
        session: ProbeResult | None = None
        wellknown: ProbeResult | None = None
        tool_names: list[str] = []

        for path in _SSE_PATHS:
            probe = facts.get(f"{port}:{path}")
            if _sse_hit(probe):
                open_transport = probe
                transport_kind = "SSE transport"
                break
        if open_transport is None:
            for path in _HTTP_PATHS:
                probe = facts.get(f"{port}:{path}")
                if _jsonrpc_hit(probe):
                    open_transport = probe
                    transport_kind = "HTTP transport"
                    break
        for path in _SESSION_PATHS:
            probe = facts.get(f"{port}:{path}")
            if _session_hit(probe):
                session = probe
                break
        for path in _WELLKNOWN_PATHS:
            probe = facts.get(f"{port}:{path}")
            hit, names = _wellknown_hit(probe)
            if hit:
                wellknown = probe
                tool_names = names
                break

        if open_transport is None and session is None and wellknown is None:
            continue

        if open_transport is not None:
            severity = "CRITICAL"
            title = "MCP server exposed without authentication"
            tool_note = ""
            if tool_names:
                shown = ", ".join(tool_names[:_MAX_TOOL_NAMES])
                extra = len(tool_names) - _MAX_TOOL_NAMES
                tool_note = f"; discovery card lists tools: {shown}"
                if extra > 0:
                    tool_note += f" (+{extra} more)"
            evidence = (
                f"GET {open_transport.url} → {open_transport.status_code} "
                f"({transport_kind} answers unauthenticated) — "
                "anyone can enumerate and call the tools this server exposes"
                f"{tool_note}"
            )
            url = open_transport.url
            details = {
                "transport": transport_kind,
                "port": port,
                "auth": "none",
                "discovery": bool(wellknown),
                "tools_listed": tool_names[:_MAX_TOOL_NAMES],
            }
        elif tool_names and wellknown is not None:
            # GET-visible static tools catalog = unauthenticated tools/list
            severity = "CRITICAL"
            shown = ", ".join(tool_names[:_MAX_TOOL_NAMES])
            extra = len(tool_names) - _MAX_TOOL_NAMES
            catalog = shown + (f" (+{extra} more)" if extra > 0 else "")
            title = "MCP tools catalog exposed without authentication"
            evidence = (
                f"GET {wellknown.url} → {wellknown.status_code} — "
                f"public MCP discovery lists tools without auth ({catalog}); "
                "this is the GET equivalent of unauthenticated tools/list"
            )
            url = wellknown.url
            details = {
                "transport": "discovery+tools",
                "port": port,
                "auth": "none",
                "tools_listed": tool_names[:_MAX_TOOL_NAMES],
            }
        elif session is not None:
            severity = "HIGH"
            title = "MCP session endpoint exposed without authentication"
            evidence = (
                f"GET {session.url} → {session.status_code} "
                "(`session_id is required`) — MCP session surface answers strangers; "
                "pair with an open SSE/HTTP transport and tools are callable"
            )
            url = session.url
            details = {"transport": "session", "port": port, "auth": "none"}
        else:
            assert wellknown is not None
            severity = "MEDIUM"
            title = "MCP discovery document exposed to the internet"
            evidence = (
                f"GET {wellknown.url} → {wellknown.status_code} — "
                "a public MCP server card/manifest advertises this host as agent infrastructure"
            )
            url = wellknown.url
            details = {"transport": "discovery", "port": port, "auth": "none"}

        candidate = Finding(
            check_id=CHECK_ID,
            product="MCP server",
            title=title,
            severity=severity,
            url=url,
            evidence=evidence,
            fix_card_id=FIX_CARD_ID,
            details=details,
        )
        if best is None or rank[severity] > rank[best.severity]:
            best = candidate

    return [best] if best else []
