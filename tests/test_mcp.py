"""MCP checker — severity ladder + GET-only tools/list stand-in (A1 parity)."""

from __future__ import annotations

import json

from aicheck.checks import mcp
from aicheck.models import ProbeResult
from aicheck.recon import fact_key, probe_plan


def _pr(port: int, path: str, status: int | None, body: str = "") -> ProbeResult:
    return ProbeResult(
        url=f"http://fixture:{port}{path}", status_code=status, body=body,
    )


def _facts(*results: ProbeResult) -> dict[str, ProbeResult]:
    out: dict[str, ProbeResult] = {}
    for r in results:
        # url is http://fixture:PORT/path
        rest = r.url.split("://", 1)[1]
        hostport, path = rest.split("/", 1)
        port = int(hostport.rsplit(":", 1)[1])
        out[fact_key(port, "/" + path)] = r
    return out


def _j(obj) -> str:
    return json.dumps(obj)


def test_mcp_positive_sse():
    findings = mcp.detect(_facts(
        _pr(3000, "/sse", 200, "event: endpoint\ndata: /messages/?session_id=abc\n\n"),
    ))
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].product == "MCP server"
    assert findings[0].fix_card_id == "mcp-exposed"
    assert findings[0].details["auth"] == "none"


def test_mcp_positive_jsonrpc():
    """Real streamable-HTTP MCP servers answer a bare GET with a parsed
    JSON-RPC error on a transport status (400 here). Works against both
    the pre- and post-hardening checker."""
    findings = mcp.detect(_facts(
        _pr(8080, "/mcp", 400, _j({"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "Bad Request: No valid session ID provided (initialize method required)"}})),
    ))
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_mcp_no_fp_on_jsonrpc_mentioning_error_page():
    """An error page / API docs mentioning JSON-RPC is not transport evidence."""
    findings = mcp.detect(_facts(
        _pr(8080, "/mcp", 404, "<html><body>Unknown route. This API speaks JSON-RPC; call method tools/list.</body></html>"),
    ))
    assert findings == []


def test_mcp_no_fp_on_405_bodies():
    """A 405 body is not transport evidence — the method itself failed."""
    findings = mcp.detect(_facts(
        _pr(8080, "/mcp", 405, _j({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Method not allowed"}})),
    ))
    assert findings == []


def test_mcp_session_surface_high():
    findings = mcp.detect(_facts(_pr(3000, "/messages/", 200, "session_id is required")))
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "session" in findings[0].title.lower()


def test_mcp_wellknown_discovery_medium():
    findings = mcp.detect(_facts(
        _pr(443, "/.well-known/mcp.json", 200, _j({
            "name": "demo-mcp",
            "mcp_version": "2025-06-18",
            "remotes": [{"type": "sse", "url": "https://example.com/sse"}],
        })),
    ))
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "discovery" in findings[0].title.lower()


def test_mcp_transport_outranks_discovery():
    findings = mcp.detect(_facts(
        _pr(3000, "/sse", 200, "event: endpoint\ndata: /messages/?session_id=abc\n\n"),
        _pr(3000, "/.well-known/mcp", 200, _j({"mcp_version": "1.0", "endpoints": {"sse": "/sse"}})),
    ))
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].details.get("discovery") is True


def test_mcp_auth_wall_not_finding():
    assert mcp.detect(_facts(
        _pr(3000, "/sse", 401, "unauthorized"),
        _pr(3000, "/mcp", 403, "forbidden"),
        _pr(3000, "/messages/", 401, "session_id is required"),
        _pr(3000, "/.well-known/mcp.json", 401, _j({"mcp_version": "1.0"})),
    )) == []


def test_mcp_no_fp_on_normal_api():
    assert mcp.detect(_facts(
        _pr(3000, "/sse", 404, "not found"),
        _pr(3000, "/mcp", 200, _j({"status": "ok"})),
    )) == []


def test_mcp_sse_406_not_acceptable():
    findings = mcp.detect(_facts(
        _pr(3000, "/sse", 406, "Not Acceptable: Client must accept text/event-stream"),
    ))
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].details["transport"] == "SSE transport"


def test_mcp_tools_catalog_critical():
    findings = mcp.detect(_facts(
        _pr(443, "/.well-known/mcp/server-card.json", 200, _j({
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "demo"},
            "transport": {"type": "streamable-http", "url": "/mcp"},
            "tools": [
                {"name": "read_file", "description": "read a file"},
                {"name": "run_shell", "description": "exec"},
            ],
        })),
    ))
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "tools catalog" in findings[0].title.lower()
    assert "read_file" in findings[0].evidence
    assert findings[0].details["tools_listed"] == ["read_file", "run_shell"]


def test_mcp_dynamic_tools_not_catalog():
    findings = mcp.detect(_facts(
        _pr(443, "/.well-known/mcp.json", 200, _j({
            "mcp_version": "2025-06-18",
            "tools": "dynamic",
            "remotes": [{"type": "sse", "url": "https://example.com/sse"}],
        })),
    ))
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].details.get("tools_listed") in (None, [])


def test_mcp_recon_includes_discovery_and_session():
    plan = set(probe_plan())
    assert (3000, "/.well-known/mcp.json") in plan
    assert (443, "/.well-known/mcp/server-card.json") in plan  # via 443 alias
    assert (3000, "/messages/") in plan
    assert (3000, "/mcp/") in plan
