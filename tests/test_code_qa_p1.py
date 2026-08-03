"""Acceptance tests for Code QA 2026-08-03 P1s (dual-stack + Chroma .ok)."""

from __future__ import annotations

import asyncio
import json
import socket

import httpx
import pytest

from aicheck import recon, ssrf
from aicheck.checks import chroma
from aicheck.models import ProbeResult
from aicheck.render import render_summary
from aicheck.scan import _services_wanted, render_text
from aicheck.scoring import grade


def _pr(port: int, path: str, status: int | None, body: str = "") -> ProbeResult:
    return ProbeResult(
        url=f"http://fixture:{port}{path}", status_code=status, body=body,
    )


def test_chroma_v1_only_falls_through_failed_v2():
    facts = {
        "8000:/api/v2/heartbeat": _pr(8000, "/api/v2/heartbeat", 404, "Not Found"),
        "8000:/api/v1/heartbeat": _pr(
            8000, "/api/v1/heartbeat", 200,
            json.dumps({"nanosecond heartbeat": 1}),
        ),
        "8000:/api/v2/collections": _pr(8000, "/api/v2/collections", 404, ""),
        "8000:/api/v1/collections": _pr(
            8000, "/api/v1/collections", 200,
            json.dumps([{"name": "legacy"}]),
        ),
    }
    findings = chroma.detect(facts)
    assert len(findings) == 1 and findings[0].severity == "CRITICAL"


def test_chroma_v2_only_collections_critical():
    facts = {
        "8000:/api/v2/heartbeat": _pr(
            8000, "/api/v2/heartbeat", 200,
            json.dumps({"nanosecond heartbeat": 1}),
        ),
        "8000:/api/v1/heartbeat": _pr(8000, "/api/v1/heartbeat", 404, ""),
        "8000:/api/v2/collections": _pr(
            8000, "/api/v2/collections", 200,
            json.dumps([{"name": "modern"}]),
        ),
        "8000:/api/v1/collections": _pr(8000, "/api/v1/collections", 404, ""),
    }
    findings = chroma.detect(facts)
    assert len(findings) == 1 and findings[0].severity == "CRITICAL"
    assert "modern" in findings[0].evidence


def test_chroma_both_apis_critical():
    facts = {
        "8000:/api/v2/heartbeat": _pr(
            8000, "/api/v2/heartbeat", 200,
            json.dumps({"nanosecond heartbeat": 1}),
        ),
        "8000:/api/v1/heartbeat": _pr(
            8000, "/api/v1/heartbeat", 200,
            json.dumps({"nanosecond heartbeat": 1}),
        ),
        "8000:/api/v2/collections": _pr(
            8000, "/api/v2/collections", 200,
            json.dumps([{"name": "a"}]),
        ),
        "8000:/api/v1/collections": _pr(
            8000, "/api/v1/collections", 200,
            json.dumps([{"name": "b"}]),
        ),
    }
    findings = chroma.detect(facts)
    assert len(findings) == 1 and findings[0].severity == "CRITICAL"


def test_dual_stack_keeps_only_public_ipv4(monkeypatch):
    v6 = "2606:2800:220:1:248:1893:25c8:1946"

    def fake(*_a, **_k):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (v6, 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    host, ips = ssrf.validate_target("example.com")
    assert host == "example.com"
    assert ips == ["93.184.216.34"]


def test_rejects_aaaa_only(monkeypatch):
    v6 = "2606:2800:220:1:248:1893:25c8:1946"
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_a, **_k: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (v6, 0, 0, 0)),
        ],
    )
    with pytest.raises(ssrf.TargetRejected, match="IPv6"):
        ssrf.validate_target("ipv6-only.example.com")


def test_dual_stack_v6_first_pinned_still_probes_v4():
    attempts: list[str] = []
    v6 = "2606:2800:220:1:248:1893:25c8:1946"

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(str(request.url.host))
        if request.url.host == "93.184.216.34" and request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.32.5"})
        raise httpx.ConnectError("refused", request=request)

    facts = asyncio.run(
        recon.gather_facts(
            "test.example",
            transport=httpx.MockTransport(handler),
            pinned_ips=[v6, "93.184.216.34"],
        )
    )
    assert "93.184.216.34" in attempts
    assert facts["11434:/api/version"].status_code == 200
    assert (8000, "/api/v2/collections") in recon.PROBES


def test_services_filter_exact_not_substring():
    class F:
        check_id = "n8n"
        product = "n8n"

    assert _services_wanted(F(), {"n8n"})
    assert not _services_wanted(F(), {"n8"})  # substring must not match


def test_filtered_clean_summary_does_not_claim_estate_clean():
    text = render_summary("A", [], services_filter=["ollama"])
    assert "filtered: ollama" in text
    assert "clean estate" in text.lower() or "not included" in text.lower()
    assert "grade A ✓ clean" not in text
    cli = render_text("h", "A", [], services_filter=["ollama"])
    assert "filtered services" in cli
    assert grade([]) == "A"
