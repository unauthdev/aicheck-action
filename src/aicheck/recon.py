"""Fact gathering: safe HTTP GET probes of metadata endpoints only.

Hard rules (see SPEC.md): GETs only. No POSTs, no auth attempts, no
exploit verification, no model pulls. Bodies are capped at 64 KB.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable

import httpx

from .models import ProbeResult

MAX_BODY = 64 * 1024
TIMEOUT = httpx.Timeout(5.0, connect=3.0)
CONCURRENCY = 12
# Hard budget for the whole fact-gathering phase. A scan must ALWAYS complete;
# a heavily filtered target must never hang the report (dead hosts finish in
# ~15-20s at these settings, budget covers stragglers).
GATHER_BUDGET_S = 40
USER_AGENT = "aicheck/0.1 (+exposure-checker; safe metadata GETs only)"

# (port, path) candidate probes for all tier-1 checkers.
PROBES: list[tuple[int, str]] = [
    # Ollama
    (11434, "/"),
    (11434, "/api/version"),
    (11434, "/api/tags"),
    # n8n
    (5678, "/"),
    (5678, "/rest/settings"),
    # Open WebUI
    (8080, "/"),
    (8080, "/api/config"),
    # vLLM + OpenAI-compatible proxies (LiteLLM :4000, etc.)
    (8000, "/v1/models"),
    (8000, "/version"),
    (4000, "/v1/models"), (8080, "/v1/models"), (5000, "/v1/models"),
    # OpenHands Agent Server (GET / and /server_info → ServerInfo JSON)
    (8000, "/"), (8000, "/server_info"), (8000, "/alive"),
    (3000, "/server_info"),
    (8080, "/server_info"),
    # Langfuse (shares :3000 — fingerprint by content, never by port alone)
    (3000, "/"),
    (3000, "/api/public/health"),
    (3000, "/auth/sign-up"),
    # ComfyUI
    (8188, "/"),
    (8188, "/system_stats"),
    (8188, "/api/manager/version"),  # ComfyUI-Manager extension version (CVE-2025-67303)
    # Ray dashboard
    (8265, "/"),
    (8265, "/api/version"),
    (8265, "/api/jobs/"),
    (8265, "/nodes"),
    # Dify (web :80/:3000, api :5001 — fingerprint by content)
    (80, "/signin"),
    (5001, "/console/api/setup"),
    # Qdrant
    (6333, "/"),
    (6333, "/collections"),
    # AnythingLLM
    (3001, "/"),
    (3001, "/api/ping"),
    # Jupyter
    (8888, "/"),
    (8888, "/api/status"),
    (8888, "/api/kernels"),
    # Gradio / Langflow (share :7860 — content fingerprint decides)
    (7860, "/"),
    (7860, "/config"),
    (7860, "/api/v1/version"),
    (7860, "/health"),
    # Flowise (shares :3000 — content decides)
    (3000, "/api/v1/ping"),
    # Chroma (shares :8000 with vLLM — content decides)
    (8000, "/api/v1/heartbeat"),
    (8000, "/api/v2/heartbeat"),
    (8000, "/api/v1/collections"),
    (8000, "/api/v2/collections"),
    # Weaviate (shares :8080 with Open WebUI — content decides)
    (8080, "/v1/meta"),
    (8080, "/v1/schema"),
    # RedisInsight (default :5540, older :8001) + Redis Commander (:8081)
    # — HTTP consoles only; raw Redis RESP :6379 is out of scope
    (5540, "/"), (5540, "/api/health"), (5540, "/api/health/"), (5540, "/api/databases"),
    (8001, "/"), (8001, "/api/health"), (8001, "/api/health/"), (8001, "/api/databases"),
    (8081, "/"), (8082, "/"),
    # MCP servers (no standard port — probe the common ones + 443 via alias)
    (3000, "/sse"), (3000, "/mcp/sse"), (3000, "/mcp"), (3000, "/mcp/"),
    (3001, "/sse"), (3001, "/mcp/sse"), (3001, "/mcp"),
    (5000, "/sse"), (5000, "/mcp/sse"), (5000, "/mcp"),
    (8000, "/sse"), (8000, "/mcp/sse"), (8000, "/mcp"),
    (8080, "/sse"), (8080, "/mcp/sse"), (8080, "/mcp"), (8080, "/mcp/"),
    # MCP discovery (SEP / IETF-style well-known cards — GET only)
    (3000, "/.well-known/mcp"), (3000, "/.well-known/mcp.json"),
    (3000, "/.well-known/mcp/server-card.json"), (3000, "/.well-known/mcp-server"),
    (3001, "/.well-known/mcp"), (3001, "/.well-known/mcp.json"),
    (3001, "/.well-known/mcp/server-card.json"),
    (5000, "/.well-known/mcp"), (5000, "/.well-known/mcp.json"),
    (5000, "/.well-known/mcp/server-card.json"),
    (8000, "/.well-known/mcp"), (8000, "/.well-known/mcp.json"),
    (8000, "/.well-known/mcp/server-card.json"),
    (8080, "/.well-known/mcp"), (8080, "/.well-known/mcp.json"),
    (8080, "/.well-known/mcp/server-card.json"), (8080, "/.well-known/mcp-server"),
    # MCP SSE session surface (AIG / nuclei GET fingerprint)
    (3000, "/messages/"), (3001, "/messages/"), (5000, "/messages/"),
    (8000, "/messages/"), (8080, "/messages/"),
]


def fact_key(port: int, path: str) -> str:
    return f"{port}:{path}"


# A connection log entry: (method, logical URL, address actually dialed).
ConnectLog = Callable[[str, str, str], None]


def probe_plan() -> list[tuple[int, str]]:
    """The full (port, path) request list a scan sends: PROBES plus a :443
    alias of every API path (real-world deployments often sit behind TLS
    reverse proxies on 443 instead of their product-default port — leakix/
    Shodan confirm much of the exposed Ollama population answers there).
    Single source of truth for gather_facts and --dry-run."""
    extra = [(443, path) for (port, path) in PROBES if port not in (80, 443) and path != "/"]
    return PROBES + extra


_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _connect_kwargs(target: str, ip: str | None, scheme: str, port: int) -> dict:
    """When pinned to a validated IP we dial the IP but keep the logical
    identity of the target: Host header carries the hostname, and TLS SNI
    stays the hostname (certs are not verified, but vhosts route on SNI)."""
    if ip is None:
        return {}
    kwargs = {"headers": {"Host": target if port in (80, 443) else f"{target}:{port}"}}
    if scheme == "https":
        kwargs["extensions"] = {"sni_hostname": target}
    return kwargs


def _url_host(host: str) -> str:
    """Bracket IPv6 literals so httpx accepts scheme://[v6]:port/path."""
    try:
        if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            return f"[{host}]"
    except ValueError:
        pass
    return host


async def _fetch(
    client: httpx.AsyncClient, target: str, ip: str | None, port: int, path: str,
    log: ConnectLog | None = None,
) -> tuple[str, ProbeResult]:
    """One probe, following up to 3 redirects. Anti-rebinding/proxy rules:
    redirects are only followed when they stay on the SAME host as the
    validated target (any scheme/port), and when pinned IPs are given the
    connection always goes to those IPs — never to a fresh DNS answer. A
    cross-host redirect would turn this scanner into an open GET proxy."""
    from urllib.parse import urljoin, urlparse

    scheme = "https" if port == 443 else "http"
    cur_port, cur_path = port, path
    for _hop in range(3):
        host = ip or target
        url = f"{scheme}://{_url_host(host)}:{cur_port}{cur_path}"
        logical_url = f"{scheme}://{target}:{cur_port}{cur_path}"
        if log is not None:
            log("GET", logical_url, host)
        resp = await client.get(
            url, follow_redirects=False, **_connect_kwargs(target, ip, scheme, cur_port)
        )
        if resp.status_code in _REDIRECT_STATUSES:
            nxt = urlparse(urljoin(logical_url, resp.headers.get("location", "")))
            if (nxt.hostname or "").rstrip(".").lower() != target:
                return ProbeResult(
                    url=logical_url, status_code=None, error="CrossHostRedirectBlocked"
                )
            scheme = nxt.scheme or scheme
            cur_port = nxt.port or (443 if scheme == "https" else 80)
            cur_path = nxt.path or "/"
            if nxt.query:
                cur_path += "?" + nxt.query
            continue
        chunks: list[bytes] = []
        size = 0
        try:
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY:
                    break
        except httpx.TimeoutException:
            pass  # open-ended stream (SSE): keep whatever arrived
        body = b"".join(chunks)[:MAX_BODY].decode("utf-8", "replace")
        return ProbeResult(url=logical_url, status_code=resp.status_code, body=body)
    return ProbeResult(url=logical_url, status_code=None, error="TooManyRedirects")


async def _probe(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    target: str,
    port: int,
    path: str,
    pinned_ips: list[str] | None = None,
    log: ConnectLog | None = None,
) -> tuple[str, ProbeResult]:
    key = fact_key(port, path)
    start_url = f"{'https' if port == 443 else 'http'}://{target}:{port}{path}"
    async with sem:
        # Try each validated IP in turn; only connection-level failures move
        # to the next address (one black-holed IP must not sink the probe).
        last_exc: BaseException | None = None
        for ip in (pinned_ips or [None]):
            try:
                return key, await _fetch(client, target, ip, port, path, log)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_exc = exc
            except httpx.InvalidURL as exc:
                # Unbracketed IPv6 (or other bad URL) must not silently drop
                # the probe task — try the next pinned address.
                last_exc = exc
            except httpx.HTTPError as exc:
                return key, ProbeResult(url=start_url, status_code=None, error=type(exc).__name__)
        return key, ProbeResult(
            url=start_url, status_code=None, error=type(last_exc).__name__ if last_exc else "ConnectError"
        )


async def gather_facts(
    target: str,
    transport: httpx.AsyncBaseTransport | None = None,
    pinned_ips: list[str] | None = None,
    log: ConnectLog | None = None,
) -> dict[str, ProbeResult]:
    """Run all candidate probes concurrently, bounded by GATHER_BUDGET_S.
    On budget expiry, unfinished probes are recorded as absent and we return
    partial facts — the scan always completes.

    `pinned_ips` are the addresses validated by ssrf.validate_target; when
    given, every connection dials those IPs (never a fresh DNS answer), so a
    rebind between validation and connect goes nowhere.

    `log`, when given, is called as log(method, logical_url, dialed_address)
    just before every outbound request — the --verbose connection log."""
    sem = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=TIMEOUT,
        follow_redirects=False,
        verify=False,  # tolerate self-signed certs if a probe redirects to https
        headers={"User-Agent": USER_AGENT},
    ) as client:
        tasks = {
            asyncio.ensure_future(_probe(client, sem, target, p, path, pinned_ips, log)): (p, path)
            for p, path in probe_plan()
        }
        done, pending = await asyncio.wait(tasks, timeout=GATHER_BUDGET_S)
        for t in pending:
            t.cancel()
        results = [t.result() for t in done if not t.cancelled() and t.exception() is None]
        out = dict(results)
        for t in pending:
            p, path = tasks[t]
            out[fact_key(p, path)] = ProbeResult(url=f"http://{target}:{p}{path}", status_code=None, error="BudgetExceeded")
        # Alias good :443 hits (reverse-proxied deployments) back to the
        # product's canonical key.
        for port, path in PROBES:
            if port in (80, 443) or path == "/":
                continue
            key = fact_key(port, path)
            proxied = out.get(fact_key(443, path))
            if (out.get(key) is None or out[key].status_code is None) and proxied is not None and proxied.status_code == 200:
                out[key] = proxied
    return out
