"""Optional outbound webhook for inventory drift (customer-configured URL).

Disabled unless --webhook is set. Does not phone home to unauth.dev.

Egress posture: inventory runs on the customer's own network and the SIEM
endpoint is very often an INTERNAL host, so the scan-target public-IP guard
does NOT apply here. We only block loopback and link-local (169.254.0.0/16,
cloud metadata) by default; --webhook-allow-local opts out explicitly.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import socket
import sys
import time
from typing import Any
from urllib.parse import urlparse

import httpx

# Retries on top of the first attempt, on timeout / 5xx / connection error.
RETRY_ATTEMPTS = 3


class WebhookError(RuntimeError):
    pass


def webhook_payload(report: dict[str, Any], *, event: str = "inventory.drift") -> dict[str, Any]:
    drift = report.get("drift") or {}
    return {
        "event": event,
        "tool": "aicheck-inventory",
        "schema_version": report.get("schema_version"),
        "run_id": report.get("run_id"),
        "started_at": report.get("started_at"),
        "finished_at": report.get("finished_at"),
        "target_count": report.get("target_count"),
        "finding_count": report.get("finding_count"),
        "probe_mode": report.get("probe_mode"),
        "phone_home": False,
        "drift": {
            "new_count": drift.get("new_count", 0),
            "fixed_count": drift.get("fixed_count", 0),
            "changed_count": drift.get("changed_count", 0),
            "still_open_count": drift.get("still_open_count", 0),
            "new": drift.get("new") or [],
            "fixed": [
                {"finding_id": f.get("finding_id"), "title": f.get("title"),
                 "product": f.get("product"), "host": f.get("host")}
                for f in (drift.get("fixed") or [])
            ],
            "changed": [
                {"finding_id": f.get("finding_id"), "title": f.get("title"),
                 "product": f.get("product"), "host": f.get("host"),
                 "changes": f.get("changes") or {}}
                for f in (drift.get("changed") or [])
            ],
        },
    }


def should_notify(report: dict[str, Any], *, on: str) -> bool:
    if on == "always":
        return True
    if on == "new":
        return int((report.get("drift") or {}).get("new_count") or 0) > 0
    if on == "change":
        d = report.get("drift") or {}
        return (
            int(d.get("new_count") or 0)
            + int(d.get("fixed_count") or 0)
            + int(d.get("changed_count") or 0)
        ) > 0
    raise ValueError(f"unknown webhook on={on!r}")


def _resolve_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise WebhookError(f"webhook host {host!r} does not resolve: {exc}") from exc
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        try:
            ips.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return ips


def check_egress(url: str, *, allow_local: bool = False) -> None:
    """Resolve-and-check before POST. Internal RFC1918 endpoints are fine;
    loopback and link-local (cloud metadata) are blocked unless allow_local."""
    parsed = urlparse(url)
    if parsed.scheme == "http":
        print(
            f"webhook warning: {parsed.scheme}:// URL — drift payload contains "
            "estate data and will be sent unencrypted (operator's choice)",
            file=sys.stderr,
        )
    host = parsed.hostname or ""
    for ip in _resolve_ips(host):
        if (ip.is_loopback or ip.is_link_local) and not allow_local:
            raise WebhookError(
                f"webhook host {host!r} resolves to loopback/link-local {ip} — "
                "blocked by default (pass --webhook-allow-local to allow)"
            )


def sign_body(secret: str, body: bytes) -> str:
    """X-Aicheck-Signature value for the exact request body."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def post_webhook(
    url: str,
    report: dict[str, Any],
    *,
    on: str = "new",
    timeout_s: float = 10.0,
    secret: str | None = None,
    allow_local: bool = False,
    retries: int = RETRY_ATTEMPTS,
    backoff_s: float = 0.25,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any] | None:
    """POST drift payload. Returns response summary, or None if skipped.

    Redirects are never followed (follow_redirects=False) and any 3xx is an
    error. Retries (default 3 attempts total, short backoff) cover timeout,
    connection error, and 5xx only; 3xx/4xx fail immediately.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise WebhookError(f"invalid webhook URL: {url!r}")
    if not should_notify(report, on=on):
        return None
    check_egress(url, allow_local=allow_local)
    body = webhook_payload(report)
    raw = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "aicheck-inventory/1.2 (+webhook; no-phone-home)",
    }
    if secret:
        headers["X-Aicheck-Signature"] = sign_body(secret, raw)

    resp: httpx.Response | None = None
    last_exc: httpx.TransportError | None = None
    for attempt in range(1, retries + 1):
        try:
            with httpx.Client(
                timeout=timeout_s, follow_redirects=False, transport=transport
            ) as client:
                resp = client.post(url, content=raw, headers=headers)
        except httpx.TransportError as exc:  # timeout, connect error, network
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff_s * attempt)
            continue
        except httpx.HTTPError as exc:
            raise WebhookError(f"webhook request failed: {exc}") from exc
        if resp.status_code >= 500:
            if attempt < retries:
                time.sleep(backoff_s * attempt)
            continue
        if resp.status_code >= 300:
            # 3xx (we do not follow redirects) and 4xx are not retried.
            raise WebhookError(
                f"webhook HTTP {resp.status_code}: {(resp.text or '')[:200]}"
            )
        return {"status_code": resp.status_code, "event": body["event"], "on": on}

    if resp is not None:
        raise WebhookError(
            f"webhook HTTP {resp.status_code} after {retries} attempts: "
            f"{(resp.text or '')[:200]}"
        )
    raise WebhookError(f"webhook request failed after {retries} attempts: {last_exc}")
