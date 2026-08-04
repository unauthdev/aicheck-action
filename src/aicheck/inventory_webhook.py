"""Optional outbound webhook for inventory drift (customer-configured URL).

Disabled unless --webhook is set. Does not phone home to unauth.dev.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx


class WebhookError(RuntimeError):
    pass


def webhook_payload(report: dict[str, Any], *, event: str = "inventory.drift") -> dict[str, Any]:
    drift = report.get("drift") or {}
    return {
        "event": event,
        "tool": "aicheck-inventory",
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
            "still_open_count": drift.get("still_open_count", 0),
            "new": drift.get("new") or [],
            "fixed": [
                {"finding_id": f.get("finding_id"), "title": f.get("title"),
                 "product": f.get("product"), "host": f.get("host")}
                for f in (drift.get("fixed") or [])
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
        return int(d.get("new_count") or 0) + int(d.get("fixed_count") or 0) > 0
    raise ValueError(f"unknown webhook on={on!r}")


def post_webhook(
    url: str,
    report: dict[str, Any],
    *,
    on: str = "new",
    timeout_s: float = 10.0,
) -> dict[str, Any] | None:
    """POST drift payload. Returns response summary, or None if skipped."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise WebhookError(f"invalid webhook URL: {url!r}")
    if not should_notify(report, on=on):
        return None
    body = webhook_payload(report)
    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=False) as client:
            resp = client.post(
                url,
                content=json.dumps(body),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "aicheck-inventory/1.2 (+webhook; no-phone-home)",
                },
            )
    except httpx.HTTPError as exc:
        raise WebhookError(f"webhook request failed: {exc}") from exc
    if resp.status_code >= 300:
        raise WebhookError(
            f"webhook HTTP {resp.status_code}: {(resp.text or '')[:200]}"
        )
    return {"status_code": resp.status_code, "event": body["event"], "on": on}
