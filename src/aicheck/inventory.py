"""Local continuous inventory of self-hosted AI services.

Air-gapped by default: reads a targets file, live-probes each host (GET-only),
writes findings + drift to a local state directory. No phone-home, no accounts.

  python -m aicheck.inventory --targets targets.yaml --state-dir ./state --allow-private

See docs/PROBES.md for the exact traffic model.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from . import scan
from .inventory_findings import enrich_finding
from .inventory_targets import TargetLoadError, load_targets
from .inventory_webhook import WebhookError, post_webhook
from .probe_class import ProbeClassError, ProbeMode, resolve_probe_mode
from .ssrf import TargetRejected


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_id_from(ts: str) -> str:
    return ts.replace(":", "").replace("-", "")


def load_state(state_dir: Path) -> dict[str, Any]:
    path = state_dir / "state.json"
    if not path.is_file():
        return {"findings": {}, "last_run_at": None, "last_run_id": None}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(state_dir: Path, state: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "state.json").write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def write_run(state_dir: Path, report: dict[str, Any]) -> Path:
    runs = state_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    path = runs / f"{report['run_id']}.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (state_dir / "latest.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return path


def diff_findings(
    previous: dict[str, dict], current: dict[str, dict]
) -> dict[str, list[dict]]:
    prev_ids = set(previous)
    curr_ids = set(current)
    new_ids = sorted(curr_ids - prev_ids)
    fixed_ids = sorted(prev_ids - curr_ids)
    open_ids = sorted(curr_ids & prev_ids)
    return {
        "new": [current[i] for i in new_ids],
        "fixed": [previous[i] for i in fixed_ids],
        "still_open": [current[i] for i in open_ids],
    }


async def scan_target(
    target: dict[str, str | None],
    *,
    allow_private: bool,
    services: list[str] | None,
    transport: httpx.AsyncBaseTransport | None,
) -> dict[str, Any]:
    host = str(target["host"])
    try:
        grade, findings = await scan.scan(
            host,
            allow_private=allow_private,
            services=services,
            transport=transport,
        )
    except TargetRejected as exc:
        return {
            "host": host,
            "owner": target.get("owner"),
            "env": target.get("env"),
            "status": "rejected",
            "error": str(exc),
            "grade": None,
            "findings": [],
        }

    enriched = [
        enrich_finding(
            f,
            host=host,
            owner=target.get("owner"),
            env=target.get("env"),
        )
        for f in findings
    ]
    return {
        "host": host,
        "owner": target.get("owner"),
        "env": target.get("env"),
        "status": "done",
        "error": None,
        "grade": grade,
        "findings": enriched,
    }


async def run_inventory(
    targets: list[dict[str, str | None]],
    state_dir: Path,
    *,
    allow_private: bool = False,
    services: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    probe_mode: ProbeMode | None = None,
) -> dict[str, Any]:
    started = utc_now()
    rid = run_id_from(started)
    mode = probe_mode or resolve_probe_mode()
    prev_state = load_state(state_dir)
    previous = dict(prev_state.get("findings") or {})

    results: list[dict[str, Any]] = []
    scanned_hosts = {str(t["host"]).strip().lower().rstrip(".") for t in targets}
    # Keep prior findings for hosts not in this run — partial sweeps must not
    # look like mass remediation.
    current: dict[str, dict] = {
        fid: dict(f)
        for fid, f in previous.items()
        if str(f.get("host") or "").strip().lower().rstrip(".") not in scanned_hosts
    }
    for t in targets:
        result = await scan_target(
            t,
            allow_private=allow_private,
            services=services,
            transport=transport,
        )
        results.append(result)
        for f in result.get("findings") or []:
            fid = f["finding_id"]
            prev = previous.get(fid) or {}
            row = dict(f)
            row["status"] = "open"
            row["first_seen"] = prev.get("first_seen") or started
            row["last_seen"] = started
            current[fid] = row
            # Keep target payload in sync with stamped fields.
            f.update({
                "status": row["status"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            })

    # Drift only among findings that belong to hosts probed this run.
    prev_scoped = {
        fid: f
        for fid, f in previous.items()
        if str(f.get("host") or "").strip().lower().rstrip(".") in scanned_hosts
    }
    curr_scoped = {
        fid: f
        for fid, f in current.items()
        if str(f.get("host") or "").strip().lower().rstrip(".") in scanned_hosts
    }
    drift = diff_findings(prev_scoped, curr_scoped)
    finished = utc_now()
    fixed_out = []
    for f in drift["fixed"]:
        row = dict(f)
        row["status"] = "fixed"
        row["last_seen"] = finished
        fixed_out.append(row)
    report = {
        "run_id": rid,
        "started_at": started,
        "finished_at": finished,
        "target_count": len(targets),
        "finding_count": len(current),
        "drift": {
            "new_count": len(drift["new"]),
            "fixed_count": len(drift["fixed"]),
            "still_open_count": len(drift["still_open"]),
            "new": drift["new"],
            "fixed": fixed_out,
            "still_open": drift["still_open"],
        },
        "targets": results,
        "phone_home": False,
        "probe_model": "docs/PROBES.md",
        "probe_mode": mode.to_dict(),
    }
    save_state(
        state_dir,
        {
            "findings": current,
            "last_run_at": finished,
            "last_run_id": rid,
        },
    )
    write_run(state_dir, report)
    return report


def render_text(report: dict[str, Any]) -> str:
    d = report["drift"]
    lines = [
        f"aicheck inventory — run {report['run_id']}",
        f"  targets: {report['target_count']}  open findings: {report['finding_count']}",
        f"  drift: +{d['new_count']} new  -{d['fixed_count']} fixed  "
        f"={d['still_open_count']} still open",
        "",
    ]
    if d["new"]:
        lines.append("NEW:")
        for f in d["new"]:
            owner = f.get("owner") or "unassigned"
            env = f.get("env") or "?"
            cve = f", {', '.join(f['cves'])}" if f.get("cves") else ""
            ver = f" v{f['version']}" if f.get("version") else ""
            lines.append(
                f"  [{f['finding_id']}] {f['severity']:8} {f['product']}{ver} "
                f"@ {f['host']} ({owner}/{env}){cve}"
            )
            lines.append(f"             {f['title']}")
        lines.append("")
    if d["fixed"]:
        lines.append("FIXED:")
        for f in d["fixed"]:
            lines.append(
                f"  [{f['finding_id']}] {f['product']} @ {f['host']} — {f['title']}"
            )
        lines.append("")
    if not d["new"] and not d["fixed"]:
        lines.append("No drift since last run." if report["finding_count"] else "Clean — no exposed AI services found.")
        lines.append("")
    mode = report.get("probe_mode") or {}
    lines.append(
        f"Probe class {mode.get('probe_class', 'A')}. "
        f"State under state-dir (latest.json). No telemetry left this host."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="aicheck inventory",
        description=(
            "Local continuous inventory of self-hosted AI services. "
            "Default Class A = GET-only; results stay on disk; no phone-home."
        ),
    )
    ap.add_argument(
        "--targets",
        required=True,
        type=Path,
        help="YAML/JSON/CSV/JSONL targets (host lines, CIDRs, or flow-log-ish exports)",
    )
    ap.add_argument(
        "--state-dir",
        required=True,
        type=Path,
        help="local directory for state.json + runs/ (never uploaded)",
    )
    ap.add_argument(
        "--allow-private",
        action="store_true",
        help="allow RFC1918 / localhost targets (required for internal sweeps)",
    )
    ap.add_argument(
        "--max-hosts",
        type=int,
        default=256,
        help="max hosts expanded from a single CIDR (default 256)",
    )
    ap.add_argument(
        "--no-expand-cidrs",
        action="store_true",
        help="treat CIDR strings as literal hostnames (do not expand)",
    )
    ap.add_argument(
        "--services",
        default="",
        help="optional comma-separated product filter, e.g. ollama,n8n",
    )
    ap.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
    )
    ap.add_argument(
        "--fail-on-new",
        action="store_true",
        help="exit 1 if any NEW findings appeared since the previous run",
    )
    ap.add_argument(
        "--webhook",
        default="",
        help="optional URL to POST drift JSON (your endpoint; never unauth.dev)",
    )
    ap.add_argument(
        "--webhook-on",
        choices=["new", "change", "always"],
        default="new",
        help="when to POST: new findings (default), any drift, or every run",
    )
    ap.add_argument(
        "--webhook-require",
        action="store_true",
        help="exit 2 if the webhook is set and the POST fails",
    )
    ap.add_argument(
        "--deep",
        action="store_true",
        help=(
            "Class B gate: customer-run estate mode (requires "
            "--i-own-these-targets). No deep packs ship yet — traffic still "
            "matches Class A until packs are added."
        ),
    )
    ap.add_argument(
        "--i-own-these-targets",
        action="store_true",
        help="required with --deep: you authorize probing these hosts",
    )
    ap.add_argument(
        "--deep-packs",
        default="",
        help="comma-separated Class B packs (none available yet)",
    )
    args = ap.parse_args(argv)

    try:
        targets = load_targets(
            args.targets,
            max_hosts=args.max_hosts,
            expand_cidrs=not args.no_expand_cidrs,
        )
    except (OSError, TargetLoadError, json.JSONDecodeError, ValueError) as exc:
        print(f"targets error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("targets error: empty list", file=sys.stderr)
        return 2

    packs = [s.strip() for s in args.deep_packs.split(",") if s.strip()]
    try:
        probe_mode = resolve_probe_mode(
            deep=args.deep,
            i_own_these_targets=args.i_own_these_targets,
            deep_packs=packs,
        )
    except ProbeClassError as exc:
        print(f"probe class error: {exc}", file=sys.stderr)
        return 2

    services = [s.strip() for s in args.services.split(",") if s.strip()] or None
    report = asyncio.run(
        run_inventory(
            targets,
            args.state_dir,
            allow_private=args.allow_private,
            services=services,
            probe_mode=probe_mode,
        )
    )

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report), end="")

    if args.webhook:
        try:
            result = post_webhook(args.webhook, report, on=args.webhook_on)
            if result and args.format == "text":
                print(
                    f"Webhook OK (HTTP {result['status_code']}, on={result['on']}).",
                    file=sys.stderr,
                )
            elif result is None and args.format == "text":
                print(f"Webhook skipped (webhook-on={args.webhook_on}).", file=sys.stderr)
        except WebhookError as exc:
            print(f"webhook error: {exc}", file=sys.stderr)
            if args.webhook_require:
                return 2

    if args.fail_on_new and report["drift"]["new_count"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
