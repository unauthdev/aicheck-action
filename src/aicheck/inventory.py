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
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

from . import scan
from .inventory_findings import enrich_finding
from .ssrf import TargetRejected

_HOST_LINE = re.compile(
    r"^(?P<host>\S+)(?:\s+(?P<owner>\S+))?(?:\s+(?P<env>\S+))?$"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_id_from(ts: str) -> str:
    return ts.replace(":", "").replace("-", "")


def load_targets(path: Path) -> list[dict[str, str | None]]:
    """Load targets from YAML/JSON ({targets: [...]}) or plain host lines.

    Each target: {host, owner?, env?}. Plain text: `host [owner] [env]`.
    """
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        data = json.loads(text)
    elif path.suffix in {".yaml", ".yml"} or stripped.startswith("targets:"):
        data = yaml.safe_load(text)
    else:
        data = None
        targets: list[dict[str, str | None]] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = _HOST_LINE.match(line)
            if not m:
                raise ValueError(f"bad targets line: {raw!r}")
            targets.append(
                {
                    "host": m.group("host"),
                    "owner": m.group("owner"),
                    "env": m.group("env"),
                }
            )
        return targets

    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("targets") or []
    else:
        raise ValueError("targets file must be a list or {targets: [...]}")

    out: list[dict[str, str | None]] = []
    for row in rows:
        if isinstance(row, str):
            out.append({"host": row, "owner": None, "env": None})
            continue
        if not isinstance(row, dict) or not row.get("host"):
            raise ValueError(f"bad target row: {row!r}")
        out.append(
            {
                "host": str(row["host"]),
                "owner": (str(row["owner"]) if row.get("owner") is not None else None),
                "env": (str(row["env"]) if row.get("env") is not None else None),
            }
        )
    return out


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
) -> dict[str, Any]:
    started = utc_now()
    rid = run_id_from(started)
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
    lines.append(f"State written under state-dir (latest.json). No telemetry left this host.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m aicheck.inventory",
        description=(
            "Local continuous inventory of self-hosted AI services. "
            "GET-only probes; results stay on disk; no phone-home."
        ),
    )
    ap.add_argument(
        "--targets",
        required=True,
        type=Path,
        help="YAML/JSON targets file or plain host lines (host [owner] [env])",
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
    args = ap.parse_args(argv)

    try:
        targets = load_targets(args.targets)
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"targets error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("targets error: empty list", file=sys.stderr)
        return 2

    services = [s.strip() for s in args.services.split(",") if s.strip()] or None
    report = asyncio.run(
        run_inventory(
            targets,
            args.state_dir,
            allow_private=args.allow_private,
            services=services,
        )
    )

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report), end="")

    if args.fail_on_new and report["drift"]["new_count"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
