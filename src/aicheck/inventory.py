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
import os
import secrets
import sys
import time
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

# Frozen output schema: additive-only within v1; renames/removals bump this.
# See docs/schemas/inventory-report-v1.md.
SCHEMA_VERSION = 1

# Per-host sweep concurrency bound (asyncio semaphore).
SWEEP_CONCURRENCY = 8

# A sibling run's lock file younger than this is honored; older = stale.
LOCK_MAX_AGE_S = 3600.0

# Default cap on total expanded targets per run (--max-total-targets).
MAX_TOTAL_TARGETS = 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_id_from(ts: str) -> str:
    return ts.replace(":", "").replace("-", "")


def _norm_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _atomic_write_text(path: Path, text: str) -> None:
    """Write via temp file + os.replace so a crash never leaves a partial file."""
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def load_state(state_dir: Path) -> dict[str, Any]:
    clean = {
        "schema_version": SCHEMA_VERSION,
        "findings": {},
        "last_run_at": None,
        "last_run_id": None,
    }
    path = state_dir / "state.json"
    if not path.is_file():
        return clean
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(state, dict)
            or state.get("schema_version") != SCHEMA_VERSION
            or not isinstance(state.get("findings"), dict)
        ):
            raise ValueError("missing/incompatible schema")
    except (OSError, ValueError) as exc:
        # Corrupt or pre-versioning state: quarantine, never crash.
        base = f"{path.name}.corrupt-{utc_now().replace(':', '').replace('-', '')}"
        aside = path.with_name(base)
        n = 1
        while aside.exists():  # second-resolution ts can collide
            n += 1
            aside = path.with_name(f"{base}-{n}")
        try:
            os.replace(path, aside)
        except OSError:
            aside = path
        print(
            f"state warning: {path} unreadable/incompatible ({exc}) — "
            f"moved to {aside.name}; starting clean",
            file=sys.stderr,
        )
        return clean
    return state


def save_state(state_dir: Path, state: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    out = dict(state)
    out["schema_version"] = SCHEMA_VERSION
    _atomic_write_text(
        state_dir / "state.json",
        json.dumps(out, indent=2, sort_keys=True) + "\n",
    )


def write_run(state_dir: Path, report: dict[str, Any]) -> Path:
    runs = state_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    path = runs / f"{report['run_id']}.json"
    _atomic_write_text(path, json.dumps(report, indent=2) + "\n")
    _atomic_write_text(
        state_dir / "latest.json", json.dumps(report, indent=2) + "\n"
    )
    return path


class InventoryLockError(RuntimeError):
    """A sibling run holds a fresh lock on this state dir."""


def acquire_lock(state_dir: Path, *, force: bool = False) -> Path:
    """Advisory lock file (O_CREAT|O_EXCL). Fresh sibling lock (< 1h)
    refuses the run; stale or unparseable locks are tolerated (taken over).
    Portable: no fcntl, works anywhere O_EXCL does."""
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / "inventory.lock"
    if path.exists():
        fresh = False
        age_s: float | None = None
        try:
            epoch = float(json.loads(path.read_text(encoding="utf-8"))["epoch"])
            age_s = time.time() - epoch
            fresh = age_s < LOCK_MAX_AGE_S
        except (OSError, ValueError, KeyError, TypeError):
            fresh = False  # unparseable lock → treat as stale
        if fresh and not force:
            raise InventoryLockError(
                f"another inventory run holds {path} "
                f"(started {int(age_s or 0)}s ago) — wait for it to finish, "
                "or pass --force to override"
            )
        try:
            path.unlink()
        except OSError:
            pass
    payload = json.dumps(
        {"pid": os.getpid(), "started": utc_now(), "epoch": time.time()}
    )
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        raise InventoryLockError(
            f"another inventory run just took {path} — "
            "wait for it to finish, or pass --force to override"
        ) from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(payload)
    return path


def release_lock(state_dir: Path) -> None:
    try:
        (state_dir / "inventory.lock").unlink()
    except OSError:
        pass


def _finding_changes(prev: dict, curr: dict) -> dict:
    """Drift signals on a stable finding ID: severity and details.version,
    plus details.known_cve_count when either side reports it. Finding IDs
    exclude these fields by design, so a same-exposure/worse-version move
    would otherwise show zero drift."""
    changes: dict[str, dict] = {}
    if prev.get("severity") != curr.get("severity"):
        changes["severity"] = {"was": prev.get("severity"), "now": curr.get("severity")}
    pd = prev.get("details") or {}
    cd = curr.get("details") or {}
    if pd.get("version") != cd.get("version"):
        changes["version"] = {"was": pd.get("version"), "now": cd.get("version")}
    if "known_cve_count" in pd or "known_cve_count" in cd:
        if pd.get("known_cve_count") != cd.get("known_cve_count"):
            changes["known_cve_count"] = {
                "was": pd.get("known_cve_count"), "now": cd.get("known_cve_count")
            }
    return changes


def diff_findings(
    previous: dict[str, dict], current: dict[str, dict]
) -> dict[str, list[dict]]:
    prev_ids = set(previous)
    curr_ids = set(current)
    new_ids = sorted(curr_ids - prev_ids)
    fixed_ids = sorted(prev_ids - curr_ids)
    open_ids: list[str] = []
    changed: list[dict] = []
    for i in sorted(curr_ids & prev_ids):
        changes = _finding_changes(previous[i], current[i])
        if changes:
            row = dict(current[i])
            row["changes"] = changes
            changed.append(row)
        else:
            open_ids.append(i)
    return {
        "new": [current[i] for i in new_ids],
        "fixed": [previous[i] for i in fixed_ids],
        "still_open": [current[i] for i in open_ids],
        "changed": changed,
    }


async def scan_target(
    target: dict[str, str | None],
    *,
    allow_private: bool,
    services: list[str] | None,
    transport: httpx.AsyncBaseTransport | None,
) -> dict[str, Any]:
    host = str(target["host"])
    row_base = {"host": host, "owner": target.get("owner"), "env": target.get("env")}
    try:
        grade, findings, coverage = await scan.scan(
            host,
            allow_private=allow_private,
            services=services,
            transport=transport,
        )
    except TargetRejected as exc:
        return {
            **row_base,
            "status": "rejected",
            "error": str(exc),
            "grade": None,
            "coverage": None,
            "findings": [],
        }
    except Exception as exc:
        # One bad host must never kill the run — record and move on.
        return {
            **row_base,
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "grade": None,
            "coverage": None,
            "findings": [],
        }

    # A host that answered nothing is not "clean" — an A grade from zero
    # answered probes is a filtered/dead host, not an all-clear.
    status = "done" if coverage["probes_answered"] > 0 else "unreachable"
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
        **row_base,
        "status": status,
        "error": None,
        "grade": grade,
        "coverage": coverage,
        "findings": enriched,
    }


async def _run_sweep(
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
    # run_id has second resolution — suffix on collision keeps it sortable
    # (timestamp prefix first) and unique per run file.
    if (state_dir / "runs" / f"{rid}.json").exists():
        rid = f"{rid}-{secrets.token_hex(2)}"
    mode = probe_mode or resolve_probe_mode()
    prev_state = load_state(state_dir)
    previous = dict(prev_state.get("findings") or {})

    # Bounded-concurrency sweep; asyncio.gather preserves input order, so
    # per-target status rows stay deterministic.
    sem = asyncio.Semaphore(SWEEP_CONCURRENCY)

    async def _one(t: dict[str, str | None]) -> dict[str, Any]:
        async with sem:
            return await scan_target(
                t,
                allow_private=allow_private,
                services=services,
                transport=transport,
            )

    results = list(await asyncio.gather(*(_one(t) for t in targets)))
    current: dict[str, dict] = {}
    for result in results:
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

    # Carry over prior findings for hosts not successfully probed this run
    # (out of sweep, unreachable, rejected, error) — a dead host must not
    # look like mass remediation.
    probed_hosts = {
        _norm_host(str(r["host"])) for r in results if r.get("status") == "done"
    }
    for fid, f in previous.items():
        if _norm_host(str(f.get("host") or "")) not in probed_hosts:
            current[fid] = dict(f)

    # Drift only among findings that belong to hosts successfully probed this
    # run — unreachable/error hosts appear in neither `new` nor `fixed`.
    prev_scoped = {
        fid: f
        for fid, f in previous.items()
        if _norm_host(str(f.get("host") or "")) in probed_hosts
    }
    curr_scoped = {
        fid: f
        for fid, f in current.items()
        if _norm_host(str(f.get("host") or "")) in probed_hosts
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
        "schema_version": SCHEMA_VERSION,
        "run_id": rid,
        "started_at": started,
        "finished_at": finished,
        "target_count": len(targets),
        "finding_count": len(current),
        "services_filter": services,
        "drift": {
            "new_count": len(drift["new"]),
            "fixed_count": len(drift["fixed"]),
            "changed_count": len(drift["changed"]),
            "still_open_count": len(drift["still_open"]),
            "new": drift["new"],
            "fixed": fixed_out,
            "changed": drift["changed"],
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


async def run_inventory(
    targets: list[dict[str, str | None]],
    state_dir: Path,
    *,
    allow_private: bool = False,
    services: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    probe_mode: ProbeMode | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Sweep + drift under an advisory lock on the state dir (released on
    exit, stale locks tolerated). Raises InventoryLockError if a sibling
    run holds a fresh lock and force is False."""
    acquire_lock(state_dir, force=force)
    try:
        return await _run_sweep(
            targets,
            state_dir,
            allow_private=allow_private,
            services=services,
            transport=transport,
            probe_mode=probe_mode,
        )
    finally:
        release_lock(state_dir)


def render_text(report: dict[str, Any]) -> str:
    d = report["drift"]
    lines = [
        f"aicheck inventory — run {report['run_id']}",
        f"  targets: {report['target_count']}  open findings: {report['finding_count']}",
        f"  drift: +{d['new_count']} new  -{d['fixed_count']} fixed  "
        f"~{d.get('changed_count', 0)} changed  ={d['still_open_count']} still open",
    ]
    if report.get("services_filter"):
        lines.append(
            f"  note: services filter active ({', '.join(report['services_filter'])}) "
            "— other products were not probed or graded"
        )
    lines.append("")
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
    if d.get("changed"):
        lines.append("CHANGED:")
        for f in d["changed"]:
            bits = ", ".join(
                f"{k}: {v['was']} → {v['now']}"
                for k, v in (f.get("changes") or {}).items()
            )
            lines.append(
                f"  [{f['finding_id']}] {f['product']} @ {f['host']} — {bits}"
            )
        lines.append("")
    if not d["new"] and not d["fixed"] and not d.get("changed"):
        lines.append("No drift since last run." if report["finding_count"] else "Clean — no exposed AI services found.")
        lines.append("")
    not_scanned = [
        t for t in report.get("targets") or [] if t.get("status") != "done"
    ]
    if not_scanned:
        lines.append("TARGETS NOT SCANNED:")
        for t in not_scanned:
            err = f" — {t['error']}" if t.get("error") else ""
            lines.append(f"  {t['host']}: {t.get('status')}{err}")
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
        help=(
            "allow RFC1918 / localhost targets (required for internal sweeps; "
            "requires --i-own-these-targets)"
        ),
    )
    ap.add_argument(
        "--max-hosts",
        type=int,
        default=256,
        help="max hosts expanded from a single CIDR (default 256)",
    )
    ap.add_argument(
        "--max-total-targets",
        type=int,
        default=MAX_TOTAL_TARGETS,
        help=f"max total targets after all sources expand (default {MAX_TOTAL_TARGETS})",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="override a fresh inventory.lock from a sibling run",
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
        "--webhook-secret",
        default="",
        help=(
            "HMAC-sign the exact request body; header X-Aicheck-Signature: "
            "sha256=<hex>. Verify receiver-side with: "
            "hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()"
        ),
    )
    ap.add_argument(
        "--webhook-allow-local",
        action="store_true",
        help=(
            "allow webhook URLs resolving to loopback/link-local "
            "(169.254.0.0/16, cloud metadata) — blocked by default"
        ),
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
    if len(targets) > args.max_total_targets:
        print(
            f"targets error: {len(targets)} targets after expansion exceeds "
            f"--max-total-targets {args.max_total_targets} "
            "(raise the flag, or split the sweep)",
            file=sys.stderr,
        )
        return 2

    if args.allow_private and not args.i_own_these_targets:
        print(
            "probe class error: --allow-private requires "
            "--i-own-these-targets (customer-run estate only; acknowledges "
            "you own / are authorized to probe these internal hosts)",
            file=sys.stderr,
        )
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
    try:
        report = asyncio.run(
            run_inventory(
                targets,
                args.state_dir,
                allow_private=args.allow_private,
                services=services,
                probe_mode=probe_mode,
                force=args.force,
            )
        )
    except InventoryLockError as exc:
        print(f"lock error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report), end="")

    if args.webhook:
        try:
            result = post_webhook(
                args.webhook,
                report,
                on=args.webhook_on,
                secret=args.webhook_secret or None,
                allow_local=args.webhook_allow_local,
            )
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
