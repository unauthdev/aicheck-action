"""Target loading for inventory: hosts, CIDRs, CSV, flow-log-ish JSONL."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

import yaml

_HOST_LINE = re.compile(
    r"^(?P<host>\S+)(?:\s+(?P<owner>\S+))?(?:\s+(?P<env>\S+))?$"
)

# Common keys in VPC flow / export dumps → host
_IP_KEYS = (
    "host", "ip", "addr", "address", "dstaddr", "srcaddr",
    "destination_ip", "source_ip", "private_ip", "public_ip",
)


class TargetLoadError(ValueError):
    pass


def _row(host: str, owner: str | None = None, env: str | None = None) -> dict[str, str | None]:
    return {"host": host, "owner": owner, "env": env}


def looks_like_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def expand_cidr(cidr: str, *, max_hosts: int) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    # Skip network/broadcast for IPv4 if usable hosts exist
    hosts = list(net.hosts()) if net.version == 4 and net.num_addresses > 2 else list(net)
    if len(hosts) > max_hosts:
        raise TargetLoadError(
            f"CIDR {cidr} expands to {len(hosts)} hosts; "
            f"max is {max_hosts} (pass --max-hosts to raise, or list hosts explicitly)"
        )
    return [str(h) for h in hosts]


def _expand_host_field(
    host: str,
    *,
    owner: str | None,
    env: str | None,
    max_hosts: int,
    expand_cidrs: bool,
) -> list[dict[str, str | None]]:
    host = host.strip()
    if expand_cidrs and looks_like_cidr(host):
        return [_row(h, owner, env) for h in expand_cidr(host, max_hosts=max_hosts)]
    return [_row(host, owner, env)]


def _from_mapping(row: dict[str, Any], *, max_hosts: int, expand_cidrs: bool) -> list[dict[str, str | None]]:
    host = None
    for key in _IP_KEYS:
        if row.get(key) not in (None, ""):
            host = str(row[key])
            break
    if not host and row.get("cidr"):
        host = str(row["cidr"])
    if not host:
        raise TargetLoadError(f"no host/ip in row: {row!r}")
    owner = row.get("owner")
    env = row.get("env") or row.get("environment")
    return _expand_host_field(
        host,
        owner=str(owner) if owner is not None else None,
        env=str(env) if env is not None else None,
        max_hosts=max_hosts,
        expand_cidrs=expand_cidrs,
    )


def load_targets(
    path: Path,
    *,
    max_hosts: int = 256,
    expand_cidrs: bool = True,
) -> list[dict[str, str | None]]:
    """Load targets from YAML/JSON, plain lines, CSV, or JSONL.

    CIDR values in `host` (or `cidr`) expand to individual IPs when
    expand_cidrs is true, capped by max_hosts per CIDR.
    """
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    stripped = text.lstrip()

    if suffix == ".csv":
        return _load_csv(path, max_hosts=max_hosts, expand_cidrs=expand_cidrs)

    if suffix == ".jsonl":
        return _load_jsonl(text, max_hosts=max_hosts, expand_cidrs=expand_cidrs)

    # JSONL heuristic: many `{...}` lines (flow-log style exports)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if (
        len(lines) >= 1
        and all(ln.startswith("{") and ln.endswith("}") for ln in lines[:20])
        and not stripped.startswith("[")
        and "targets:" not in stripped[:80]
    ):
        return _load_jsonl(text, max_hosts=max_hosts, expand_cidrs=expand_cidrs)

    if stripped.startswith("{") or stripped.startswith("["):
        data = json.loads(text)
    elif suffix in {".yaml", ".yml"} or stripped.startswith("targets:"):
        data = yaml.safe_load(text)
    else:
        return _load_plain(text, max_hosts=max_hosts, expand_cidrs=expand_cidrs)

    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("targets") or data.get("hosts") or data.get("items") or []
    else:
        raise TargetLoadError("targets file must be a list or {targets: [...]}")

    out: list[dict[str, str | None]] = []
    for row in rows:
        if isinstance(row, str):
            out.extend(
                _expand_host_field(
                    row, owner=None, env=None,
                    max_hosts=max_hosts, expand_cidrs=expand_cidrs,
                )
            )
            continue
        if not isinstance(row, dict):
            raise TargetLoadError(f"bad target row: {row!r}")
        out.extend(_from_mapping(row, max_hosts=max_hosts, expand_cidrs=expand_cidrs))
    return _dedupe(out)


def _load_plain(text: str, *, max_hosts: int, expand_cidrs: bool) -> list[dict[str, str | None]]:
    out: list[dict[str, str | None]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _HOST_LINE.match(line)
        if not m:
            raise TargetLoadError(f"bad targets line: {raw!r}")
        out.extend(
            _expand_host_field(
                m.group("host"),
                owner=m.group("owner"),
                env=m.group("env"),
                max_hosts=max_hosts,
                expand_cidrs=expand_cidrs,
            )
        )
    return _dedupe(out)


def _load_csv(path: Path, *, max_hosts: int, expand_cidrs: bool) -> list[dict[str, str | None]]:
    out: list[dict[str, str | None]] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise TargetLoadError("CSV has no header row")
        for row in reader:
            # normalize keys
            norm = {((k or "").strip().lower()): (v.strip() if isinstance(v, str) else v)
                    for k, v in row.items()}
            out.extend(_from_mapping(norm, max_hosts=max_hosts, expand_cidrs=expand_cidrs))
    return _dedupe(out)


def _load_jsonl(text: str, *, max_hosts: int, expand_cidrs: bool) -> list[dict[str, str | None]]:
    out: list[dict[str, str | None]] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TargetLoadError(f"bad JSONL line {i}: {exc}") from exc
        if not isinstance(row, dict):
            raise TargetLoadError(f"JSONL line {i} must be an object")
        out.extend(_from_mapping(row, max_hosts=max_hosts, expand_cidrs=expand_cidrs))
    return _dedupe(out)


def _dedupe(rows: list[dict[str, str | None]]) -> list[dict[str, str | None]]:
    seen: set[str] = set()
    out: list[dict[str, str | None]] = []
    for r in rows:
        key = str(r["host"]).strip().lower().rstrip(".")
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out
