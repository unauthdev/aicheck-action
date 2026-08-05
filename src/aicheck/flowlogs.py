"""Passive shadow-AI discovery from VPC flow telemetry.

Reads flow-log files (AWS VPC Flow Logs text, plain or .gz, or generic JSONL
flow records) and attributes AI-service candidates to internal destination
hosts — offline analysis only. This module never opens a socket: the only
traffic involved was observed by someone else's flow collector.

Design doc: docs/flow-logs.md. Honesty contract: every row this module
produces is flow-attributed and content-unverified; generic web ports are
never product-attributed (the design-partner lesson — Attu on :3000/:8000 is
indistinguishable from any other web app in flow data).
"""

from __future__ import annotations

import gzip
import inspect
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .recon import DATA_PLANE_PORTS

# Scanner-noise thresholds: internet scanners (Censys/Shodan-class) knock with
# bare SYN probes of ~40-60B and at most a packet or two — no payload, no
# session. A flow under BOTH bounds is probe noise, not usage.
NOISE_MAX_BYTES = 200
NOISE_MAX_PACKETS = 2

# Seed list of internet-scanner networks. Deliberately small and shippable;
# users extend it with --scanner-networks (comma-separated CIDRs).
SCANNER_NETWORKS_SEED: dict[str, tuple[str, ...]] = {
    "censys": (
        "162.142.125.0/24",
        "167.94.138.0/24",
        "167.94.145.0/24",
        "167.94.146.0/24",
        "205.210.31.0/24",
    ),
    "shodan": (
        "198.20.69.0/24",
        "198.20.87.0/24",
        "198.20.99.0/24",
    ),
}

# Attribution tiers — the exact labels carried in report rows. Port evidence
# alone makes a candidate; real sessions above the noise threshold corroborate.
TIER_PORT_ATTRIBUTED = "port-attributed candidate"
TIER_FLOW_CORROBORATED = "flow-shape corroborated"

# Verification states (set by inventory: passive-only run vs merged sweep).
VERIFICATION_NOT_PROBED = "unverified — host not probed"
VERIFICATION_CONFIRMED = "probe-verified"
VERIFICATION_NOT_CONFIRMED = "unverified — probe did not confirm"

# Exact honesty strings (tests pin these; docs quote them).
SCANNER_OBSERVATION = "already internet-scanned / likely in public indexes"
ATTU_HINT = "possible Attu UI — verify with a probe"

# Ports where an ACCEPTED flow to the destination is meaningful product
# evidence. Data-plane entries come from recon's Class B topology (single
# source of truth — 19530/6334/50051); the rest are ports distinctive enough
# that traffic implies the product. Generic web ports (80/443/3000/8000/8080)
# are deliberately ABSENT — flow logs cannot attribute them.
AI_PORTS: dict[int, tuple[str, str]] = {
    **{port: (product, "data-plane") for port, product in DATA_PLANE_PORTS.items()},
    9091: ("milvus", "management"),
    6333: ("qdrant", "management"),
    11434: ("ollama", "api"),
    5678: ("n8n", "web"),
    8188: ("comfyui", "web"),
    8265: ("ray", "dashboard"),
    8888: ("jupyter", "web"),
    7860: ("gradio/langflow", "web"),
    3001: ("anythingllm", "web"),
    5001: ("dify", "api"),
    18789: ("openclaw", "gateway"),
    5540: ("redisinsight", "web"),
    8001: ("redisinsight", "web"),
}

# Tracked (accept counts only) to power the Attu hint: a host with BOTH a
# Milvus flow-candidate (:9091 or :19530) AND web flows on Attu's UI ports
# earns a hint — never a finding.
ATTU_WEB_PORTS: tuple[int, ...] = (3000, 8000)
ATTU_BACKEND_PORTS: tuple[int, ...] = (9091, 19530)

FMT_AWS = "aws-vpc-flow-text"
FMT_JSONL = "jsonl"

_PRODUCT_DISPLAY = {
    "milvus": "Milvus",
    "qdrant": "Qdrant",
    "weaviate": "Weaviate",
    "ollama": "Ollama",
    "n8n": "n8n",
    "comfyui": "ComfyUI",
    "ray": "Ray",
    "jupyter": "Jupyter",
    "gradio/langflow": "Gradio/Langflow",
    "anythingllm": "AnythingLLM",
    "dify": "Dify",
    "openclaw": "OpenClaw",
    "redisinsight": "RedisInsight",
}


class FlowLogError(ValueError):
    """Unreadable or unrecognized flow-log input."""


@dataclass
class Flow:
    """One normalized flow record. bytes/packets/start/end may be None when
    the export omits them (a flow we cannot prove tiny is NOT noise)."""

    src: str
    dst: str
    dst_port: int
    packets: int | None
    bytes: int | None
    action: str
    start: float | None
    end: float | None


@dataclass
class ParseStats:
    lines_total: int = 0
    lines_malformed: int = 0
    flows_rejected_action: int = 0
    format: str = ""


@dataclass
class PortAgg:
    accepts: int = 0
    real: int = 0
    noise: int = 0
    byte_count: int = 0
    scanner_hits: int = 0
    scanner_sources: set[str] = field(default_factory=set)
    start: float | None = None
    end: float | None = None

    def add(self, flow: Flow, scanner: str | None) -> None:
        self.accepts += 1
        self.byte_count += flow.bytes or 0
        if is_noise(flow):
            self.noise += 1
        else:
            self.real += 1
        if scanner:
            self.scanner_hits += 1
            self.scanner_sources.add(scanner)
        if flow.start is not None:
            self.start = flow.start if self.start is None else min(self.start, flow.start)
        if flow.end is not None:
            self.end = flow.end if self.end is None else max(self.end, flow.end)


def is_noise(flow: Flow) -> bool:
    """SYN-only knock: tiny payload AND at most a couple of packets. A flow
    missing byte/packet counts cannot be proven tiny → not noise."""
    return (
        flow.bytes is not None
        and flow.bytes < NOISE_MAX_BYTES
        and flow.packets is not None
        and flow.packets <= NOISE_MAX_PACKETS
    )


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _is_number(value: str) -> bool:
    try:
        float(value)
        return True
    except ValueError:
        return False


def _detect_format(line: str) -> str:
    if line.startswith("{"):
        return FMT_JSONL
    parts = line.split()
    # AWS v2: version account-id interface-id srcaddr dstaddr srcport dstport
    # protocol packets bytes start end action log-status (later versions append
    # fields — accept >= 14).
    if (
        len(parts) >= 14
        and parts[0].isdigit()
        and _is_number(parts[10])
        and parts[12] in ("ACCEPT", "REJECT")
    ):
        return FMT_AWS
    raise FlowLogError(
        "unrecognized flow-log format: expected AWS VPC Flow Logs text "
        "(space-separated v2+ fields) or generic JSONL flow records — "
        "see docs/flow-logs.md"
    )


def _opt_int(value: str) -> int | None:
    return None if value == "-" else int(value)


def _opt_float(value: str) -> float | None:
    return None if value == "-" else float(value)


def _parse_aws(line: str) -> Flow:
    parts = line.split()
    if len(parts) < 14:
        raise ValueError(f"AWS flow line needs >= 14 fields, got {len(parts)}")
    dst = parts[4]
    dst_port = _opt_int(parts[6])
    if dst == "-" or dst_port is None:
        raise ValueError("missing dstaddr/dstport")
    return Flow(
        src=parts[3],
        dst=dst,
        dst_port=dst_port,
        packets=_opt_int(parts[8]),
        bytes=_opt_int(parts[9]),
        action=parts[12],
        start=_opt_float(parts[10]),
        end=_opt_float(parts[11]),
    )


def _first(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return None


def _parse_jsonl(line: str) -> Flow:
    obj = json.loads(line)
    if not isinstance(obj, dict):
        raise ValueError("JSONL flow line must be an object")
    src = _first(obj, "src_ip", "srcaddr")
    dst = _first(obj, "dst_ip", "dstaddr")
    dst_port = _first(obj, "dst_port", "dstport")
    if dst is None or dst_port is None:
        raise ValueError("missing dst_ip/dst_port")
    packets = _first(obj, "packets")
    byte_count = _first(obj, "bytes")
    start = _first(obj, "start", "ts")
    end = _first(obj, "end") or start
    return Flow(
        src=str(src or ""),
        dst=str(dst),
        dst_port=int(dst_port),
        packets=int(packets) if packets is not None else None,
        bytes=int(byte_count) if byte_count is not None else None,
        action=str(_first(obj, "action") or "ACCEPT").upper(),
        start=float(start) if start is not None else None,
        end=float(end) if end is not None else None,
    )


def iter_flows(path: Path, stats: ParseStats) -> Iterator[Flow]:
    """Stream normalized flows from `path` (plain or .gz). The format is
    detected from the first non-blank line; anything else raises FlowLogError.
    Malformed lines are skipped (counted in stats.lines_malformed), never
    fatal — flow logs are GBs and one bad line must not sink the run."""
    opener = gzip.open if str(path).endswith(".gz") else open
    fmt = ""
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            stats.lines_total += 1
            if not fmt:
                fmt = _detect_format(line)  # raises FlowLogError
                stats.format = fmt
            try:
                flow = _parse_aws(line) if fmt == FMT_AWS else _parse_jsonl(line)
            except (ValueError, KeyError, TypeError):
                stats.lines_malformed += 1
                continue
            yield flow


def _scanner_networks(
    extra: list[str] | tuple[str, ...] = (),
) -> list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    nets: list[tuple[str, Any]] = []
    for label, cidrs in SCANNER_NETWORKS_SEED.items():
        for cidr in cidrs:
            nets.append((label, ipaddress.ip_network(cidr)))
    for cidr in extra:
        try:
            nets.append(("user", ipaddress.ip_network(cidr, strict=False)))
        except ValueError as exc:
            raise FlowLogError(f"bad --scanner-networks CIDR {cidr!r}: {exc}") from exc
    return nets


def _scanner_source(src: str, nets: list[tuple[str, Any]]) -> str | None:
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return None
    for label, net in nets:
        if ip in net:
            return label
    return None


def _evidence_text(accepts: int, byte_count: int, start: float | None, end: float | None) -> str:
    win = (
        f"{_iso(start)}→{_iso(end)}"
        if start is not None and end is not None
        else "unknown"
    )
    return (
        f"flow-attributed — content unverified "
        f"({accepts} accepted flows, {byte_count / 1_000_000:.1f} MB, window {win})"
    )


def _host_sort_key(host: str) -> tuple[int, Any]:
    try:
        return (0, int(ipaddress.ip_address(host)))
    except ValueError:
        return (1, host)


def analyze(
    path: Path,
    *,
    extra_networks: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Parse + aggregate + attribute. Returns the `passive` report section
    (additive within inventory report schema v1)."""
    nets = _scanner_networks(extra_networks)
    stats = ParseStats()
    ai: dict[str, dict[int, PortAgg]] = {}
    web: dict[str, dict[int, PortAgg]] = {}
    win_start: float | None = None
    win_end: float | None = None

    for flow in iter_flows(path, stats):
        if flow.action != "ACCEPT":
            stats.flows_rejected_action += 1
            continue
        if flow.start is not None:
            win_start = flow.start if win_start is None else min(win_start, flow.start)
        if flow.end is not None:
            win_end = flow.end if win_end is None else max(win_end, flow.end)
        if flow.dst_port in AI_PORTS:
            scanner = _scanner_source(flow.src, nets)
            ai.setdefault(flow.dst, {}).setdefault(flow.dst_port, PortAgg()).add(flow, scanner)
        elif flow.dst_port in ATTU_WEB_PORTS:
            web.setdefault(flow.dst, {}).setdefault(flow.dst_port, PortAgg()).add(flow, None)

    hosts: list[dict[str, Any]] = []
    for host in sorted(ai, key=_host_sort_key):
        rows: list[dict[str, Any]] = []
        host_scanner_sources: set[str] = set()
        for port in sorted(ai[host]):
            agg = ai[host][port]
            product, role = AI_PORTS[port]
            host_scanner_sources |= agg.scanner_sources
            rows.append(
                {
                    "host": host,
                    "product": product,
                    "port": port,
                    "role": role,
                    "tier": (
                        TIER_FLOW_CORROBORATED if agg.real else TIER_PORT_ATTRIBUTED
                    ),
                    "title": (
                        f"{_PRODUCT_DISPLAY.get(product, product)} candidate — "
                        f"port evidence ({role} :{port})"
                    ),
                    "accepted_flows": agg.accepts,
                    "real_sessions": agg.real,
                    "noise_flows": agg.noise,
                    "bytes": agg.byte_count,
                    "window": {"start": _iso(agg.start), "end": _iso(agg.end)},
                    "evidence": _evidence_text(
                        agg.accepts, agg.byte_count, agg.start, agg.end
                    ),
                    "scanner_observation": (
                        SCANNER_OBSERVATION if agg.scanner_hits else None
                    ),
                    "scanner_sources": sorted(agg.scanner_sources),
                    "verification": VERIFICATION_NOT_PROBED,
                }
            )
        hints: list[str] = []
        host_web = web.get(host) or {}
        if (
            any(p in ai[host] for p in ATTU_BACKEND_PORTS)
            and any((host_web.get(p) and host_web[p].accepts) for p in ATTU_WEB_PORTS)
        ):
            # A hint, not a finding: generic web ports stay unattributable.
            hints.append(ATTU_HINT)
        observations = [SCANNER_OBSERVATION] if host_scanner_sources else []
        hosts.append(
            {
                "host": host,
                "rows": rows,
                "observations": observations,
                "hints": hints,
            }
        )

    return {
        "source": str(path),
        "format": stats.format,
        "lines_total": stats.lines_total,
        "lines_malformed": stats.lines_malformed,
        "flows_rejected_action": stats.flows_rejected_action,
        "window": {"start": _iso(win_start), "end": _iso(win_end)},
        "scanner_networks": sorted({str(net) for _label, net in nets}),
        "hosts": hosts,
        # Feeds straight back as --targets input (targets JSONL v1).
        "discovered_targets": [
            {"host": h["host"], "owner": None, "env": None} for h in hosts
        ],
        "targets_path": None,
    }


def targets_to_jsonl(targets: list[dict[str, Any]]) -> str:
    """Discovered targets in targets JSONL v1 shape (docs/schemas/
    targets-jsonl-v1.md) — round-trips through inventory_targets.load_targets."""
    lines = [json.dumps({"host": str(t["host"])}, sort_keys=True) for t in targets]
    return "\n".join(lines) + ("\n" if lines else "")


def _product_variants(product_id: str) -> set[str]:
    return {p.strip() for p in product_id.lower().split("/") if p.strip()}


def _product_matches(product_id: str, observed: set[str]) -> bool:
    for variant in _product_variants(product_id):
        for prod in observed:
            if variant == prod or variant in prod or prod in variant:
                return True
    return False


def merge_verification(passive: dict[str, Any], report: dict[str, Any]) -> None:
    """Upgrade passive rows after a --verify sweep (in place): a row becomes
    'probe-verified' only when the Class A engine fingerprinted the same
    product on the same host. Unconfirmed rows stay honestly labeled."""
    probed: dict[str, set[str]] = {}
    for t in report.get("targets") or []:
        if t.get("status") != "done":
            continue
        products = set()
        for f in (t.get("findings") or []) + (t.get("observations") or []):
            prod = str(f.get("product") or "").strip().lower()
            if prod:
                products.add(prod)
        probed[_norm_host(str(t.get("host") or ""))] = products
    for host in passive.get("hosts") or []:
        products = probed.get(_norm_host(str(host.get("host") or "")))
        for row in host.get("rows") or []:
            if products is None:
                row["verification"] = VERIFICATION_NOT_PROBED
            elif _product_matches(str(row.get("product") or ""), products):
                row["verification"] = VERIFICATION_CONFIRMED
            else:
                row["verification"] = VERIFICATION_NOT_CONFIRMED


def is_generator(obj: Any) -> bool:
    """Exposed for tests: iter_flows must stream, never materialize."""
    return inspect.isgenerator(obj)
