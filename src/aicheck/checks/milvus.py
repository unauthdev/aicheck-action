"""Milvus :9091 healthz + Attu admin UI — vector database exposed.

Evidence rules (content fingerprints, never port-only):

- Milvus service (:9091 /healthz or /): the response's Server header must
  start with "milvus" (case-insensitive) — Milvus answers
  `Server: Milvus/2.3.4` there, which is product-unique AND carries the
  version. The {"status": "ok"} body ALONE is a generic health shape served
  by countless apps and is never sufficient; it only corroborates the
  header (healthz JSON with a "status" key + Milvus Server header).
- Attu admin UI (root on the shared web ports 8000/3000/80): the body must
  contain BOTH "attu" AND "milvus" (case-insensitive) — Attu's page ships
  `<title>Attu</title>` plus a meta description "best milvus management
  tool". Either word alone is too common to fingerprint on.

Severity: the healthz probe proves the Milvus service is exposed but reads
no data, so it grades like the qdrant/chroma banner-only case (HIGH). The
gRPC data API (:19530) is out of probe scope — severity reflects "service
confirmed exposed, data API presumably reachable on the same host". Attu
is one tier below (MEDIUM): a management console that still needs a Milvus
connection string to reach data.

Finding class: agent-memory (OWASP ASI06) — grades unchanged vs prior severity.

Auth-walled (observation, INFO — never graded): a :9091 probe answering
401/403 whose Server header starts with "milvus" — the SAME product-unique
bar as the exposure fingerprint. A bare 401 on :9091 is NOT evidence.
"""

from __future__ import annotations

import re

from ..models import Finding, ProbeResult
from ..recon import DATA_PLANE_PORTS
from .auth_wall import observation, walled
from .risk_classes import AGENT_MEMORY, with_risk

CHECK_ID = "milvus"
FIX_CARD_ID = "milvus-exposed"

# Class B data-plane pack (docs/deep-pack-data-plane.md): separate finding,
# gated on the Class A fingerprint AND a zero-byte TCP accept on the gRPC
# data-plane port. recon.DATA_PLANE_PORTS owns the probe topology.
DATA_PLANE_CHECK_ID = "milvus-dataplane"
DATA_PLANE_FIX_CARD_ID = "milvus-dataplane-exposed"
DATA_PLANE_PORT = next(p for p, name in DATA_PLANE_PORTS.items() if name == "milvus")

_VERSION_RE = re.compile(r"milvus/(\d+(?:\.\d+)*)", re.IGNORECASE)

# Shared web ports whose root probe Attu can answer (fact keys from
# recon.PROBES, which probes / on 8000, 3000, and 80).
_ATTU_PORTS = (8000, 3000, 80)


def _version_from(server: str) -> str:
    """Server: Milvus/2.3.4 -> "2.3.4" ("" when the header carries none)."""
    m = _VERSION_RE.search(server or "")
    return m.group(1) if m else ""


def _service_probe(facts: dict[str, ProbeResult]) -> ProbeResult | None:
    """First 200 from the Milvus healthz probes — never truthiness of the
    dataclass itself (every probed key exists in facts, including errors)."""
    for key in ("9091:/healthz", "9091:/"):
        p = facts.get(key)
        if p is not None and p.ok:
            return p
    return None


def _is_milvus_service(p: ProbeResult) -> bool:
    """The Server header must confirm Milvus. A healthz JSON body with a
    "status" key corroborates it, but the body ALONE ({"status": "ok"} is a
    generic health shape served by countless apps) is never sufficient."""
    header_says_milvus = (p.server or "").lower().startswith("milvus")
    j = p.json()
    health_shape = isinstance(j, dict) and "status" in j
    return header_says_milvus or (health_shape and header_says_milvus)


def _walled_marker(facts: dict[str, ProbeResult]) -> ProbeResult | None:
    """Auth-walled Milvus: a :9091 probe answered 401/403 with the Milvus
    Server header — the SAME product-unique bar as the exposure fingerprint.
    A bare 401 on :9091 is NOT evidence."""
    return next(
        (
            p
            for key in ("9091:/healthz", "9091:/")
            if (p := facts.get(key)) is not None
            and walled(p)
            and (p.server or "").lower().startswith("milvus")
        ),
        None,
    )


def _product_fingerprinted(facts: dict[str, ProbeResult]) -> bool:
    """Class A leg of the data-plane conjunction: the Milvus service itself
    answered (exposure fingerprint) or its walled response identified it.
    Attu alone does NOT qualify — the UI can attach to a Milvus on another
    host, so it never proves the data plane behind THIS host."""
    svc = _service_probe(facts)
    return (svc is not None and _is_milvus_service(svc)) or _walled_marker(facts) is not None


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    findings: list[Finding] = []

    svc = _service_probe(facts)
    if svc is not None and _is_milvus_service(svc):
        version = _version_from(svc.server)
        version_bit = f"; version {version}" if version else ""
        findings.append(
            Finding(
                check_id=CHECK_ID,
                product="Milvus",
                title="Milvus vector database exposed to the internet",
                severity="HIGH",
                url="http://TARGET:9091/",
                evidence=(
                    f"GET {svc.url} → 200 (Server: {svc.server}{version_bit}) — "
                    "Milvus healthz answers anyone; the gRPC data API (:19530) is "
                    "presumably reachable on the same host, and vector stores like "
                    "this often hold agent memory (OWASP ASI06)"
                ),
                fix_card_id=FIX_CARD_ID,
                details=with_risk({"version": version}, AGENT_MEMORY),
            )
        )
    else:
        # Auth-walled Milvus: the walled response itself identifies the
        # product — same product-unique bar as the exposure fingerprint.
        hit = _walled_marker(facts)
        if hit is not None:
            findings.append(
                observation(
                    check_id=CHECK_ID,
                    product="Milvus",
                    title="Milvus vector database present but auth-walled",
                    url="http://TARGET:9091/",
                    evidence=(
                        f"GET {hit.url} → {hit.status_code} (Server: {hit.server}) — "
                        "the walled response itself identifies Milvus; the service "
                        "is present but demands authentication (present, not graded)"
                    ),
                    fix_card_id=FIX_CARD_ID,
                    details={"version": _version_from(hit.server)},
                )
            )

    for port in _ATTU_PORTS:
        root = facts.get(f"{port}:/")
        if root is None or not root.ok:
            continue
        low = root.body.lower()
        if "attu" in low and "milvus" in low:
            findings.append(
                Finding(
                    check_id=CHECK_ID,
                    product="Milvus",
                    title="Milvus admin UI (Attu) exposed to the internet",
                    severity="MEDIUM",
                    url=f"http://TARGET:{port}/",
                    evidence=(
                        f"GET {root.url} → 200 (Attu admin UI — page carries both "
                        "the Attu title and the Milvus meta description) — the "
                        "console itself needs a Milvus connection string, but its "
                        "exposure confirms a Milvus deployment to attach to"
                    ),
                    fix_card_id=FIX_CARD_ID,
                    details=with_risk({"ui": "attu"}, AGENT_MEMORY),
                )
            )
            break

    return findings


def detect_with_connects(
    facts: dict[str, ProbeResult], connects: dict[int, str]
) -> list[Finding]:
    """Class B entrypoint (data-plane pack): detect(facts) plus a SEPARATE
    data-plane finding when the conjunction holds — Milvus identified by
    Class A on this host AND the gRPC port accepted a zero-byte connect.

    Evidence doctrine: the finding claims reachability ONLY ("accepts
    connections from the prober's position"). Connect-only cannot know
    whether gRPC auth/TLS is required or vector data is readable, so the
    evidence never claims either — CRITICAL stays reserved for proven
    unauthenticated data access, which this probe can never prove."""
    findings = detect(facts)
    if _product_fingerprinted(facts) and connects.get(DATA_PLANE_PORT) == "accepted":
        findings.append(
            Finding(
                check_id=DATA_PLANE_CHECK_ID,
                product="Milvus",
                title="Milvus gRPC data plane (:19530) accepts connections",
                severity="HIGH",
                url="tcp://TARGET:19530/",
                evidence=(
                    "TCP connect accepted — 0 bytes sent to the Milvus gRPC "
                    "data plane (:19530), and the same host was fingerprinted "
                    "as Milvus by the Class A HTTP probes (:9091 Server "
                    "header) — the data plane accepts connections from the "
                    "prober's position. Reachability only: connect-only "
                    "cannot tell whether gRPC auth or TLS is required or "
                    "whether vector data is readable"
                ),
                fix_card_id=DATA_PLANE_FIX_CARD_ID,
                details=with_risk(
                    {"data_plane_port": DATA_PLANE_PORT, "method": "tcp-connect-0-bytes"},
                    AGENT_MEMORY,
                ),
            )
        )
    return findings
