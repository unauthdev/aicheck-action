"""Probe classes: what traffic aicheck is allowed to send.

Class A (default) — GET-only metadata probes. Safe for CI, hosted scanner
doctrine, and air-gapped inventory. Near-zero false positives.

Class B (--deep) — reserved for customer-run estate checks that may go beyond
GET-only (authenticated headers, limited POSTs, future runtime packs).
Requires an explicit ownership acknowledgement.

Packs shipped: "data-plane" — zero-byte TCP connect-and-close to the Milvus /
Qdrant / Weaviate data-plane ports (reachability only; see
docs/deep-pack-data-plane.md and docs/PROBES.md).

Hosted unauth.dev never enables Class B.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProbeClass = Literal["A", "B"]

CLASS_A = "A"
CLASS_B = "B"

# Opt-in deep packs. "data-plane": TCP connect (0 bytes) to vector-store data
# planes — the first Class B pack (docs/deep-pack-data-plane.md).
DEEP_PACKS_AVAILABLE: tuple[str, ...] = ("data-plane",)


@dataclass(frozen=True)
class ProbeMode:
    probe_class: ProbeClass
    deep: bool
    deep_packs: tuple[str, ...]
    i_own_these_targets: bool

    def to_dict(self) -> dict:
        data_plane = "data-plane" in self.deep_packs
        return {
            "probe_class": self.probe_class,
            "deep": self.deep,
            "deep_packs": list(self.deep_packs),
            "deep_packs_available": list(DEEP_PACKS_AVAILABLE),
            "i_own_these_targets": self.i_own_these_targets,
            "methods": (
                ["GET"]
                if self.probe_class == CLASS_A
                else (
                    ["GET", "TCP connect (0 bytes)"]
                    if data_plane
                    else ["GET", "(pack-defined)"]
                )
            ),
            "note": (
                "Class A: GET-only metadata probes."
                if self.probe_class == CLASS_A
                else (
                    "Class B with data-plane pack: GET probes plus zero-byte "
                    "TCP connect-and-close to vector-store data-plane ports "
                    "(reachability only — no bytes sent, no auth attempted)."
                    if data_plane
                    else (
                        "Class B acknowledged; no deep packs are enabled in this "
                        "build — behavior matches Class A until packs ship."
                    )
                )
            ),
        }


class ProbeClassError(ValueError):
    """Bad --deep / ownership flags."""


def resolve_probe_mode(
    *,
    deep: bool = False,
    i_own_these_targets: bool = False,
    deep_packs: list[str] | None = None,
) -> ProbeMode:
    packs = tuple(p.strip() for p in (deep_packs or []) if p and p.strip())
    if not deep and not packs:
        return ProbeMode(
            probe_class=CLASS_A,
            deep=False,
            deep_packs=(),
            i_own_these_targets=False,
        )
    if packs and not deep:
        raise ProbeClassError("--deep-packs requires --deep")
    if deep and not i_own_these_targets:
        raise ProbeClassError(
            "--deep requires --i-own-these-targets (customer-run estate only; "
            "acknowledges you authorize probing these hosts beyond Class A)"
        )
    unknown = [p for p in packs if p not in DEEP_PACKS_AVAILABLE]
    if unknown:
        avail = ", ".join(DEEP_PACKS_AVAILABLE) or "(none shipped yet)"
        raise ProbeClassError(
            f"unknown deep pack(s): {', '.join(unknown)}. available: {avail}"
        )
    # Class B gate open; packs empty ⇒ same traffic as Class A for now.
    return ProbeMode(
        probe_class=CLASS_B,
        deep=True,
        deep_packs=packs,
        i_own_these_targets=True,
    )
