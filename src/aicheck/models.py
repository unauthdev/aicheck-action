"""Shared data types for the checks engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")


@dataclass
class ProbeResult:
    """Result of one safe HTTP GET probe. status_code=None means the
    connection failed (refused / timeout / DNS)."""

    url: str
    status_code: Optional[int]
    body: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status_code == 200

    def json(self):
        import json

        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None


@dataclass
class Finding:
    check_id: str
    product: str
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM
    url: str
    evidence: str
    fix_card_id: str
    # Optional structured payload (e.g. CVE id, fixed_in, reference_url).
    # Defaults to {} so existing checkers/consumers keep working unchanged.
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
