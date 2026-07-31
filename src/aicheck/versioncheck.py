"""Weekly PyPI version check — opt-out, failure-invisible.

Once a week (cached in ~/.cache/aicheck/version-check) a successful scan
checks https://pypi.org/pypi/aicheck-scan/json for a newer release and prints
one stderr line if there is one. This is the only network call in the package
besides the scan itself, and it cannot raise, hang the scan (3s timeout), or
touch anything but PyPI: every failure mode — offline, timeout, 404 (the
package predates its first release), bad JSON, unwritable cache — is silence.

Disable with --no-version-check or AICHECK_NO_VERSION_CHECK=1.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

PYPI_URL = "https://pypi.org/pypi/aicheck-scan/json"
RELEASES_URL = "https://github.com/unauthdev/aicheck-scan/releases"
CACHE_PATH = Path.home() / ".cache" / "aicheck" / "version-check"
WEEK = timedelta(days=7)
TIMEOUT = 3.0


def _parse(version: str) -> tuple[int, ...]:
    """Numeric tuple per dotted part, pre-release suffixes ignored
    ('1.2.0rc1' -> (1, 2, 0))."""
    nums = []
    for part in version.split("."):
        digits = ""
        for ch in part:
            if not ch.isdigit():
                break
            digits += ch
        nums.append(int(digits) if digits else 0)
    return tuple(nums)


def _newer(latest: str, current: str) -> bool:
    a, b = _parse(latest), _parse(current)
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return a > b


def _fetch_latest() -> str | None:
    """GET the PyPI JSON and return info.version, None on anything unexpected
    (offline, timeout, non-200, bad JSON, missing key)."""
    try:
        r = httpx.get(PYPI_URL, timeout=TIMEOUT)
        if r.status_code != 200:
            return None
        version = r.json().get("info", {}).get("version")
        return version if isinstance(version, str) and version else None
    except Exception:
        return None


def maybe_notify(current_version: str, *, cache_path: Path, now: datetime,
                 fetcher) -> str | None:
    """Core: return the one-line upgrade notice, or None for silence. Reads
    and writes the cache at `cache_path` (written only after a successful
    fetch — failures don't back off, they just stay silent). Never raises."""
    try:
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            checked = datetime.fromisoformat(data["checked"])
            if now - checked < WEEK:
                return None
        except Exception:
            pass  # missing/corrupt cache → check now

        try:
            latest = fetcher()
        except Exception:
            return None  # offline, timeout, ... — no cache write
        if not isinstance(latest, str) or not latest:
            return None

        notice = None
        if _newer(latest, current_version):
            notice = (f"v{latest} is out — pip install -U aicheck-scan "
                      f"(release notes: {RELEASES_URL})")
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps({"checked": now.isoformat()}),
                                  encoding="utf-8")
        except Exception:
            return None  # unwritable cache dir → silent no-op
        return notice
    except Exception:
        return None


def check_for_update(*, disabled: bool = False) -> None:
    """Side-effect wrapper called once at the end of a successful scan.
    Prints the notice to stderr if there is one. Cannot raise."""
    try:
        if disabled:
            return
        if os.environ.get("AICHECK_NO_VERSION_CHECK", "") not in ("", "0"):
            return
        from . import __version__
        notice = maybe_notify(__version__, cache_path=CACHE_PATH,
                              now=datetime.now(timezone.utc),
                              fetcher=_fetch_latest)
        if notice:
            print(notice, file=sys.stderr)
    except Exception:
        pass
