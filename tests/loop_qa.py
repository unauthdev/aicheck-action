"""Nightly loop-qa: every door URL the action prints must resolve.

Crawls:
- https://unauth.dev/fixes/<fix_card_id> for every checker's FIX_CARD_ID
  and every CVE-map card — a renamed card id becomes a 404 in thousands
  of CI logs without this.
- the playground deep link from a rendered job summary (?from=ci…) — the
  CI → scope loop's last mile.
- the fix-card links in that same summary.

Run: python tests/loop_qa.py   (exit 1 on any dead link)
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from aicheck import render  # noqa: E402
from aicheck.checks import ALL_CHECKERS  # noqa: E402
from aicheck.checks.cvemap import all_entries  # noqa: E402

BASE = "https://unauth.dev"
UA = {"User-Agent": "aicheck-loop-qa/1.0 (+https://github.com/unauthdev/aicheck-action)"}


def card_ids() -> list[str]:
    ids = set()
    for checker in ALL_CHECKERS:
        cid = getattr(checker, "FIX_CARD_ID", None)
        if cid:
            ids.add(cid)
    for entry in all_entries():
        ids.add(str(entry["cve"]).lower())  # cve-2026-21858 style card ids
    return sorted(ids)


def summary_urls() -> list[str]:
    artifact = {
        "target": "ollama", "grade": "F",
        "findings": [{
            "check_id": "ollama", "product": "Ollama",
            "title": "Ollama API exposed without authentication",
            "severity": "CRITICAL", "url": "http://ollama:11434/api/tags",
            "evidence": "GET → 200", "fix_card_id": "ollama-exposed",
            "details": {},
        }],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(artifact, fh)
        path = fh.name
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    argv = [path, "--format", "summary", "--redact"]
    with redirect_stdout(buf):
        assert render.main(argv) == 0
    return re.findall(r"https://unauth\.dev/[^\s)\]]+", buf.getvalue())


def main() -> int:
    urls = [f"{BASE}/fixes/{cid}" for cid in card_ids()] + summary_urls()
    dead = []
    with httpx.Client(follow_redirects=True, timeout=15, headers=UA) as client:
        for url in sorted(set(urls)):
            try:
                code = client.get(url).status_code
            except httpx.HTTPError as exc:
                code = f"error: {exc}"
            ok = code == 200
            print(("ok  " if ok else "DEAD") + f"  {url}" + ("" if ok else f" -> {code}"))
            if not ok:
                dead.append(url)
    print(f"\n{len(set(urls))} urls, {len(dead)} dead")
    return 1 if dead else 0


if __name__ == "__main__":
    sys.exit(main())
