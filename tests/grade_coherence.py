"""Grade coherence: run one fixture stack through an engine checkout and
print the canonical result as JSON. The loop-qa workflow runs this twice —
once against the action/pip engine (src/), once against the site engine
(the unauth.dev checkout) — and fails on any divergence.

No network: canned recon facts for an exposed ollama + openwebui stack.

  PYTHONPATH=<engine-parent> python tests/grade_coherence.py
"""

from __future__ import annotations

import json
import sys

from aicheck.models import ProbeResult
from aicheck.scoring import grade, run_checkers

# canned facts: ollama answering unauthenticated on 11434, open webui on 8080
def facts() -> dict:
    def ok(port, path, body):
        return ProbeResult(url=f"http://fixture-host:{port}{path}",
                           status_code=200, body=body)
    return {
        "11434:/": ok(11434, "/", "Ollama is running"),
        "11434:/api/version": ok(11434, "/api/version", '{"version":"0.5.7"}'),
        "11434:/api/tags": ok(11434, "/api/tags",
                              '{"models":[{"name":"llama3.1:8b"}]}'),
        "8080:/": ok(8080, "/", '<html><title>Open WebUI</title></html>'),
        "8080:/api/config": ok(8080, "/api/config",
                               '{"status":true,"name":"Open WebUI"}'),
    }


def main() -> int:
    res = run_checkers(facts(), "fixture-host")
    # Engine 1.2.4+ returns (findings, observations); older engines return
    # findings only. Grade coherence compares findings either way.
    findings = res[0] if isinstance(res, tuple) else res
    out = {
        "grade": grade(findings),
        "findings": sorted(
            ({"check_id": f.check_id, "severity": f.severity} for f in findings),
            key=lambda d: (d["check_id"], d["severity"]),
        ),
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
