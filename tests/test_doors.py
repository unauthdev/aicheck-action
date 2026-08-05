"""Unit tests for the CLI door lines — run standalone: python tests/test_doors.py

Every text output ends with exactly one door line, after the findings:
- findings → first fix card + the demo deep link (from=cli) carrying
  grade, finding count and product slugs only — never the target string;
- clean → the CI-action link.
The action summary must keep calling the shared link builder with from=ci,
and that builder must exist exactly once in the codebase.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from aicheck import render as render_mod
from aicheck import scan as scan_mod

REPO = Path(__file__).resolve().parent.parent

CLEAN_DOOR = ("clean. keep it that way: the CI action watches every PR → "
              "https://github.com/unauthdev/aicheck-scan")


def make_findings() -> list[dict]:
    return [
        {
            "check_id": "ollama",
            "product": "Ollama",
            "title": "Ollama API exposed without authentication",
            "severity": "CRITICAL",
            "url": "http://10.0.0.1:11434/api/tags",
            "evidence": "GET http://10.0.0.1:11434/api/tags → 200",
            "fix_card_id": "ollama-exposed",
            "details": {},
        },
        {
            "check_id": "n8n",
            "product": "n8n",
            "title": "n8n automation UI exposed without authentication",
            "severity": "CRITICAL",
            "url": "http://10.0.0.1:5678/rest/settings",
            "evidence": "GET http://10.0.0.1:5678/rest/settings → 200",
            "fix_card_id": "n8n-exposed",
            "details": {},
        },
    ]


def test_findings_door_is_last_line() -> None:
    out = scan_mod.render_text("10.0.0.1", "F", make_findings())
    lines = out.rstrip("\n").splitlines()
    door = lines[-1]
    assert door.startswith(
        "fix cards: https://unauth.dev/fixes/ollama-exposed — "), door
    assert door.endswith(
        "see your stack the way the internet sees it: "
        "https://unauth.dev/demo?from=cli&grade=F&findings=2"
        "&services=ollama,n8n"), door
    # exactly one door line: one demo link, one "see your stack" pitch
    assert out.count("unauth.dev/demo") == 1
    assert out.count("see your stack the way the internet sees it") == 1
    # the door comes after the findings, never before
    assert lines[-3].startswith("  CRITICAL"), lines
    print("ok — findings output ends with the fix-cards + demo door")


def test_door_url_never_contains_target() -> None:
    # targets that double as product slugs / IPs: use findings whose own
    # slugs don't collide, so any occurrence of the target is a leak
    findings = [f for f in make_findings() if f["product"] == "n8n"] + [
        dict(make_findings()[1], check_id="qdrant", product="Qdrant",
             fix_card_id="qdrant-exposed")]
    for target in ("ollama", "10.0.0.1"):
        out = scan_mod.render_text(target, "F", findings)
        door = out.rstrip("\n").splitlines()[-1]
        demo_url = door.rsplit("sees it: ", 1)[1]
        assert demo_url.startswith("https://unauth.dev/demo?from=cli")
        assert target not in demo_url, (target, demo_url)
    print("ok — door URL carries no target string ('ollama', '10.0.0.1')")


def test_clean_door_is_last_line() -> None:
    out = scan_mod.render_text("10.0.0.1", "A", [])
    door = out.rstrip("\n").splitlines()[-1]
    assert door == CLEAN_DOOR, door
    assert "10.0.0.1" not in door
    print("ok — clean output ends with the CI-action door")


def test_link_builder_defined_once() -> None:
    # pattern split so this test file doesn't match its own grep
    pattern = "def " + "deep_link"
    r = subprocess.run(["git", "grep", "-n", pattern], cwd=REPO,
                       capture_output=True, text=True, check=True)
    hits = [l for l in r.stdout.splitlines() if l.strip()]
    assert len(hits) == 1, hits
    assert hits[0].startswith("src/aicheck/render.py:"), hits
    print(f"ok — {pattern} exists exactly once: {hits[0]}")


def test_action_summary_keeps_from_ci() -> None:
    artifact = {"target": "ollama", "grade": "F", "findings": make_findings()}
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "artifact.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = render_mod.main([str(path), "--format", "summary", "--redact"])
    assert code == 0
    out = buf.getvalue()
    assert "https://unauth.dev/demo?from=ci&grade=F&findings=2" in out, out
    assert "from=cli" not in out
    print("ok — action summary render still deep-links with from=ci")


def test_deep_link_maps_scanner_products_to_demo_ids() -> None:
    url = render_mod.deep_link("F", [
        {"product": "MCP server"},
        {"product": "Open WebUI"},
        {"product": "CrewAI Studio"},
        {"product": "Ollama"},
    ])
    assert "services=mcp,openwebui,crewai,ollama" in url, url
    assert render_mod.demo_service_id("MCP server") == "mcp"
    print("ok — deep_link maps scanner products to demo service ids")


def main() -> int:
    test_findings_door_is_last_line()
    test_door_url_never_contains_target()
    test_clean_door_is_last_line()
    test_link_builder_defined_once()
    test_action_summary_keeps_from_ci()
    test_deep_link_maps_scanner_products_to_demo_ids()
    print("all door tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
