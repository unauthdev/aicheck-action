"""Unit tests for aicheck.render.redact — run standalone: python tests/test_redact.py

Regression guard for the substring-collision bug: when the scan target equals
a product slug (the documented GitLab pattern TARGET: ollama), a textual
replace corrupted check_id/fix_card_id and 404'd every fix link. redact()
must scrub structurally instead.
"""

from __future__ import annotations

import json
import sys

from aicheck.render import REDACTED_TARGET, redact


def make_artifact(target: str) -> dict:
    return {
        "target": target,
        "grade": "F",
        "findings": [
            {
                "check_id": "ollama",
                "product": "Ollama",
                "title": "Ollama API exposed without authentication",
                "severity": "CRITICAL",
                "url": f"http://{target}:11434/api/tags",
                "evidence": f"GET http://{target}:11434/api/tags → 200 (model list)",
                "fix_card_id": "ollama-exposed",
                "details": {},
            },
            {
                "check_id": "cve-2026-21858",
                "product": "n8n",
                "title": "n8n 1.2 is vulnerable to CVE-2026-21858",
                "severity": "CRITICAL",
                "url": f"http://{target}:5678/rest/settings",
                "evidence": f"GET http://{target}:5678/rest/settings → 200",
                "fix_card_id": "cve-2026-21858",
                "details": {
                    "cve": "CVE-2026-21858",
                    "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-21858",
                    "affected": [">=1.0, <1.65.0"],
                },
            },
        ],
    }


def check(target: str) -> None:
    out = redact(make_artifact(target))
    blob = json.dumps(out)

    # identifiers and references survive untouched
    ollama, cve = out["findings"]
    assert ollama["check_id"] == "ollama", ollama["check_id"]
    assert ollama["fix_card_id"] == "ollama-exposed", ollama["fix_card_id"]
    assert ollama["product"] == "Ollama"
    assert cve["check_id"] == "cve-2026-21858", cve["check_id"]
    assert cve["details"]["cve"] == "CVE-2026-21858"
    assert cve["details"]["reference_url"].startswith("https://nvd.nist.gov/")

    # fix links are built from fix_card_id — they must stay valid
    for f in out["findings"]:
        link = f"https://unauth.dev/fixes/{f['fix_card_id']}"
        assert REDACTED_TARGET not in link, link

    # the target is scrubbed from the fields that carried it (URL-anchored:
    # a target literally named 'target' is a substring of the placeholder,
    # so bare-substring asserts would false-fail)
    assert out["target"] == REDACTED_TARGET
    for f in out["findings"]:
        assert f["url"].startswith(f"http://{REDACTED_TARGET}:"), f["url"]
        assert f"http://{target}" not in f["url"], f["url"]
        assert f"http://{target}" not in f["evidence"], f["evidence"]
        assert REDACTED_TARGET in f["evidence"]

    # no host:port trace of the raw target anywhere in the artifact
    assert f"http://{target}:11434" not in blob
    assert f"http://{target}:5678" not in blob


def check_bare_fqdn_in_evidence() -> None:
    """FQDN/IP tokens in free-text evidence must redact even without :port."""
    target = "internal.acme.corp"
    out = redact({
        "target": target,
        "grade": "F",
        "findings": [{
            "check_id": "ollama",
            "product": "Ollama",
            "title": "exposed",
            "severity": "CRITICAL",
            "url": f"http://{target}:11434/",
            "evidence": f"host {target} is wide open",
            "fix_card_id": "ollama-exposed",
            "details": {"note": f"host {target} responded"},
        }],
    })
    blob = json.dumps(out)
    assert target not in blob, blob
    assert REDACTED_TARGET in out["findings"][0]["evidence"]
    # product-slug targets still must not corrupt identifiers
    slug = redact(make_artifact("ollama"))
    assert slug["findings"][0]["fix_card_id"] == "ollama-exposed"


def main() -> int:
    for target in ["ollama", "n8n", "10.0.0.1", "my-host.internal",
                   "localhost", "target"]:
        check(target)
        print(f"ok — target {target!r}")
    check_bare_fqdn_in_evidence()
    print("ok — bare FQDN evidence redacted")
    print("all redact tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
