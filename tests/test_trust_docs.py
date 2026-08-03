"""Trust-surface guards — run standalone: python tests/test_trust_docs.py

Covers the publishing + trust surface:
- no workflow carries a PyPI password/token input (trusted publishing only)
- pyproject URLs point at the renamed repo (unauthdev/aicheck-scan)
- docs/trust.md documents --dry-run, --verbose, AICHECK_NO_VERSION_CHECK,
  --require-hashes
- SECURITY.md carries the never-ask-for-credentials line
- README links both trust docs
- `aicheck --version` matches __version__ in src/aicheck/__init__.py
  (single-sourcing guard)
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_workflows_have_no_pypi_tokens() -> None:
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflows, "no workflows found"
    for wf in workflows:
        text = wf.read_text()
        assert "PYPI_API_TOKEN" not in text, f"{wf.name}: PYPI_API_TOKEN found"
        assert "secrets.PYPI" not in text, f"{wf.name}: PyPI secret found"
        for line in text.splitlines():
            if "password:" in line:
                # the only acceptable password input is the docker login to
                # ghcr.io with the ephemeral, auto-provisioned GITHUB_TOKEN
                assert "secrets.GITHUB_TOKEN" in line, (
                    f"{wf.name}: non-GITHUB_TOKEN password: {line.strip()}")
    publish = (ROOT / ".github" / "workflows" / "publish-pypi.yml").read_text()
    assert "password:" not in publish, "publish-pypi.yml must be token-free"
    assert "id-token: write" in publish, "publish-pypi.yml must use OIDC"


def test_pyproject_urls_new_repo_name() -> None:
    text = (ROOT / "pyproject.toml").read_text()
    assert "github.com/unauthdev/aicheck-scan" in text
    assert "aicheck-action" not in text


def test_trust_doc_mentions_flags() -> None:
    text = (ROOT / "docs" / "trust.md").read_text()
    for needle in ("--dry-run", "--verbose", "AICHECK_NO_VERSION_CHECK",
                   "--require-hashes"):
        assert needle in text, f"docs/trust.md missing {needle}"


def test_security_md_ground_rule() -> None:
    text = (ROOT / "SECURITY.md").read_text()
    assert "we will never ask for your credentials" in text
    assert "needs none and sends nothing anywhere" in text


def test_readme_links_trust_docs() -> None:
    text = (ROOT / "README.md").read_text()
    assert "docs/trust.md" in text, "README does not link docs/trust.md"
    assert "SECURITY.md" in text, "README does not link SECURITY.md"
    assert "docs/marketplace.md" in text, "README does not link docs/marketplace.md"
    assert (ROOT / "examples" / "github-action.yml").is_file()
    assert (ROOT / "docs" / "marketplace.md").is_file()
    # Do not claim a live Marketplace URL until the listing returns 200
    assert "marketplace/actions/aicheck-scan)" not in text.replace(
        "docs/marketplace.md", ""), "README links a Marketplace URL that may 404"


def test_version_single_sourced() -> None:
    init = (ROOT / "src" / "aicheck" / "__init__.py").read_text()
    m = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    assert m, "__version__ not found in src/aicheck/__init__.py"
    out = subprocess.run(
        ["aicheck", "--version"],
        capture_output=True, text=True,
    )
    cli_out = (out.stdout + out.stderr).strip()
    assert out.returncode == 0, f"--version exited {out.returncode}: {cli_out}"
    assert cli_out.endswith(m.group(1)), (
        f"--version says {cli_out!r}, __init__.py says {m.group(1)!r}")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"ok {t.__name__}")
    print(f"{len(tests)} tests passed")
