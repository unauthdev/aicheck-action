# Architecture

One engine, four doors.

## The engine

`src/aicheck` — the whole product. Deterministic, no database, no
phone-home; dependencies are `httpx` and `pyyaml`, nothing else.

- `recon.py` probes the well-known AI-service ports and gathers facts.
- `checks/` — one checker per product (plus `cvemap.py` driven by
  `content/cve_map.yaml`). Each checker maps facts to findings.
- `scoring.py` grades findings (A/C/D/F).
- `sarif.py` / `render.py` turn the same finding set into SARIF, JSON,
  text and job-summary output.
- `scan.py` is the CI-shaped CLI (`python -m aicheck.scan`); `cli.py` is
  the thin console-script wrapper behind the `aicheck` command.

Contracts that are load-bearing across every door:

- **Exit codes**: `0` pass, `1` grade at or worse than `--fail-grade`,
  `2` target/usage/engine error (an engine crash is never a grade).
- **Version**: single-sourced as `aicheck.__version__`; the package
  metadata, `--version` output and SARIF `tool.driver.version` all read
  from it.
- **Stable IDs**: `check_id` and `fix_card_id` are the internal API —
  SARIF rules, fix-card URLs and CI greps all key on them. Never rename
  one without a migration plan.

## The four doors

1. **pip CLI** — `pip install aicheck-scan` gives you the `aicheck`
   command. Built from this repo (`pyproject.toml`, hatchling, src
   layout).
2. **GitHub Action** — `action.yml` (composite) pip-installs the package
   from the action path and runs the `aicheck` console script, then
   renders SARIF / job summary from the same JSON artifact.
3. **Docker image** — `packaging/Dockerfile` pip-installs the package
   and ENTRYPOINTs `aicheck`; published to ghcr.io by
   `publish-image.yml` on version tags. The one-line install for GitLab,
   Bitbucket, Azure DevOps, Jenkins and bare CI.
4. **unauth.dev site scanner** — the hosted scanner reuses the same
   engine; the fix cards and deep links the CLI prints loop back to it.

Every door runs the same engine and the same finding schema, so a grade
means the same thing no matter which door you came through.
