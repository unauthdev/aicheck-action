# Publish aicheck-scan to PyPI

Trusted publishing only (OIDC). No API tokens in the repo.

Workflow: [`.github/workflows/publish-pypi.yml`](../.github/workflows/publish-pypi.yml)  
GitHub environments (already created): `pypi` (tags `v*` only), `testpypi`.

## Blocker if publish fails with `invalid-publisher`

PyPI has no matching trusted publisher yet. That is a **PyPI UI** step — GitHub
cannot finish it for you.

### Pending publisher (first upload — package does not exist yet)

1. Sign in at https://pypi.org/manage/account/publishing/
2. Under **Add a new pending publisher**, enter exactly:

| Field | Value |
|---|---|
| PyPI Project Name | `aicheck-scan` |
| Owner | `unauthdev` |
| Repository name | `aicheck-scan` |
| Workflow name | `publish-pypi.yml` |
| Environment name | `pypi` |

3. Click **Add**. Do **not** leave Environment blank — the workflow sets
   `environment: pypi`, and a blank publisher will never match.

### TestPyPI (optional dry-run)

Same fields on https://test.pypi.org/manage/account/publishing/ with
Environment name `testpypi`. Then run **Actions → publish-pypi → Run workflow**.

## After the pending publisher exists

Re-run the failed release job, or publish any new GitHub Release:

```bash
gh run rerun <run-id> --repo unauthdev/aicheck-scan --failed
# e.g. the v1.1.6 failure:
# gh run rerun 30838699783 --repo unauthdev/aicheck-scan --failed
```

Confirm: https://pypi.org/p/aicheck-scan and `pip install aicheck-scan`.

## Claims from a failed run (for debugging)

If PyPI still rejects, compare against the job’s OIDC claims. A good match looks
like:

- `repository`: `unauthdev/aicheck-scan`
- `job_workflow_ref`: `…/.github/workflows/publish-pypi.yml@…`
- `environment`: `pypi`
