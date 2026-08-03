# Publish aicheck to GitHub Marketplace (E1)

The Action is ready for Marketplace (`action.yml` has `name`, `description`,
`branding`). Listing is a **GitHub UI step** — `gh release create` cannot
check the Marketplace box or accept the Developer Agreement.

## Preconditions

- [ ] Org owner accepted [GitHub Marketplace Developer Agreement](https://docs.github.com/en/site-policy/github-terms/github-marketplace-developer-agreement)
  (checkbox stays disabled until this is done)
- [ ] Repo public, `action.yml` at repo root, branding present
- [ ] Latest semver release tagged (e.g. `v1.1.1`) and `v1` floating tag updated
- [ ] 2FA enabled on the publishing account

## Publish (once per release you want listed)

1. Open https://github.com/unauthdev/aicheck-scan/action.yml  
   — banner **Draft a release** / publish to Marketplace should appear.
2. Or: **Releases → Draft a new release**, choose tag `v1.1.1` (or newer).
3. Check **Publish this Action to the GitHub Marketplace**.
4. Primary category: **Security** (secondary optional: Continuous integration).
5. Title/notes: reuse release body; keep “SARIF code scanning on by default”.
6. **Publish release**.

Listing URL (after success):

https://github.com/marketplace/actions/aicheck-scan

Update README Marketplace badge to that URL once it returns 200.

Note: Marketplace `name` must be unique and ≤125-char `description`. The
CLI command stays `aicheck`; only the Marketplace listing name is
`aicheck-scan` (repo name; avoids collision with GitHub user `AIcheck`).

## After listing

- Prefer `uses: unauthdev/aicheck-scan@v1` in all docs (floating major).
- Do not invent a `badge?target=` endpoint — badges only from CI/SARIF artifacts.
- Adoption metric (roadmap E1): ≥10 public repos using the Action.
- PyPI CLI publish (`pip install aicheck-scan`) is separate — see [`docs/pypi.md`](pypi.md).

## One-click path for consumers (no Marketplace required)

```yaml
# .github/workflows/aicheck.yml
permissions:
  contents: read
  security-events: write
jobs:
  aicheck:
    runs-on: ubuntu-latest
    steps:
      - uses: unauthdev/aicheck-scan@v1
        with:
          target: localhost
```

Copy-paste examples: [`examples/`](../examples/).
