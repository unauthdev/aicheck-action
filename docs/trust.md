# trust

why you can run aicheck in your CI without taking our word for anything.

## what the engine does

one thing: read-only GETs to the target you give it, on the well-known
AI-service ports. it asks for version, tags, and settings endpoints — the
same metadata the unauth.dev scanner reads — and grades what answers.

nothing else is ever dialed. no telemetry, no phone-home, no analytics, no
beacon to unauth.dev. no logins, no POSTs to your services, no exploit
verification. it needs no credentials and accepts none.

there is one optional extra — a weekly, opt-in PyPI version check, off
unless you enable it — in its own section below.

## verify it yourself

don't trust this page. check:

- `aicheck example.com --dry-run` prints every request it would send — no
  sockets, no DNS. the plan you see is the whole plan.
- `aicheck example.com --verbose` logs each connection actually dialed
  (with the pinned IP) to stderr, 1:1 against the transport.
- run it behind a logging proxy and watch every byte.
- or read the source. the engine is dependency-light python (httpx +
  pyyaml); the core is an afternoon's audit.

## supply chain

- every release is built and published by
  [.github/workflows/publish-pypi.yml](https://github.com/unauthdev/aicheck-scan/blob/main/.github/workflows/publish-pypi.yml)
  with SLSA provenance attestations on the `dist/*` artifacts (via
  `actions/attest-build-provenance`). verify an artifact with
  `gh attestation verify`.
- publishing uses OIDC trusted publishing — there is no PyPI API token
  anywhere, so there is no token to leak. Maintainer checklist:
  [`docs/pypi.md`](pypi.md).
- the build is reproducible: `pip install build && python -m build` on a
  clean checkout.

## verifying the container image

the `ghcr.io/unauthdev/aicheck` image gets the same treatment as the PyPI
dists, via
[.github/workflows/publish-image.yml](https://github.com/unauthdev/aicheck-scan/blob/main/.github/workflows/publish-image.yml):

- the base image (`python:3.11-slim`) is pinned by digest in
  `packaging/Dockerfile` — no floating base.
- every tag build emits a build-provenance attestation for the image digest.
  verify what you pulled:

  ```bash
  gh attestation verify oci://ghcr.io/unauthdev/aicheck:v1 \
    --owner unauthdev
  ```

- an SBOM (SPDX-JSON, via `anchore/sbom-action`) is generated for every
  image and attached to the release as `sbom.spdx.json` — diff it between
  releases if you want to know exactly what changed inside.
- tag pushes assert the tag equals `__version__` before anything is built,
  so `v1.2.3` the tag is always `1.2.3` the code.

## per-release hashes

the release notes for each version carry the sha256 of the sdist and wheel
(appended by the publish workflow itself, straight from the built `dist/`).
that's the number to pin against in `--require-hashes` installs — not a
hash you computed from whatever the index handed you, and not one we typed
into the notes by hand.

## the optional network call beyond your target

off by default. if you enable it with `--version-check` or
`AICHECK_VERSION_CHECK=1`, then once per week, if online, the CLI checks
PyPI's JSON API for a newer version (3s timeout, cannot raise, PyPI-only).
the old opt-out switches — `--no-version-check` and
`AICHECK_NO_VERSION_CHECK=1` — are still honored and silence it. it never
goes anywhere else.

## Action pin posture

`uses: unauthdev/aicheck-scan@v1` is a **mutable** floating major tag (convenience).
Third-party Actions in this repo are pinned to full SHAs (Dependabot keeps
them fresh). For a SHA-locked consumer install:

```yaml
- uses: unauthdev/aicheck-scan@<full-commit-sha>  # pin a release commit
```

`--allow-private` is intentional inside CI runners (you already control that
network). The Action is not a sandbox — a malicious workflow can still reach
metadata IPs the same way `curl` could.

## hash-pinned install

for the paranoid path, pin by hash instead of trusting the index:

```bash
pip download aicheck-scan --no-deps -d /tmp/aicheck
pip install --require-hashes aicheck-scan \
  --hash sha256:<hash from the release notes>
```

the sha256 hashes of the sdist and wheel are published in the release
notes for each version. combine with `gh attestation verify` for the full
chain: source → build → artifact.

## disclosure

found something? see [SECURITY.md](../SECURITY.md).
