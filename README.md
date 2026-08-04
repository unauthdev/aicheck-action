# aicheck

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-aicheck--scan-blue?logo=github)](https://github.com/marketplace/actions/aicheck-scan)
[![Use this Action](https://img.shields.io/badge/GitHub-Use%20this%20Action-orange?logo=github)](https://github.com/unauthdev/aicheck-scan#add-to-your-repo-60-seconds)
[![selftest](https://github.com/unauthdev/aicheck-scan/actions/workflows/selftest.yml/badge.svg)](https://github.com/unauthdev/aicheck-scan/actions/workflows/selftest.yml)
[![Docker image](https://img.shields.io/badge/ghcr.io-unauthdev%2Faicheck%3Av1-blue?logo=docker)](https://github.com/unauthdev/aicheck-scan/pkgs/container/aicheck)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Find exposed self-hosted AI services — in CI, or continuously across your estate.**

One engine, four doors (pip / GitHub Action / Docker / site):

- **`aicheck <target>`** — CI feeder: fail the build if a PR ships an unauthenticated AI service
- **`aicheck inventory`** — local continuous inventory: multi-host, stable finding IDs, drift (`new` / `fixed` / `still_open`), no phone-home

Live-probes Ollama, n8n, vLLM, Langfuse, Open WebUI, ComfyUI, Ray, Dify, Qdrant,
AnythingLLM, Jupyter, Gradio, Langflow, Flowise, Chroma, Weaviate, Redis consoles,
MCP servers and more — grades A–F, SARIF on by default in CI, plain-English fix
cards. From [unauth.dev](https://unauth.dev).

Install from the [GitHub Marketplace](https://github.com/marketplace/actions/aicheck-scan),
or follow the steps below. Maintainer listing notes:
[`docs/marketplace.md`](docs/marketplace.md).

## Add to your repo (60 seconds)

1. Copy [`examples/github-action.yml`](examples/github-action.yml) to
   `.github/workflows/aicheck.yml` (or use the minimal snippet below).
2. Point `target` at the host your job starts (often `localhost` + a `services:` block).
3. Ensure the job has `permissions: security-events: write` so SARIF lands in
   **Security → Code scanning**.

```yaml
name: ai-stack-exposure
on: [pull_request]
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

Pin `@v1` for floating majors, or `@v1.1.1` for an exact release. More examples:
[`examples/`](examples/).
## Why live probing

This is not a config linter. The action starts from what actually answers:
it runs the same read-only GET probes the unauth.dev scanner runs, against
the real service in your job. If Ollama responds unauthenticated on 11434,
that's ground truth — no guessing from compose files, near-zero false
positives.

It answers one question: **"did this PR ship an AI service with no auth?"**
It does not prove internet reachability (your firewall/proxy is invisible
from CI) — that's what post-deploy monitoring is for.

## One engine, four doors

| door | install / use | when |
|---|---|---|
| pip CLI | `pip install aicheck-scan` → `aicheck your-host` | check any machine, right now |
| GitHub Action | `uses: unauthdev/aicheck-scan@v1` | every PR, in the build |
| Docker | `docker run ghcr.io/unauthdev/aicheck:v1 your-host --allow-private` | GitLab, Bitbucket, Azure, Jenkins, bare CI |
| site scanner | [unauth.dev](https://unauth.dev) | zero-install, from the internet's side |

Same engine, same severity model, same grade — pick the door that fits.

## Usage (fail the PR on exposure)

```yaml
name: ai-stack-exposure
on: [pull_request]

permissions:
  contents: read
  security-events: write   # SARIF → code scanning (default on)

jobs:
  aicheck:
    runs-on: ubuntu-latest
    services:
      ollama:
        image: ollama/ollama:latest
        ports: ["11434:11434"]
    steps:
      - uses: unauthdev/aicheck-scan@v1
        with:
          target: localhost
          fail-grade: C      # D or F fails the build
```

Full copy-paste: [`examples/github-action.yml`](examples/github-action.yml).
A default Ollama container fails — that's the point. Fix it (the annotation
links the fix card), watch it go green.

What you get on the run page:

> ## aicheck — grade F
>
> Your PR ships **2 exposed AI services** — anyone who can reach them can use them.
>
> | severity | service | finding | fix |
> |---|---|---|---|
> | CRITICAL | Ollama | API exposed without authentication | [fix card](https://unauth.dev/fixes/ollama-exposed) |
> | HIGH | n8n | settings endpoint readable without authentication | [fix card](https://unauth.dev/fixes/n8n-exposed) |
>
> [See your stack the way the internet sees it →](https://unauth.dev/playground?from=ci&grade=F&findings=2&services=ollama,n8n)

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `target` | *(required)* | Host to probe. No port — well-known AI-service ports are probed. |
| `fail-grade` | `F` | Fail if the grade is this or worse. `F` = only critical exposure fails; `C` = anything above clean fails. |

Note: `fail-grade: A` fails the build even on a clean scan; it exists to
smoke-test the wiring on first install.
| `services` | *(all 17)* | Comma-separated product filter, e.g. `ollama,n8n`. |
| `upload-sarif` | `true` | Upload results to code scanning. Set `false` to skip (no `security-events` permission needed then). |

## Outputs

| Output | Meaning |
|---|---|
| `grade` | `A` (clean), `C`, `D`, or `F` (critical exposure). |

## Install (local CLI)

```bash
pip install aicheck-scan

# CI / single host (same as the Action)
aicheck example.com
aicheck scan localhost --allow-private --fail-grade F

# Local estate inventory (air-gapped; nothing phones home)
aicheck inventory --targets targets.yaml --state-dir ./state --allow-private

# CSV / flow-log JSONL / CIDRs + webhook to YOUR endpoint on new findings
aicheck inventory --targets hosts.jsonl --state-dir ./state --allow-private \
  --webhook https://hooks.example.internal/aicheck --webhook-on new
```

Probe contract: [`docs/PROBES.md`](docs/PROBES.md).  
Targets: YAML / CSV / JSONL examples under [`examples/`](examples/).

The package installs the `aicheck` console command — same engine the Action and
the Docker image run.

Paranoid path — pin by hash, don't trust the index:

```bash
pip download aicheck-scan --no-deps -d /tmp/aicheck
pip install --require-hashes aicheck-scan \
  --hash sha256:<hash from the release notes>
```

Hashes are in the release notes for each version. Details and verification:
[docs/trust.md](docs/trust.md).

## Air-gapped / offline

The only call the engine makes beyond your target is an optional weekly
PyPI version check. To run fully offline — air-gapped networks, locked-down
runners — disable it either way:

```bash
aicheck example.com --no-version-check        # per run
export AICHECK_NO_VERSION_CHECK=1             # per environment
```

With that off (and `--dry-run` to prove it), nothing is dialed except the
hosts you name. Inventory mode is offline by design.

## Auditability

the engine is dependency-light Python (httpx + pyyaml). don't trust us: run
`--dry-run`, run it behind a proxy, or read it — the core is an afternoon's
audit. full trust page: [docs/trust.md](docs/trust.md).

## Privacy / supply chain

- **Runs entirely on your runner.** Probe traffic is read-only GETs to *your*
  target. The only other dial is an optional weekly PyPI version check
  (opt out: `--no-version-check` / `AICHECK_NO_VERSION_CHECK=1`) — see
  [docs/trust.md](docs/trust.md). No telemetry to unauth.dev.
- No credentials needed. No Docker socket. No privileged mode.
- What it probes: well-known metadata endpoints only (version, tags,
  settings). No logins, no POSTs to your services, no exploit verification.

## GitLab CI

The engine is a plain CLI — GitLab support is config, not code. The
one-liner (preferred, uses the published image):

```yaml
aicheck:
  image: ghcr.io/unauthdev/aicheck:v1
  services:
    - name: ollama/ollama:latest
      alias: ollama
  variables:
    TARGET: ollama            # the service alias
  script:
    - python -m aicheck.scan "$TARGET" --allow-private --fail-grade F
```

The full version — one scan, SARIF artifact, pipeline fails on grade — with
the source pinned to the v1 tag (never track main):

```yaml
aicheck:
  image: python:3.11-slim
  services:
    - name: ollama/ollama:latest
      alias: ollama
  variables:
    TARGET: ollama            # the service alias — or localhost with a before_script install
  before_script:
    - pip install --quiet httpx pyyaml
    - git clone --depth 1 --branch v1.1.5 https://github.com/unauthdev/aicheck-scan.git /aicheck
  script:
    - cd /aicheck
    - python -m aicheck.scan "$TARGET" --allow-private --format json --fail-grade F > "$CI_PROJECT_DIR/aicheck.json" || code=$?
    - test -s "$CI_PROJECT_DIR/aicheck.json" && python -m aicheck.render "$CI_PROJECT_DIR/aicheck.json" --format sarif --redact > "$CI_PROJECT_DIR/aicheck.sarif" || true
    - test -s "$CI_PROJECT_DIR/aicheck.json" && python -m aicheck.render "$CI_PROJECT_DIR/aicheck.json" --format text || true
    - exit ${code:-0}
  artifacts:
    when: always
    reports:
      sarif: aicheck.sarif    # vulnerability report + MR security widget (GitLab Ultimate)
    paths:
      - aicheck.sarif
    expire_in: 30 days
```

On Free/Premium the findings print in the job log and the pipeline still
fails on grade — the SARIF dashboards (pipeline Security tab, vulnerability
report, MR widget) need Ultimate.

## Any CI with Docker

The same `ghcr.io/unauthdev/aicheck:v1` image works on Bitbucket Pipelines,
Azure DevOps, Jenkins, and bare CI runners — anywhere that can run a
container.

## CLI

The same engine runs standalone — install it from PyPI (see
[Install](#install-local-cli) above):

```bash
pip install aicheck-scan
aicheck localhost --allow-private
aicheck example.com --format sarif --fail-grade C
```

Exit codes: `0` pass, `1` grade at or worse than `--fail-grade`, `2` target
error. Without `--allow-private`, only public IPs/hostnames resolve (the CLI
guards against scanning internal infrastructure by accident).

Two flags expose the trust surface before and during a scan:

```bash
aicheck example.com --dry-run   # print every request it would send — no sockets, no DNS
aicheck example.com --verbose   # log each dialed connection (with pinned IP) to stderr
```

## License

MIT — see [LICENSE](LICENSE). Fix cards and grading by
[unauth.dev](https://unauth.dev); findings link to the public fix library at
`unauth.dev/fixes/`. Security reports: [SECURITY.md](SECURITY.md).
