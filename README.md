# aicheck-action

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-aicheck-orange?logo=github)](https://github.com/marketplace/actions/aicheck)
[![selftest](https://github.com/unauthdev/aicheck-action/actions/workflows/selftest.yml/badge.svg)](https://github.com/unauthdev/aicheck-action/actions/workflows/selftest.yml)
[![Docker image](https://img.shields.io/badge/ghcr.io-unauthdev%2Faicheck%3Av1-blue?logo=docker)](https://github.com/unauthdev/aicheck-action/pkgs/container/aicheck)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Fail the build if your PR ships an exposed self-hosted AI service.**

A GitHub Action that live-probes the AI stack your job just started — Ollama,
n8n, vLLM, Langfuse, Open WebUI, ComfyUI, Ray, Dify, Qdrant, AnythingLLM,
Jupyter, Gradio, Langflow, Flowise, Chroma, Weaviate, MCP servers — grades it
A–F, and reports the results in the run summary and code scanning, each
linking a plain-English fix card. From [unauth.dev](https://unauth.dev), the
free AI-stack exposure checker.

## Why live probing

This is not a config linter. The action starts from what actually answers:
it runs the same read-only GET probes the unauth.dev scanner runs, against
the real service in your job. If Ollama responds unauthenticated on 11434,
that's ground truth — no guessing from compose files, near-zero false
positives.

It answers one question: **"did this PR ship an AI service with no auth?"**
It does not prove internet reachability (your firewall/proxy is invisible
from CI) — that's what post-deploy monitoring is for.

## Usage

```yaml
name: ai-stack-exposure
on: [pull_request]

permissions:
  security-events: write   # for the SARIF annotations

jobs:
  aicheck:
    runs-on: ubuntu-latest
    services:
      ollama:
        image: ollama/ollama:latest
        ports: ["11434:11434"]
    steps:
      - uses: unauthdev/aicheck-action@v1
        with:
          target: localhost
          fail-grade: C      # D or F fails the build
```

The demo above fails: a default Ollama container is unauthenticated — that's
the point. Fix it (the annotation links the fix card), watch it go green.

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

## Privacy / supply chain

- **Runs entirely on your runner.** The only network traffic is read-only
  GETs to *your* target. Nothing is sent to unauth.dev or anywhere else —
  no telemetry, no phone-home, by design.
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
    - git clone --depth 1 --branch v1.0.3 https://github.com/unauthdev/aicheck-action.git /aicheck
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

The same engine runs standalone:

```bash
pip install httpx pyyaml
python -m aicheck.scan localhost --allow-private
python -m aicheck.scan example.com --format sarif --fail-grade C
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
`unauth.dev/fixes/`.
