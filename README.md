# aicheck-action

**Fail the build if your PR ships an exposed self-hosted AI service.**

A GitHub Action that live-probes the AI stack your job just started — Ollama,
n8n, vLLM, Langfuse, Open WebUI, ComfyUI, Ray, Dify, Qdrant, AnythingLLM,
Jupyter, Gradio, Langflow, Flowise, Chroma, Weaviate, MCP servers — grades it
A–F, annotates the PR via SARIF, and links every finding to a plain-English
fix card. From [unauth.dev](https://unauth.dev), the free AI-stack exposure
checker.

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

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `target` | *(required)* | Host to probe. No port — well-known AI-service ports are probed. |
| `fail-grade` | `F` | Fail if the grade is this or worse. `F` = only critical exposure fails; `C` = anything above clean fails. |
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

## License

MIT — see [LICENSE](LICENSE). Fix cards and grading by
[unauth.dev](https://unauth.dev); findings link to the public fix library at
`unauth.dev/fixes/`.
