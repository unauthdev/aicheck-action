# Probe model — what aicheck sends

This document is the contract for local / air-gapped inventory runs
(`aicheck inventory`) and the single-target CLI (`aicheck scan`).

## Probe classes

| Class | How to enable | Traffic | Where |
|---|---|---|---|
| **A (default)** | always on | GET-only metadata probes | CI, inventory, hosted scanner |
| **B (`--deep`)** | `--deep --i-own-these-targets [--deep-packs data-plane]` | Class A GETs **plus** whatever the enabled packs send (today: zero-byte TCP connects — see below) | Customer-run estate only; **never** on hosted unauth.dev |

Class B exists so enterprise mode can grow past GET-only without changing the
default trust story. Selecting an unknown `--deep-packs` name fails closed.

## Class B pack: `data-plane` (zero-byte TCP connect)

Enabled only by the full triple: `--deep --deep-packs data-plane
--i-own-these-targets`. Design doc: `docs/deep-pack-data-plane.md`.

**Exact traffic added** — per host, per scan, nothing else:

| Port | Product | What is sent |
|---:|---|---|
| 19530 | Milvus gRPC | One TCP connect-and-close. **Zero bytes sent.** |
| 6334 | Qdrant gRPC | One TCP connect-and-close. **Zero bytes sent.** |
| 50051 | Weaviate gRPC | One TCP connect-and-close. **Zero bytes sent.** |

- Full TCP handshake, then close immediately. No protocol bytes, no TLS
  detection, no banner reads — reachability only. Arguably less invasive than
  the Class A GETs.
- Same safety machinery as the GET probes: ssrf-validated pinned IPs (never a
  fresh DNS answer), 2s per-connect timeout, ~10s overall budget, bounded
  concurrency, `--verbose` connection log (`→ CONNECT tcp://host:19530 ...`),
  and full `--dry-run` disclosure (`CONNECT tcp://host:19530 (0 bytes)`).
- One connect per port per scan — no retry storms.
- Deliberately **no Redis :6379** (raw RESP stays out of scope) and no other
  products in v1.

**Evidence rule — port alone never creates a finding.** A data-plane finding
requires BOTH: the product identified by the Class A HTTP fingerprint on the
same host, AND a TCP accept on that product's data-plane port. The finding is
separate per product (`<product>-dataplane`, severity HIGH) with its own fix
card — it never upgrades the HTTP finding.

**What the finding claims:** the data plane *accepts connections from the
prober's position* (evidence names the method: `TCP connect accepted — 0 bytes
sent`). **What it deliberately does NOT claim:** that gRPC auth or TLS is
absent, or that vector data is accessible. Connect-only cannot know —
reachable ≠ data accessible. CRITICAL stays reserved for proven
unauthenticated data access, which this probe can never prove.

## Class A guarantees (default)

| Rule | Detail |
|---|---|
| **Method** | HTTP **GET only** |
| **No auth** | No logins, no Bearer/Basic attempts, no cookie jars |
| **No writes** | No POST / PUT / PATCH / DELETE to the target |
| **No exploits** | No exploit verification, no model pulls, no payload injection |
| **Body cap** | Response bodies truncated at **64 KiB** |
| **Timeouts** | Connect 3s, overall request 5s; whole gather budget ~40s per host |
| **Concurrency** | Up to 12 probes in flight per host |
| **User-Agent** | `aicheck/0.1 (+exposure-checker; safe metadata GETs only)` |
| **Phone-home** | **None.** Inventory writes only to `--state-dir` on the machine you run it on |
| **DNS pinning** | Resolved IPs are pinned for the scan; redirects that leave the host are blocked |

## Permissions required

- Outbound TCP from the runner to the **targets you listed** on the well-known ports below.
- No cloud roles, no agent, no privileged host access.
- For internal ranges: pass `--allow-private --i-own-these-targets` (RFC1918 / localhost / link-local — the pair acknowledges you own the sweep targets).

## Ports and paths probed

Content fingerprints decide the product — **port alone never creates a finding**.
Source of truth: `aicheck/recon.py` → `PROBES`.

| Port | Paths (representative) | Products (if content matches) |
|---:|---|---|
| 80 | `/`, `/signin` | Dify, Attu (Milvus UI) |
| 11434 | `/`, `/api/version`, `/api/tags` | Ollama |
| 5678 | `/`, `/rest/settings` | n8n |
| 8080 | `/`, `/api/config`, `/v1/models`, `/v1/meta`, `/v1/schema`, MCP paths, … | Open WebUI, Weaviate, OpenAI-compat, MCP, … |
| 8000 | `/v1/models`, Chroma heartbeats/collections, OpenAPI/docs, MCP, … | vLLM, Chroma, LangServe, AutoGen, Attu (Milvus UI), … |
| 8188 | `/`, `/system_stats`, `/api/manager/version` | ComfyUI |
| 8265 | `/`, `/api/version`, `/api/jobs/`, `/nodes` | Ray |
| 6333 | `/`, `/collections` | Qdrant |
| 9091 | `/healthz`, `/` | Milvus (Server-header fingerprint) |
| 8888 | `/`, `/api/status`, `/api/kernels` | Jupyter |
| 7860 | `/`, `/config`, `/api/v1/version`, `/health` | Gradio / Langflow |
| 3000–3001 | health/version/auth/MCP/well-known | Langfuse, Flowise, Dify UI, MCP, Attu (Milvus UI), … |
| 5000–5001 | `/`, `/version`, Dify console, MCP | MLflow, Dify API, MCP |
| 4000 | `/v1/models`, `/health`, OpenAPI | LiteLLM / OpenAI-compat |
| 443 | `/v1/models`, `/.well-known/mcp*` | HTTPS OpenAI-compat / MCP discovery |
| 18789 | `/`, OpenClaw control-ui config | OpenClaw |
| 5540 / 8001 / 8081–8082 | RedisInsight / Commander HTTP consoles | Redis consoles (not raw RESP :6379) |
| 1234 | LM Studio greeting / models | LM Studio |
| 8501 | `/auth/login` | CrewAI Studio |

Port **443** uses `https://`; all other listed ports use `http://`.

## How a finding is produced

1. Runner resolves the host (pinned IPs).
2. Issues the GET probes above; connection errors are non-findings.
3. Each checker requires a **content fingerprint** (e.g. Ollama body contains
   `Ollama is running`, or `/api/version` JSON with `version`).
4. Optional: version string → curated CVE map / vuln lookup (annotation only
   unless a dedicated CVE finding is emitted).
5. Output includes `evidence` (URL + status) and `how_produced` explaining the
   probe class. Severity is not LLM-assigned.

## Auth-walled services (observations)

A probe answered with 401/403 (or a login wall) is never a finding — but when
the product is still confidently fingerprinted (the walled response itself
carries a product-unique marker, e.g. a `Server: Milvus/...` header, or a
sibling probe already fingerprinted the product), the checker emits an
**observation**: severity `INFO`, `details.auth = "present"`, reported on a
separate output channel (`observations` in scan/inventory JSON, note-level in
SARIF). Observations are never graded and never fail CI. A bare 401 on a
well-known port with no product marker produces nothing — the FP bar is the
same as for exposures. This needs no extra traffic: observations reuse only
the probe plan above.

## What this deliberately misses

Documented limits (not bugs):

- Authenticated-but-vulnerable services (token present, still RCE-prone —
  auth-walled services are reported as INFO observations, not tested)
- Non-standard ports not in the probe list
- Services only reachable behind a reverse proxy on an unlisted path/host
- Raw Redis RESP (`:6379`) — HTTP consoles only
- Business ownership / prod-vs-dev — supply via the targets file (`owner`, `env`);
  the scanner does not invent CMDB data

## Inventory outputs (local only)

```
state-dir/
  state.json       # current open findings by finding_id
  latest.json      # last run report (includes drift)
  runs/<run_id>.json
```

Drift keys: `new`, `fixed`, `still_open`. Finding IDs are stable hashes of
`check_id|host|url-shape` so re-runs dedupe without a SaaS backend.
