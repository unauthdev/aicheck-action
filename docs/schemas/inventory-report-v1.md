# Inventory report schema v1

The JSON written to `<state-dir>/runs/<run_id>.json`, mirrored to
`<state-dir>/latest.json`, and printed by `aicheck inventory --format json`.
`state.json` shares the same `schema_version`.

**Stability promise:** additive-only within v1 (new fields may appear;
consumers must tolerate unknown keys). Renames, removals, or type changes
bump `schema_version`.

## Top level

| field | type | meaning |
|---|---|---|
| `schema_version` | int | Always `1` (`SCHEMA_VERSION` in `aicheck/inventory.py`). |
| `run_id` | string | UTC timestamp `YYYYMMDDTHHMMSSZ`; a `-<hex>` suffix is appended on same-second collision (prefix stays sortable). |
| `started_at` / `finished_at` | string | UTC ISO-ish `YYYY-MM-DDTHH:MM:SSZ`. |
| `target_count` | int | Targets swept this run (after expansion). |
| `finding_count` | int | Open findings after the run (includes carry-over from unprobed hosts). |
| `services_filter` | list[string] \| null | `--services` product filter in effect; `null` = all products probed. When set, other products were not probed or graded. |
| `drift` | object | See below. |
| `targets` | list[object] | Per-target rows, input order. See below. |
| `phone_home` | bool | Always `false`. Inventory is local-only. |
| `probe_model` | string | Pointer to `docs/PROBES.md` (traffic contract). |
| `probe_mode` | object | `ProbeMode.to_dict()` — probe class, deep flags, methods, note. |
| `passive` | object | **Additive within v1.** Present only when the run used `--flow-logs`. See below. |

## `drift`

| field | type | meaning |
|---|---|---|
| `new_count` / `fixed_count` / `changed_count` / `still_open_count` | int | Bucket sizes. |
| `new` | list[finding] | Findings first seen this run. |
| `fixed` | list[finding] | Findings gone on a successfully probed host (stamped `status: "fixed"`). |
| `changed` | list[finding] | Same stable `finding_id`, but `severity` / `details.version` / `details.known_cve_count` moved; each row carries `changes: {field: {was, now}}`. |
| `still_open` | list[finding] | Present before and now, unchanged. |

Hosts not successfully probed this run (`unreachable` / `error` / `rejected`)
are excluded from every drift bucket — a dead host never looks remediated.

## `targets[]` row

| field | type | meaning |
|---|---|---|
| `host` | string | Target as swept. |
| `owner` / `env` | string \| null | From the targets file. |
| `status` | string | `done` (at least one probe answered), `unreachable`, `rejected` (SSRF guard), or `error`. |
| `error` | string \| null | Reason when status is not `done`. |
| `grade` | string \| null | Letter grade; `null` unless `done`. |
| `coverage` | object \| null | `{probes_total, probes_answered, partial}`. |
| `findings` | list[finding] | Enriched findings (empty unless `done`). |
| `observations` | list[observation] | Auth-walled-but-fingerprinted services (severity `INFO`). **Additive within v1** (added after freeze). Empty unless `done`. |

## observation (additive within v1)

An observation is a raw checker `Finding.to_dict()` (same shape as
`aicheck scan --format json` findings): `check_id`, `product`, `title`,
`severity` (always `"INFO"`), `url`, `evidence`, `fix_card_id`, `details`
(always `details.auth == "present"`). It means the product was confidently
fingerprinted — same product-unique evidence bar as an exposure — but its
API/UI demands authentication (401/403 or a login wall).

Observations are **never graded** and deliberately **not diffed by drift in
v1**: they carry no `finding_id`, enter no drift bucket, and are not
persisted to `state.json`. Diffing observations is a deliberate deferral,
candidates for a future schema version.

## `passive` (additive within v1)

Present only on runs with `--flow-logs` (see `docs/flow-logs.md`). Produced
by `flowlogs.analyze` (`aicheck/flowlogs.py`) — offline analysis of VPC flow
telemetry; a passive-only run sends no traffic, sweeps nothing, and does not
touch `state.json`. Passive rows are **not** findings: they enter no drift
bucket, carry no `finding_id`, and are never graded.

| field | type | meaning |
|---|---|---|
| `source` | string | Flow-log file analyzed. |
| `format` | string | `aws-vpc-flow-text` or `jsonl`. |
| `lines_total` / `lines_malformed` | int | Lines seen / skipped as malformed (never fatal). |
| `flows_rejected_action` | int | Flows with non-ACCEPT action (not usage). |
| `window` | object \| null | `{start, end}` ISO UTC across all flows. |
| `scanner_networks` | list[string] | Scanner CIDRs in effect (seed + `--scanner-networks`). |
| `hosts` | list[object] | Per-host passive evidence (below). |
| `discovered_targets` | list[object] | `{host, owner, env}` rows — feeds back as `--targets` input (targets JSONL v1). |
| `targets_path` | string \| null | Where the discovered-targets JSONL was written. |

### `passive.hosts[]` row

`{host, rows, observations, hints}`. `observations` holds
`"already internet-scanned / likely in public indexes"` when AI ports
received ACCEPTED connections from scanner networks. `hints` holds
`"possible Attu UI — verify with a probe"` only when the host has BOTH a
Milvus flow-candidate (:9091/:19530) AND web flows on :3000/:8000 — a hint,
never a finding (generic web ports are unattributable passively).

Each `rows[]` entry:

| field | type | meaning |
|---|---|---|
| `host` / `product` / `port` | string / string / int | Candidate attribution. |
| `role` | string | `data-plane` (19530/6334/50051, from recon topology), `management`, `api`, `web`, … |
| `tier` | string | `port-attributed candidate` (noise-only flows) or `flow-shape corroborated` (≥ 1 real session above the noise rule: `bytes < 200 AND packets <= 2` = probe noise). |
| `title` | string | e.g. `Milvus candidate — port evidence (data-plane :19530)`. |
| `accepted_flows` / `real_sessions` / `noise_flows` / `bytes` | int | Flow counts and byte total. |
| `window` | object | `{start, end}` ISO UTC for this port's flows (values may be null). |
| `evidence` | string | Always `flow-attributed — content unverified (N accepted flows, X MB, window W)`. |
| `scanner_observation` / `scanner_sources` | string \| null / list[string] | Set when scanner networks hit this port. |
| `verification` | string | `unverified — host not probed` (passive-only), or after `--verify`: `probe-verified` / `unverified — probe did not confirm`. |


## finding (enriched)

Produced by `enrich_finding` (`aicheck/inventory_findings.py`). Canonical
names only — schema v1 has **no aliases** (`id`→`finding_id`,
`asset`→`host`, `environment`→`env` were dropped before freeze).

| field | type | meaning |
|---|---|---|
| `finding_id` | string | Stable 16-hex id: sha256 of `check_id|host|scheme|port|path`. Drives drift. |
| `check_id` | string \| null | Checker that produced it (e.g. `ollama`). |
| `product` / `title` / `severity` | string \| null | From the checker. |
| `host` | string | Host the finding belongs to. |
| `url` / `evidence` | string \| null | Probe URL and what came back. |
| `how_produced` | string | Probe narrative (GET-only, version, CVE correlation, data sensitivity). |
| `description` | string | Prose block for tickets/SIEM (asset, evidence, remediation). |
| `fix_card_id` / `fix_url` | string | Remediation pointer (`fix_url` null without a card). |
| `references` | list[string] | Fix URL + optional vendor reference. |
| `owner` / `env` | string \| null | From the targets file. |
| `version` | string \| null | Version reported by the target. |
| `cves` | list[string] | Correlated CVE ids (upper-case). |
| `risk_class` | string \| null | e.g. `agent-memory`, `agent-traces`, `agent-runtime`. |
| `tool` | string | Always `aicheck-inventory`. |
| `status` | string | `open` (or `fixed` in the drift `fixed` bucket). |
| `details` | object | Raw checker details (`version`, `known_cve_count`, `risk_class`, ...). |
| `first_seen` / `last_seen` | string | Stamped per run (present on report/state findings, not on bare `enrich_finding` output). |

## `state.json`

Top level: `schema_version` (int), `findings` (map of `finding_id` →
finding), `last_run_at` (string), `last_run_id` (string). A state file
that is unparseable, not a v1 dict, or lacks a `findings` map is moved
aside to `state.json.corrupt-<ts>` and the run starts clean (stderr
warning, never a crash).

## Webhook payload

`webhook_payload` (`aicheck/inventory_webhook.py`) is derived from the
report: `event`, `tool`, `schema_version`, `run_id`, `started_at`,
`finished_at`, `target_count`, `finding_count`, `probe_mode`,
`phone_home`, and a `drift` summary (`new` in full; `fixed`/`changed`
trimmed to id/title/product/host/changes). POSTed with
`follow_redirects=False`; 3xx/4xx are errors; timeout/5xx/connection
errors retry twice (3 attempts, short backoff).

With `--webhook-secret <s>` the exact request body is signed:
`X-Aicheck-Signature: sha256=<hmac_hex>`. Verify receiver-side (Python):

```python
import hashlib, hmac
expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, request.headers["X-Aicheck-Signature"])
```

Egress: loopback and link-local (169.254.0.0/16, cloud metadata) webhook
hosts are blocked unless `--webhook-allow-local`; internal RFC1918 SIEM
endpoints are allowed by design (inventory runs on the customer network).
Plain `http://` warns loudly on stderr but is honored.
