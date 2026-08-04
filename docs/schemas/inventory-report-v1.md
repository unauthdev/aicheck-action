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
