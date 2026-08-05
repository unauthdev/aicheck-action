# Advisory dataset schema v1

`aicheck/content/advisories.yaml` — the public unauth.dev advisory dataset
("KEV for AI exposure"), also served as JSON at `GET /advisories.json` and
rendered record-by-record under `/advisories/<id>`. Mirrored to the public
repo (`unauthdev/aicheck-scan`) by `scripts/action_sync.py` so it can be
forked, diffed, and cited.

**License:** CC-BY 4.0 — attribution "unauth.dev / Raúl Acedo". The dataset
(including the rendered advisory pages and `/advisories.json`) is the only
CC-BY part of unauth.dev; site copy and brand stay proprietary.

**Stability promise:** additive-only within v1 (new fields may appear;
consumers must tolerate unknown keys). Renames, removals, or type changes
bump `schema_version`. Record ids (`UNAUTH-2026-NNNN`) are assigned once
and **never renumbered, reused, or repurposed**; new records append with
the next sequential number. A record whose source is retired stays retired
— its id is never recycled.

## Top level

| field | type | meaning |
|---|---|---|
| `schema_version` | int | Always `1`. |
| `records` | list[object] | Advisory records. Exposure-class records first (they are the point of the dataset), then CVE records. |

## Record kinds

`type` is `exposure-class` or `cve`.

**Exposure-class** records describe self-hosted AI *deployment exposure
semantics* — unclaimed setup pages, no-auth-by-design APIs, agent-memory
stores left open. These are not CVE-shaped: no CNA or bounty program will
ever record them. One record per `*-exposed` fix card
(`aicheck/content/fix_cards.yaml`).

**CVE** records are the commodity layer: curated version→CVE mappings from
`aicheck/content/cve_map.yaml`, carried with their verification provenance.
They exist so consumers get both layers from one feed.

## Record fields

Fields present on every record:

| field | type | meaning |
|---|---|---|
| `id` | string | `UNAUTH-2026-NNNN` — stable forever, zero-padded, sequential. |
| `type` | string | `exposure-class` \| `cve`. |
| `product` | string | Product name as the scanner reports it. |
| `title` | string | One-line title. |
| `summary` | string | Plain-English risk (from the fix card's `plain_english_risk` / the curated CVE summary). |
| `severity` | string | `CRITICAL` \| `HIGH` \| `MEDIUM`. |
| `fix_card_id` | string | Remediation pointer — resolves at `/fixes/<fix_card_id>`. |
| `references` | list[string] | Vendor / advisory URLs. Non-empty. |
| `in_the_wild` | object \| null | Honeypot telemetry — see below. |
| `published` | string | ISO date first published. |
| `updated` | string | ISO date the record content last changed. |

Exposure-class-only fields (null on `cve` records):

| field | type | meaning |
|---|---|---|
| `exposure_class` | string | `no-auth-by-design` \| `unclaimed-setup` \| `agent-memory-store` \| `agent-trace-store` \| `tool-transport` \| `data-plane`. |
| `owasp` | list[string] \| null | OWASP references (e.g. `["ASI06"]` for agent-memory stores). |
| `observable` | string | One line: what a GET-only probe sees, from the checker's fingerprint contract. Never port-only guesses. |
| `reachability_note` | string | "Exposed to the internet" vs "normally internal-only" semantics. |
| `cve` | null | Reserved (always null on exposure-class records in v1). |

CVE-only fields (absent on `exposure-class` records):

| field | type | meaning |
|---|---|---|
| `cve` | string | CVE id, upper-case. |
| `affected` | string \| list[string] | Version-range expression(s), same grammar as `cve_map.yaml`. |
| `fixed_in` | string | Fixed version(s), verbatim from the vendor advisory. |
| `kev` | bool | True when CISA KEV-listed at curation time. |
| `human_approved` | bool | A human verified the mapping against the linked advisory. |
| `last_verified` | string \| null | ISO date of that verification. |

`verification_state` (`verified` \| `stale` \| `unreviewed`) is **derived at
read time** from `human_approved` + `last_verified` by
`aicheck/checks/cvemap.py` (stale = verification older than 180 days) and
rendered on the advisory page; it is deliberately not stored, so it can
age honestly.

## `in_the_wild` — honeypot evidence

Only unauth.dev can publish this field: it comes from our own deliberately
exposed honeypot (botwatch), refreshed monthly. `null` when the honeypot
has no data for the record's service — **numbers are never invented or
estimated**; a record without telemetry simply has no block.

| field | type | meaning |
|---|---|---|
| `service` | string | Honeypot service id (e.g. `ollama`, `mcp`). |
| `first_seen` / `last_seen` | string | First / latest calendar day (ISO) with at least one probe, within retained history. |
| `probes_30d` | int | Probes in the trailing 30 calendar days ending at the latest telemetry day. |
| `probes_observed` | int | Total probes across all retained history (bounded — live stats keep 90 days). |
| `source` | string | Always `unauth.dev botwatch honeypot`. |

Counts are day-granularity aggregates from the published monthly botwatch
releases (`/releases/YYYY-MM/botwatch.json`), merged with live stats when
present. No source IPs exist anywhere in the underlying data (dropped on
the honeypot before export).

## Citing a record

Each rendered record page carries a copy-able canonical citation line:

```
unauth.dev advisory UNAUTH-2026-0007 — observed 2026-08 · CC-BY 4.0
```

`observed <month>` appears when the record has `in_the_wild` telemetry
(the telemetry month); otherwise the line reads `published <month>`.
The canonical URL is `https://unauth.dev/advisories/<id>`.
