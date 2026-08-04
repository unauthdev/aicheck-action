# Targets JSONL input schema v1

Accepted input for `aicheck inventory --targets file.jsonl` (and flow-log-ish
exports auto-detected as JSONL). This documents the *input* fields; lines
are not versioned — the loader accepts the aliases below for compatibility
with common export formats. Loader: `load_targets` in
`aicheck/inventory_targets.py`.

## Line shape

One JSON object per line. Blank lines and `#` comments are skipped.

```jsonl
{"host": "10.0.1.5", "owner": "ml-platform", "env": "production"}
{"ip": "10.0.2.8", "owner": "data-science", "environment": "development"}
{"cidr": "10.0.3.0/28", "owner": "platform"}
```

## Fields

| field | type | meaning |
|---|---|---|
| host (required, one of) | string | Bare host or IPv4, or a CIDR. Accepted keys, first non-empty wins: `host`, `ip`, `addr`, `address`, `dstaddr`, `srcaddr`, `destination_ip`, `source_ip`, `private_ip`, `public_ip`. `cidr` is used only when none of those are present. |
| `owner` | string | Owning team/person; carried into findings and reports. Optional. |
| `env` | string | Environment tag. `environment` is accepted as an alias. Optional. |

Unknown fields are ignored — exports with extra columns are fine.

## Expansion and bounds

- A CIDR in `host`/`cidr` expands to individual IPs (network/broadcast
  skipped for IPv4), capped per CIDR by `--max-hosts` (default 256).
  `--no-expand-cidrs` treats CIDR strings as literal hostnames.
- Hosts are deduped case-insensitively (trailing dot stripped), first
  occurrence wins.
- After all sources expand, a run is refused when the total exceeds
  `--max-total-targets` (default 1024).
- Sweeping RFC1918/localhost targets requires `--allow-private` together
  with `--i-own-these-targets`.

## Other accepted formats

The same `targets:` list shape works in YAML/JSON files, plus CSV (header
row, same keys) and plain text lines (`host [owner] [env]`). Per-target
fields after loading are always `host`, `owner`, `env`.
