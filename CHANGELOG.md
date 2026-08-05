# Changelog

Notable changes per release. Full notes and SHA-256 sums: [GitHub releases](https://github.com/unauthdev/aicheck-scan/releases).

## v1.2.5 — 2026-08-05

- Passive discovery: `aicheck inventory --flow-logs` turns AWS VPC flow logs (or generic JSONL) into an attributed AI-service inventory with zero probing. `--verify` sweeps what it finds.
- First Class B pack: `data-plane` — zero-byte TCP connect checks to Milvus :19530, Qdrant :6334, Weaviate :50051 (gated by `--deep --deep-packs data-plane --i-own-these-targets`).
- Public advisory dataset (`advisories.yaml`, CC-BY 4.0): exposure classes + curated CVEs with stable IDs.

## v1.2.4 — 2026-08-05

- Auth-state observations: findings (no-auth, graded), observations (auth-walled, INFO, never graded), unknown (partial coverage, surfaced).

## v1.2.3 — 2026-08-04

- Milvus + Attu checker (healthz Server-header fingerprint with version).
- Structured CVE fields in findings (`details.cves[]`, version-gated); pre-release version parsing fixed.
- Fingerprint hardening across 6 checkers, validated against ~1,100 real banners with zero cross-false-positives.
- Inventory drift honesty: unreachable hosts no longer report "fixed"; per-host errors can't kill a run; `changed` drift bucket; CIDR cap checked before expansion.
- Scan coverage surfacing: partial scans are marked, not presented as clean.
- Schema freeze: `schema_version: 1` on inventory report/state/webhook payloads.
- Webhook: HMAC signatures (`--webhook-secret`), retries, loopback/link-local blocked by default.
- `--allow-private` now requires `--i-own-these-targets`.
- Supply chain: SBOMs and build provenance on PyPI and Docker, digest-pinned base image, bounded dependency ranges, release-notes hashes, test gate before publish.

## v1.2.2 — 2026-08-04

- Inventory webhook, CIDR/CSV/JSONL target ingestion.

## v1.2.1 — 2026-08-04

- Class A/B probe gate for inventory `--deep`.

## v1.2.0 — 2026-08-04

- Local inventory mode and unified `aicheck` CLI (`scan` + `inventory`).

## v1.1.x — 2026-08-01 → 2026-08-03

- MCP checker set, agent-framework checkers (LangServe, CrewAI, Flowise, Dify, Langfuse), memory-risk finding class (Chroma/Qdrant/Weaviate/Redis consoles).
- `--dry-run` and `--verbose` trust-surface flags, exit-code discipline (0/1/2).
- Trusted PyPI publishing (OIDC), SLSA provenance, redaction pipeline, Marketplace listing.

## v1.0.x — 2026-07-31

- First public releases: single-host live-probe scanner, grade A–F, SARIF, fix cards.
