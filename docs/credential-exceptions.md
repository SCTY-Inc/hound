# Provider-credential exceptions to HSP-19

<!-- Diátaxis: reference -->

HSP-19 (`migration/check_domain_ownership.py`) enforces that provider
credentials, SDKs, and endpoints live only inside `repos/hound`. Every
domain-repo hit is a violation unless it is named here and in
`migration/domain-ownership-allowlist.v1.json` — an allowlist entry silences
enforcement, never visibility; allowlisted hits still appear in the
capability dump, tagged with their reason and decision reference.

This is the full exception list. There is no default exception.

## gc-benefits: `benefit_engine` legacy ETL/intake pipeline

- **Scope**: `repos/givecare/gc-benefits/.env`,
  `vetting/firecrawl-fetch.py`, `vetting/vet-loop-contract.schema.json`,
  `src/benefit_engine/{etl,firecrawl,harness,sweep}.py`,
  `src/benefit_engine/cli/{intake,records}.py`,
  `scripts/{enrich_programs,ingest_batch}.py`,
  `data/{run_history,source_registry}.jsonl`.
- **Decision**: D12 (2026-08-05, Ali).
- **Reason**: D1 (2026-08-04, Ali) already dropped benefits-legacy from the
  Hound migration's scope — the radar lane covers benefits discovery, and no
  adapter contract was ever specified for this pipeline. It is legacy
  ETL/intake tooling, sibling to but outside the migrated
  `benefits-radar` lane (`scripts/daily_hound_radar.py`,
  `src/benefit_engine/houndd_backend.py`), which stays clean and holds no
  provider indicators. The acceptance sentence "provider credentials exist
  only inside houndd" is scoped to migrated GiveCare lane acquisition, not
  to this deferred pipeline.
- **Re-entry condition**: this pipeline is repointed at `houndd` (or
  retired), at which point the corresponding allowlist entries are deleted
  in the same change, not left stale.

## Everything else

No other domain repo holds a named exception. `Exa`/`Firecrawl`/`Brave`
credentials remain in `/home/deploy/.env` for non-GiveCare skill consumers
(D7, D9) — those consumers are shared skills, not GiveCare lane code, and
never appear in this scanner's roots.
