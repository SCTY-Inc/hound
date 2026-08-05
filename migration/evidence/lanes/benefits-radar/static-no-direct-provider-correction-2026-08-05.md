# benefits-radar: static no-direct-provider evidence — correction (2026-08-05)

This addendum corrects `static-no-direct-provider.md` in this directory,
which is not edited in place: its content hash
(`d6d633fd285d3a4f63df7a5b695dbef093d17a605b009fba1d9ec732e8a59ddf`) is bound
by the gate receipt `migration/approvals/receipts/gate-benefits-radar-migrated-2026-08-04.json`
(subject artifact for this exact path) and the chained decision entry in
`migration/approvals/decisions.jsonl` (`receipt_hash`
`7d82f6129d9a3c2433495ba3faf641b014a78ec34e9157e2aafb097617cb499a`). Editing
that file would break the HSP-22 approval-chain binding it already sealed.

## What the original claim got wrong

The original file claimed "zero provider indicators in
`repos/givecare/gc-benefits` lane code" based on a scan scoped to
`agents/` only, and asserted gc-benefits commit `abffd89` "deleted the
direct-provider path." Both are false as stated: `abffd89` did not delete
the `benefit_engine` pipeline, and a whole-repo scan of `gc-benefits` finds
direct Firecrawl usage still present.

## What is actually true

- **The radar lane code is clean.** `scripts/daily_hound_radar.py` and
  `src/benefit_engine/houndd_backend.py` — the code that runs the
  `benefits-radar` acquisition — hold no provider indicators. This is the
  part of gc-benefits the migrated lane and its E4 approval gate actually
  cover.
- **Evidence**: E3's real repo-wide ownership scan,
  `migration/evidence/e3/ownership-scan-givecare.json` (scan date
  2026-08-05, workspace `/home/deploy`, roots including
  `repos/givecare/gc-benefits`). That scan finds zero HSP-19 hits under
  `scripts/daily_hound_radar.py` or `src/benefit_engine/houndd_backend.py`.
- **The sibling `benefit_engine` pipeline is not clean, and was never in
  scope.** `.env`, `vetting/firecrawl-fetch.py`,
  `vetting/vet-loop-contract.schema.json`,
  `src/benefit_engine/{etl,firecrawl,harness,sweep}.py`,
  `src/benefit_engine/cli/{intake,records}.py`,
  `scripts/{enrich_programs,ingest_batch}.py`, and
  `data/{run_history,source_registry}.jsonl` retain direct Firecrawl (and,
  for `ingest_batch.py`, Discord) credential/SDK usage. This is legacy
  ETL/intake tooling that D1 (2026-08-04, Ali) already dropped from the
  Hound migration's scope, not code the `benefits-radar` cutover touched.
  It is now a named exception under D12 (2026-08-05, Ali), tracked in
  `migration/domain-ownership-allowlist.v1.json` and
  `docs/credential-exceptions.md`.

## Net effect on the approval

The `benefits-radar` migrated-gate approval is unaffected: it covers the
radar lane's own acquisition code, which this correction confirms is
genuinely clean. What was wrong was the *scope claim* about the rest of the
gc-benefits repo, not the lane's own status.
