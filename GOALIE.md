# Goal: hound is the single external-ingestion engine and provenance ledger for every lane

Status: **Active — planned 2026-08-03 (supersedes the completed 2026-07 hard-cut goal; see git history)**

Baseline for this plan: full-suite 1337 passed at `b0a7bdd`; three-agent contract review of 2026-08-03 (Slice 3B faithful with 3 drifts; Slice 3C1 coded but unwired with 6 verified violations; HSP matrix 9 done / 6 partial / 7 absent).

## Outcome

All in-scope external acquisition (search, URL, file, media, transcription)
happens only through `houndd`-owned adapters and lands in one chronological,
inspectable, provenance-bearing journal. Every lane in
`migration/consumer-inventory.v1.json` reaches stage `migrated` (legacy paths
`retired`), consumers read via `hound-research` / cursors / the intake-ledger
view, provider credentials exist only inside `houndd`, and the VISION.md
HSP-01..22 acceptance table passes as one machine-verifiable command.

## Acceptance criteria

1. All six ingest operations (`ingest.search|url|file|media`, `transcribe`,
   `import.record`) dispatch live on the socket, journaled, with crash-matrix
   recovery tests passing against a **wired** runtime (no 503-placeholder
   assertions remain).
2. `hound-research` exposes the nine target operation families from VISION.md
   §"Exact CLI, API, and service contract".
3. Every inventory lane row: stage `migrated`, all nine evidence slots
   non-null, `approval_ref` set from an explicit Ali cutover decision;
   superseded legacy paths at `retired` only after recovery drill + one full
   scheduled cycle.
4. Dynamic no-bypass: every migrated consumer runs with provider credentials
   unset and either succeeds through the Unix socket or fails closed; the
   static scanner passes with exclusions limited to the allowed set.
5. `migration/acceptance.v1.json` claims all 22 HSP rows with named evidence,
   one-to-one traceability, and the full acceptance command green in CI.
6. *(added 2026-08-03, Ali)* The GiveCare Chief-of-Staff thread
   (`~/agents/config/chief-of-staff-thread`) and every GiveCare bb automation
   (`pulse-daily`, `discovery-benefits`, `refresh-wiki`, `intel-refresh`,
   `refresh-policy`, `radar-curation`, `signal-daily`, `loop-company`) complete
   one full scheduled cycle with hound as the sole acquisition path: correct
   terminal tokens reported, dependency rack green with no hound-caused
   `unknown`, `owner_queue.py` deriving matching domain results.

## Inventory (canonical: migration/consumer-inventory.v1.json)

**Jobs (operation families)** — status at plan time:

| Op | State |
|---|---|
| `journal.query` (+ intake-ledger view) | live |
| `ingest.file`, `import.record` | coded, unwired (Slice 3C1 dark) |
| `ingest.search`, `ingest.url`, `ingest.media`, `transcribe` | reserved, no code |
| `journal.get`, `journal.verify`, `journal.rebuild-index` | library-only, no route/CLI |

**Lanes (16)** — wave order per inventory; (B) = blocked_contract needing an owner decision:

- W2: pulse, benefits-radar, benefits-legacy (B)
- W3: wiki-refresh, intel-refresh, civic-policy-radar (B)
- W4: radar-curation, gmail-newsletters-attachments (B), manual-web, manual-x,
  youtube-transcription, signal-daily (B), workpad-intake-ledger (read
  client), gc-gtm-crm (consumer-only)
- W5: atelier-entity-discovery, helm-external-ingestion (B)

## Tasks

Dependency spine: R → W → B → M; C after W; D gates the marked M lanes; E1–E6
after first migrations; E7 last; V closes the goal. No two tasks own the same
file.

### Phase R — repair in-flight Slice 3C1 + 3B drift (hound repo only)

| ID | Status | Contract | Proof |
|---|---|---|---|
| R1 | complete (Codex fe0c007) | Interrupted-recovery triad: stop setting `dedupe.content_sha256` blob expectations on interrupted events (`commit_runtime.py:711`), make `verify.py:211,218-220` accept blob-less interrupted file/import events, implement interrupted `import.record` recovery per contract (`[import-outcome-id]` only, no raw object) replacing the raise at `commit_runtime.py:679-680`. | Red test: crash at `after_open` for both ops → reconcile → `verify_store.valid == true` → service restarts; response IDs exact. |
| R2 | complete (2026-08-03) | Commit atomicity: compute journal sequence at publish time (not baked at `commit_runtime.py:612`); write reservation+open marker as one fsynced validated unit. | Red test: crash at `after_record`, interleaved unrelated append, reconcile appends the event once; kill inside pair-write window → clean recovery, not unstartable. |
| R3 | complete (2026-08-03) | Authorization ceiling on commit path: intersect lineage scope with `_ACCESS_CEILINGS[requested_access]` at `service.py:544`; `scope=None` default in `commit_runtime.py:588` becomes deny. | Red test: restricted-granting policy + `requested_access: public` import cannot inherit restricted lineage. |
| R4 | complete (2026-08-03) | Tampered finalized reservation on hot path is 503 integrity, never 400 collision: validate pair before hash comparison (`commit_runtime.py:225-230`). | Red test: rewrite `canonical_request.policy_id` in finalized reservation → replay returns 503. |
| R5 | complete (2026-08-03) | Commit dispatch catches `PolicyError`/`ServiceError` → logical 503 (`service.py:601-604`), matching read path. | Red test: replace policy.json mid-session → POST returns 503 body, not dropped connection. |
| R6 | complete (2026-08-03) | 3B drift: emit `filter_not_available` error code (`service.py:640-641,681-682`); unsigned `SO_PEERCRED` uid unpack (`service.py:694-695`); authenticate cursors before the empty-visible-scope short-circuit (`snapshot.py:414,464,535`). | Wire test asserting the error code; uid ≥ 2³¹ principal test; forged-cursor-on-empty-scope → 400. |
| R7 | complete (2026-08-03) | Minor: `evidence_status` mapping already gone at HEAD; strict record/event binding validation landed in verify.py (Codex, one-event-per-outcome cardinality check + symmetric bindings); dead assignments removed from store.py put_bytes. Residual gap: verify.py's new evidence_status/artifact/usage bindings have negative-test coverage only for cardinality — fold into W3 evidence work. | Schema negative tests; suite green. |

### Phase W — wire Slice 3C1 live

| ID | Status | Contract | Proof |
|---|---|---|---|
| W1 | complete (Codex fe0c007 + 2026-08-03 repairs) | Construct `CommitRuntime` in service startup; call its `reconcile()` from `HounddStore.recover()`; replace every 503-placeholder assertion with live-commit assertions. Depends R1–R5. | Full crash matrix (kill at each commit point) against the wired service; `ingest.file` + `import.record` end-to-end over the socket. |
| W2 | mostly complete (Codex fe0c007) | `hound-research ingest file` and `import-record` commands exist and are wired to `commit_client`. Remaining: confirm client XDG socket default and run the installed-console smoke (file on disk → journal entry → `journal query` shows it with provenance) after reinstalling the tool. | Installed-console smoke. |
| W3 | pending | Seal Slice 3C1: evidence bundle under `tests/evidence/slice3c1/` + `tests/acceptance_slice3c1.json` in the slice3b seal pattern. | Verifier script green; bundle bound to commit/tree. |

### Phase B — build out remaining jobs

| ID | Status | Contract | Proof |
|---|---|---|---|
| B1 | complete (2026-08-03) | Adapter host inside `houndd`: allowlisted exa/firecrawl/camofox execution moves in-daemon (credentials read only by the service); 7-step adapter commit ordering incl. post-acceptance PHI scan and bounded non-PHI quarantine manifest per VISION. | Fault-injecting fake adapter suite: 429/timeout/truncation/abstention/kill → one durable outcome + one event each; no credential in any record/log. |
| B2 | complete (2026-08-03) | `ingest.search` via Exa adapter (strict `{query, limit 1..50}` payload; leads are candidates, not evidence). Depends B1. | Live-optional + faux tests; search record + journal event with lineage none. |
| B3 | complete (2026-08-03; contract narrowed in the 3C2 repair: one durable outcome binds exactly one provider exchange — adapter retries removed (callers own retry policy) and `max_pages` multi-page crawl abstains (`requests=0` refusal). Consumers already reject `max_pages` (Pulse article adapter, gc-benefits contract test), so nothing depended on it.) | `ingest.url` via Firecrawl (direct \| search lineage, single-page, public-URL validator). Depends B1. | Faux extract with search-record parent binding; lineage graph resolves. |
| B4 | complete (2026-08-04, commit 335e1a3: D6 Option A — octet-stream only, same digest-allowlist PHI gate as ingest.file, schema houndd.media-capture-record.v1, kind media, dedupe media:<sha>; verify.py branch added at integration so forged/duplicate media events fail like their file equivalents; no B1 dependency — media is caller-supplied SOURCE bytes.) | `ingest.media` capture records. | 13 tests incl. crash matrix + scanner contract; full suite 1730. |
| B5 | pending | `transcribe` bound to authorized capture ID; daemon-produced model/version/segment-hash provenance. Provider: OpenAI Whisper API (D5, 2026-08-04). Depends B4. | Two-segment fixture: completed/partial/failed statuses stay explicit; no PHI in record. |
| B6 | complete (2026-08-04: `journal.verify` + `journal.rebuild-index` GET routes + client commands; verdict-only `{schema_version, valid}` reports; error-ordering fixed — integrity failures now 503 before the 400 shape clause, and an uncaught `JournalError` no longer kills the serving thread; interrupted-file `include_content` fixed via outcome-gated `_staged_blob`. Decisions recorded in VISION §Slice 3D.) | `journal get`, `journal verify`, `journal rebuild-index` as service routes + client commands, plus the authorized record-read route. | Route contract tests; rebuild equality vs canonical journal; radar consumes a lead end-to-end. |
| B7 | complete (2026-08-04, be063d9: GET /v1/telemetry in the B6 route pattern — VISION silent on the surface, choice flagged; metrics derived entirely from the authorized event view, no new state; consumer_lag = projection lag (HSP-08 forbids subscriber state, deviation accepted); broken snapshot = 503 like every aggregate read.) | Observability (HSP-11). | 10 tests incl. policy-partition non-leak; redacted snapshot artifacts retained. |
| B8 | complete (2026-08-04: always-on hardened unit under `ops/systemd/` + migration how-to. Socket activation rejected on evidence: houndd's `RENAME_NOREPLACE` self-bind is incompatible with fd-passing, and the trigger-only approximation drops the first cold-start connection — a false lane failure under the no-blind-retry consumer contract, for ~14M idle RSS saved. True activation = `sd_listen_fds()` support in houndd, only if ever needed.) | Unit under `ops/systemd/`; query round-trip. | `systemd-analyze verify` clean; live round-trip proven on an isolated copy. |
| B9 | pending | Commit-path projection refresh: `commit_runtime.py` never touches `Projection`, so the SQLite index only refreshes at startup recovery or an explicit `journal.rebuild-index` — index-backed reads lag every commit since the last restart (found during B6). Either refresh the projection inside the commit transaction or document + wire a scheduled rebuild into the ops story. | Red test: commit → index-backed query sees the new entry without a restart; `verify_store` green including projection on a live-commit store. |
| B11 | complete (2026-08-04: `Projection.append` with structural applicability proof + rebuild fallback; one shared row derivation; row-level equivalence proven across the commit matrix (byte-identity of the sqlite file is not sound — page layout differs; the proof is canonical serialization of ordered rows), guards mutation-tested. Residual: publication still serializes/verifies the whole index file (~0.2ms/entry) — accepted, changing it would break the never-write-through-the-visible-leaf safety model.) | Incremental projection append. | Row-level equivalence property test; per-commit derivations = 1 regardless of journal length. |
| B12 | complete (2026-08-04: verified byte-prefix memo, process-wide keyed by journal dir device+inode — reuse only on exact `startswith` byte match, no mtime/size/inode shortcuts, head.json never cached; tamper detection bit-identical. Startup at 859 entries: one full-chain pass, 288s → 37s; N commits = exactly 2N chain verifications. Known future work: memo held for process life (~7KiB/entry) — prune/segment story at 10k+ entries.) | Bound chain verification without weakening integrity. | Operation-count proofs; tamper tests red incl. inside-cached-prefix mutations with restored mtime. |
| B13 | pending | `ingest.search` options extension (found in the Pulse cutover): the wire payload is strictly `{query, limit}`, dropping the Exa options the Pulse discovery spec produces (category, published-date window, userLocation) — the editorial week stops being a provider-received bound. Add optional bounded `options`, additively (old records stay valid — the native_id lesson), validated closed-shape end to end and retained in committed records for provenance; then pass-through in the gc-web cutover branch. Lands before Pulse's first hound-only scheduled run. | Contract tests across commit/adapter/record/client; old-record compatibility proven against the production store shape. |
| B10 | complete (2026-08-04: HounddClient.journal_query with deep entry validation incl. entry_id re-derivation; typed cursor-rejected/filter-unavailable errors; reference consumer migrated off its hand-rolled exchange) | `hound_client` journal.query support: the shared wire client's response validator only knows `/v1/ready` and record reads, so any consumer wanting typed journal.query must hand-roll the exchange (the C2 reference consumer does). Extend `hound_client` with strict journal.query request/response validation and migrate `examples/consumer` onto it. | Client contract tests in the test_hound_client.py adversarial idiom; reference consumer drops its hand-rolled exchange. |

### Phase C — consumption surfaces

| ID | Status | Contract | Proof |
|---|---|---|---|
| C1 | pending | Workpad renders the intake-ledger view read-only (server side already live). Depends W1. | Workpad shows chronological redacted rows; no write/approve/dereference path exists. |
| C2 | pending | Reference consumer pattern: per-lane cursor state file + replay discipline + how-to doc (Diátaxis how-to). | A sample consumer replays a cursor across a service restart without loss or duplicates. |

### Phase D — owner decisions (Ali; each unblocks its lane)

| ID | Status | Decision |
|---|---|---|
| D1 | decided 2026-08-04 (Ali) | benefits-legacy: **dropped from scope.** The radar lane covers benefits discovery; no adapter contract will be specified. Lane removed from the inventory closure. |
| D2 | decided 2026-08-04 (Ali) | civic-policy-radar: target ops `ingest.search` + `ingest.url`, benefits-radar-shaped bounded query rotation over the existing civic sources. Lane unblocked. |
| D3 | decided 2026-08-04 (Ali) | gmail-newsletters-attachments: **deferred** — no `ingest.file` attachment adapter until something demonstrably needs newsletter attachments as evidence. Lane removed from the inventory closure; re-entry is a new owner decision. |
| D4 | decided 2026-08-04 (Ali) | helm-external-ingestion: **deferred** — decide with real usage data if/when Wave 5 revives it. Lane removed from the inventory closure; re-entry is a new owner decision. |
| D5 | decided 2026-08-04 (Ali) | signal-daily: eligibility gate = Pulse's verified terminal token (the dependency rack's existing edge). Transcription for B5 = OpenAI Whisper API. Lane unblocked. |
| D6 | decided 2026-08-04 (advisor, under Ali's standing idiomatic-default delegation; open to veto) | `ingest.media` PHI regime: **Option A — narrow.** `media_type` exactly `application/octet-stream`; same operator digest-allowlist gate as `ingest.file` (scanner operation set extended by one label, no behavioral change); schema `houndd.media-capture-record.v1`, `artifact.kind="media"`, dedupe `media:<sha256>`. Real `audio/*`/`video/*` MIME types = a future scanner-boundary slice, decided when M4's youtube lane needs it (VISION reserves this expansion explicitly). Also corrected: B4 does NOT depend on B1 — media capture is caller-supplied SOURCE bytes like `ingest.file`, no adapter host involved. |
| D7 | decided 2026-08-04 (advisor, under Ali's standing delegation; open to veto) | manual-web / manual-x: **convention, not shared-skill rewrite.** The firecrawl/x-twitter skills serve consumers far outside GiveCare (schwab, research, travel); routing all skill use through houndd would pollute the evidence journal with non-evidence browsing and add a daemon dependency to unrelated workflows. The lanes mean *manual acquisition of GiveCare evidence*, whose houndd path is the proven `hound-research ingest` console — documented as the convention (docs/how-to-consume.md + lane contracts); shared skills unchanged. Inventory rows reflect the console mechanism. |
| D8 | decided 2026-08-04 (advisor, under Ali's standing delegation; open to veto) | signal-daily: **reclassified consumer-only; no houndd ops.** The inventory's `journal.query` gate was unimplementable — Pulse terminal tokens live in the bb thread, not the journal, and committing lane-status records to houndd would violate its refusals (no scheduler/domain state; the journal is acquisition provenance). The existing local-artifact + citation-freshness gates stay; the inventory row is corrected rather than built against. |
| D9 | decided 2026-08-04 (advisor, under Ali's standing delegation; open to veto) | atelier-entity-discovery: **out of hound's scope; lane leaves the closure.** Its acquisition is ScrapeCreators + x-twitter — shared skills serving consumers far outside GiveCare, with platform engagement metrics no hound adapter carries; an Exa/Firecrawl repoint would be a capability downgrade, and a ScrapeCreators adapter would be new shared houndd infrastructure, not a lane cutover. D7's boundary extends here. Re-entry = an explicit decision to build that adapter. |

### Phase M — lane migration

**REPLANNED 2026-08-04 (Ali: "no legacy, full cutover").** The staged
shadow-parity/per-lane-approval ceremony is dropped. Each lane's driver is
rewritten to acquire ONLY through `houndd`, proven with one real end-to-end
run, and its legacy acquisition path deleted in the same change. Rollback
during transition is `git revert`, not a retained parallel path. Standing
constraints that survive the replan: tomorrow's scheduled runs (2026-08-04
morning) execute legacy one final time — no cutover lands inside that window;
youtube-transcription still needs B4/B5 first; credential boundary unchanged
(provider keys end up only in houndd's env). The stage ledger records each
cutover as freeze_contracts → migrated → retired with the real-run evidence;
shadow stage entries are not required (shadow-required set drops to empty).

| ID | Status | Contract | Proof |
|---|---|---|---|
| M1 | complete (2026-08-04: 824 provider-derived records imported, run `m1-backfill-2026-08-04` — evidence-only selection per Ali (not-evidence leads and unstatused records deliberately excluded; they remain in repo `.hound` dirs). Journal 35 → 859 entries; `verify_store` green including projection; 5/5 random byte-fidelity spot checks identical through the read path; PHI clear manifest extended 3 → 827 digests as the operator approval. Manifests: `migration/evidence/m1/`.) | Import/mirror existing repo-local records for Pulse/Benefits/wiki via `import.record` (IDs and bytes preserved). Depends W2. | HSP-14 portability checks against the real imported corpus; before/after manifests. |
| M2 | complete (2026-08-04: **both Wave-2 lanes live on houndd**. benefits-radar since abffd89; pulse merged (gc-web 6fb4ac9 + fixes 1475e6d/dbfb1f0) with both shadow timers deleted and the bb contract updated. Live proof: full evidence stage through the production daemon — 8 searches, 128 leads, 20 captures, 0 failures, 19 retained. Defects found+fixed during the live proof: bb held-answer object-vs-string (normalized at lane intake), hound_research 5s exchange timeouts vs synchronous provider commits (now 180s commit / 60s read), non-deterministic acquisition run IDs breaking idempotent replay (now pulse-<date>, v3 key namespace). Remaining niceness: B13 search options before long unattended operation. | Wave 2 cutover: pulse + benefits drivers acquire only via houndd, legacy deleted. | One real run per lane, credential-unset, correct bb terminal tokens. |
| M3 | complete (2026-08-04: all three lanes merged and live-proven on houndd. wiki-refresh: gc-wiki 3188728 — REFRESH_FAILED root-caused (undeclared gap-signal inputs) and fixed with a two-tier signal (live coverage holes, else deterministic weekly rotation); live proof: completed gc-wiki search, 8 real leads. intel-refresh: gc-intel c782f49 — runbook-level swap, no new conductor; live wire proof completed. civic-policy-radar: gc-web 20ef28f/2b94dbd — Civic CLI acquisition replaced by houndd, corpus.propose provider-key env_allowlist deleted, human-gated apply path untouched; 17/17 policy tests + verify-policy-hound-only green post-merge. Incident recorded: during test iteration, 6 un-faked legacy tests reached the production socket and committed 4 real gc-web entries (run policy-2026-07-21, 10:59Z) — bounded spend, root-caused, all corpus.propose tests now inject fakes. Full scheduled cycles: intel next daily run, wiki next Monday, policy per its schedule.) | Wave 3 cutover: three lanes acquire only via houndd, legacy deleted. | One real run per lane; correct bb terminal tokens on next scheduled cycles. |
| M4 | in progress (2026-08-04 discovery: read baselines PROVEN clean — workpad is a pure houndd wire client with zero acquisition capability, gc-gtm is Gmail-send-only; signal-daily resolved by D8 (consumer-only, nothing to cut); manual-web/manual-x resolved by D7 (console convention, no skill rewrite); radar-curation blocked on B5 (its transcript slice) + a fork-vs-shared-skill decision for its article/media acquisition once B5 lands.) | Wave 4: radar-curation after B5; manual lanes per D7; read baselines proven. | Per-lane evidence; scanner proofs for baselines. |
| M5 | resolved by decision (2026-08-04, D9): atelier-entity-discovery leaves the inventory closure — no cutover, no code. Wave 5 closed. |

### Phase E — enforcement and closure

| ID | Status | Contract | Proof |
|---|---|---|---|
| E1 | pending | Dynamic no-bypass matrix: every migrated consumer with credentials unset (HSP-18 full, HSP-01). Runs incrementally as lanes migrate. | Consumer matrix report; static scan with allowed exclusions only. |
| E2 | pending | Stage-order checker + signed stage ledger (HSP-15). | Checker rejects skipped/reordered stages and pre-gate deletion. |
| E3 | pending | Domain-ownership static checker + capability dump (HSP-19). | Ownership report: evidence mechanics only. |
| E4 | design complete (2026-08-04: docs/approval-seams.md — receipt/decision/outcome three-record distinction, hash-chained audit-only decisions.jsonl, append-only annotations, stage-ledger approval_ref binding for HSP-22, ledger stays read-only with link-outs). Remaining: migration/check_approvals.py checker + tampered fixtures. | Approval seam records. | Tampered-decision-log and changed-hash fixtures fail the gate. |
| E5 | pending | Consolidated fault matrix + backup-restore drill closing HSP-12 (transcript failure, outage abstention, exact-hash approval binding included). | Full matrix pytest log + restored-store verification. |
| E6 | pending | Full acceptance manifest: 22 ordered rows, one-to-one artifact traceability, CI runs the acceptance command (HSP-21). | Manifest checker + CI green. |
| E7 | pending | Deletion: retire each lane's legacy paths only after its recovery drill + one full scheduled cycle; adapters' direct console/CLI entry points removed at final cutover. | `legacy_absent` evidence per lane; provider indicators scan clean outside houndd. |

### Phase A — bb runtime acceptance (added 2026-08-03)

| ID | Status | Contract | Proof |
|---|---|---|---|
| A1 | pending | One full scheduled bb cycle per acceptance criterion 6: every GiveCare lane automation acquires only through `houndd`, terminal tokens reach the Chief-of-Staff thread, `loop-company` reads lane artifacts via the dependency rack. Includes the known `refresh-wiki` REFRESH_FAILED contract gap (missing owner-declared gap signal, target, bounded query list — bb:thr_z9ha57v939) fixed under M3. Depends M2–M5. | Cycle transcript + token audit; credential-unset run shows zero direct provider calls. |

### Verify

| ID | Status | Contract | Proof |
|---|---|---|---|
| V | pending | Run acceptance criteria 1–6. Blocked by all phases. | Full suite + acceptance command + inventory check green; criteria walked with evidence links. |

## Refusals (unchanged from VISION.md)

No scheduler, no domain logic, no central approval DB, no CRM/wiki/Helm/Pulse
curation ownership, no subscriber queue state, no PHI persistence, no provider
access outside the `houndd` allowlist after cutover.
