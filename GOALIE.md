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
| B4 | pending | `ingest.media` capture records (exact source hash/type/lineage). Depends B1. | Capture record + `houndd://record/<id>` URI verify. |
| B5 | pending | `transcribe` bound to authorized capture ID; daemon-produced model/version/segment-hash provenance. Provider: OpenAI Whisper API (D5, 2026-08-04). Depends B4. | Two-segment fixture: completed/partial/failed statuses stay explicit; no PHI in record. |
| B6 | complete (2026-08-04: `journal.verify` + `journal.rebuild-index` GET routes + client commands; verdict-only `{schema_version, valid}` reports; error-ordering fixed — integrity failures now 503 before the 400 shape clause, and an uncaught `JournalError` no longer kills the serving thread; interrupted-file `include_content` fixed via outcome-gated `_staged_blob`. Decisions recorded in VISION §Slice 3D.) | `journal get`, `journal verify`, `journal rebuild-index` as service routes + client commands, plus the authorized record-read route. | Route contract tests; rebuild equality vs canonical journal; radar consumes a lead end-to-end. |
| B7 | pending | Observability (HSP-11): provider errors, spend, freshness, capture completeness, dedupe rate, consumer lag, unprocessed demand, journal/index/recovery health; policy-filtered. | Telemetry contract test per fixture class; redacted snapshot retained. |
| B8 | complete (2026-08-04: always-on hardened unit under `ops/systemd/` + migration how-to. Socket activation rejected on evidence: houndd's `RENAME_NOREPLACE` self-bind is incompatible with fd-passing, and the trigger-only approximation drops the first cold-start connection — a false lane failure under the no-blind-retry consumer contract, for ~14M idle RSS saved. True activation = `sd_listen_fds()` support in houndd, only if ever needed.) | Unit under `ops/systemd/`; query round-trip. | `systemd-analyze verify` clean; live round-trip proven on an isolated copy. |
| B9 | pending | Commit-path projection refresh: `commit_runtime.py` never touches `Projection`, so the SQLite index only refreshes at startup recovery or an explicit `journal.rebuild-index` — index-backed reads lag every commit since the last restart (found during B6). Either refresh the projection inside the commit transaction or document + wire a scheduled rebuild into the ops story. | Red test: commit → index-backed query sees the new entry without a restart; `verify_store` green including projection on a live-commit store. |
| B10 | pending | `hound_client` journal.query support: the shared wire client's response validator only knows `/v1/ready` and record reads, so any consumer wanting typed journal.query must hand-roll the exchange (the C2 reference consumer does). Extend `hound_client` with strict journal.query request/response validation and migrate `examples/consumer` onto it. | Client contract tests in the test_hound_client.py adversarial idiom; reference consumer drops its hand-rolled exchange. |

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

### Phase M — lane migration (stage order: import_mirror → shadow → migrated → retired)

Each lane fills its nine evidence slots and gets an `approval_ref` from an
explicit Ali cutover decision (HSP-22). Per-lane checks: baseline scan, shadow
parity where required, static no-direct-provider, credential-unset run, socket
use, recovery drill, one full scheduled cycle, legacy paths absent.

| ID | Status | Contract | Proof |
|---|---|---|---|
| M1 | pending | Import/mirror existing repo-local records for Pulse/Benefits/wiki via `import.record` (IDs and bytes preserved). Depends W2. | HSP-14 portability checks against the real imported corpus; before/after manifests. |
| M2 | in progress (benefits-radar SHADOW live since 2026-08-03: hound-radar-shadow.timer, daily 06:30 UTC, 8-query rotation into the ledger; B6 landed 2026-08-04 — cutover now blocked only on parity evidence + Ali approval; benefits-legacy dropped per D1) | Wave 2: Pulse shadow parity (HSP-16 comparator) then cutover; benefits-radar (HSP-17 8-query parity) then cutover. Depends B2, B3, M1. | Parity reports, no-publish audit, credential-free cutover runs, Ali approvals recorded. |
| M3 | pending | Wave 3: wiki-refresh, intel-refresh, civic-policy-radar (D2 decided: search+url rotation). Depends M2. | Same per-lane evidence set; stage ledger rows. |
| M4 | pending | Wave 4: radar-curation, manual-web, manual-x, youtube-transcription (needs B4/B5), signal-daily (D5 decided: Pulse-token gate), workpad-intake-ledger + gc-gtm-crm read baselines. gmail dropped per D3. Depends M2. | Same per-lane evidence set; consumer-only lanes prove zero acquisition capability. |
| M5 | pending | Wave 5: atelier-entity-discovery. helm-external-ingestion deferred per D4 — re-enters only by new owner decision. Depends M2. | Same per-lane evidence set. |

### Phase E — enforcement and closure

| ID | Status | Contract | Proof |
|---|---|---|---|
| E1 | pending | Dynamic no-bypass matrix: every migrated consumer with credentials unset (HSP-18 full, HSP-01). Runs incrementally as lanes migrate. | Consumer matrix report; static scan with allowed exclusions only. |
| E2 | pending | Stage-order checker + signed stage ledger (HSP-15). | Checker rejects skipped/reordered stages and pre-gate deletion. |
| E3 | pending | Domain-ownership static checker + capability dump (HSP-19). | Ownership report: evidence mechanics only. |
| E4 | pending | Approval seam records: `plus`/`amplify` annotation immutability, `decisions.jsonl` audit-only, gate receipt vs outcome distinction (HSP-10) and per-lane cutover gate (HSP-22). | Tampered-decision-log and changed-hash fixtures fail the gate. |
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
