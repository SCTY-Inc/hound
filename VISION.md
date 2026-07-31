# Hound canonical vision

This is the only canonical narrative contract for the Hound proof kernel and
the GiveCare Discovery Spine. It is normative, buildable, and machine-
verifiable. Supporting documents may explain or demonstrate this contract, but
they cannot redefine it. When a supporting document conflicts with this file,
this file wins.

During migration, this document explicitly supersedes the conflicting
architecture language in the unedited supporting documents: README wording
that permits optional or direct adapters, `docs/protocol.md` wording that
executes adapters directly, and `docs/security-model.md` wording that refuses
a persistent adapter service. The security-model refusal is about a persistent
in-process adapter service inside the proof kernel. It does not refuse the new
out-of-process local `houndd` Discovery Spine. Those documents are not edited
by this task.

## Purpose, outcomes, and impact

Hound makes consequential repository work and discovery evidence verifiable
without delegating proof to a transcript. A request is bounded by a reviewed
capability, exact inputs, immutable records, and an independently checkable
result.

The target outcomes are:

- Maintainers can delegate repository work while retaining a guarded proof
  boundary.
- Reviewers can inspect exact inputs, expected effects, access, provenance, and
  approval before a consequential write.
- GiveCare discovery accumulates durable evidence without turning the proof
  kernel into a domain registry, scheduler, or lineage authority.
- Domain repositories retain ownership of meaning, cadence, curation,
  transformation, and truth surfaces.
- Existing Hound records remain verifiable, including their IDs, hashes, and
  exact bytes, through migration and future rebuilds.

## Product layers and ownership

`hound_cli` is the small guarded-write proof kernel. It owns manifest checks,
read receipts, deterministic write plans, approval binding, guarded execution,
exact effect checks, run records, and verification for an owner Git tree. It
does not acquire external search, URLs, files, media, or transcripts, and it
does not own Discovery Spine lineage.

`hound-research` is a thin local client. It validates request shape, sends
requests over the local service boundary, displays results, stores consumer
cursor state, and verifies/imports records as specified by the service. It has
no provider credentials, provider endpoints, network acquisition code, direct
provider client, or compatible-local-adapter bypass. Consumers fail closed;
they never fall back to a direct provider.

`houndd` is the out-of-process local Discovery Spine service. It owns the
external-ingestion adapters, provider credentials, network acquisition, file
and media intake, transcription calls, immutable records, append-only journal,
access enforcement, cursor issuance/verification, and rebuildable projections.
It is the only external-ingestion boundary after cutover.

Domain repositories own intent, query sets, cadence, curation, classification
meaning, proposals, native application, and downstream truth. Workpad is a
human-readable proposal/review surface. The native owner gate is the only
authority that applies a consequential change. `gc-gtm` and CRM remain
consumers; Hound does not own CRM writes.

Hound owns no domain logic, scheduler, central approval database, central
subscriber queue, CRM, wiki, Helm, Pulse curation, or Benefits registry. The
Discovery Spine is local, auditable, rebuildable, and out of process; it does
not change the proof kernel's refusal to become a global lineage service.

## One external-ingestion boundary

There is exactly one external-ingestion boundary. After cutover, all in-scope
external search, URL extraction, origin capture, file intake, media intake, and
transcription are requests to `houndd`-owned adapters. Every attempt, success,
failure, refusal, partial result, and recovered crash outcome is journaled by
`houndd` before the caller receives a completed result.

`hound_cli` remains a separate repository-execution proof kernel. A driver
invocation against an owner Git tree is not an external-ingestion boundary and
must not be used to acquire a provider result. `hound-research` is never an
acquisition boundary: it cannot select, load, or invoke a provider.

The explicit adapter allowlist is inside `houndd` only. Provider credentials,
network sockets, provider endpoints, browser/media transport, and model calls
are inaccessible to every migrated consumer and to `hound-research`. There is
no compatible local adapter, direct HTTP, direct SDK, prompt direct-skill, or
legacy adapter fallback after no-bypass cutover.

## Roles, cadence, inputs, outputs, and jobs

The roles are deliberately separate:

- The lane owner declares search intent, query windows, caps, budgets,
  classifications, cadence, curation, and downstream meaning.
- `houndd` performs the authorized acquisition, creates immutable records,
  appends journal events, enforces access, and exposes replayable reads.
- `hound-research` submits requests and consumes service responses without
  credentials or provider knowledge.
- Workpad presents a human-readable proposal and review context.
- Ali makes the exact approve/decline decision for a consequential action.
- The native owner gate validates that exact decision and exact immutable
  proposal/records, then alone applies the action.
- Consumers such as `gc-gtm`/CRM interpret approved records without becoming
  acquisition owners.

Hound owns no cadence and has no scheduler. A job is one caller-submitted
  request, one authorized service operation, and one observable result. Caller
  jobs and external schedules may invoke the service; local systemd socket or
  service activation is allowed, but systemd is not a Hound scheduler.

Inputs are versioned request objects, an authenticated local principal, lane
  policy, optional owner-selected source references, and for file/media work a
  caller-provided path or bytes. Outputs are immutable record IDs, journal
  entry IDs, explicit outcomes, evidence status, lineage, usage, opaque
  cursors, and separate receipts/outcomes. A lead is a candidate reference,
  not evidence, until an authorized capture or extraction record exists.

Jobs may produce search, extract, capture, transcription, import, failure,
refusal, degraded, partial, or recovery records. A failure remains explicit and
is not silently converted into a successful empty result.

## Exact CLI, API, and service contract

The target `hound-research` surface is exactly these operation families:

```text
hound-research ingest search
hound-research ingest url
hound-research ingest file
hound-research ingest media
hound-research transcribe --capture-id <capture-id>
hound-research journal query
hound-research journal get
hound-research journal verify
hound-research journal rebuild-index
hound-research import-record
```

Old direct `search`, `extract`, `capture`, `interact`, `source.*`, and
`--adapter` consumer paths are not target surface and cannot remain as
acquisition bypasses. The proof-kernel CLI remains its existing guarded-write
surface (`driver check`, `invoke`, `plan`, `approve`, `execute`, and `verify`)
with its existing semantics.

The versioned API is a logical JSON method/path contract carried only over a
Unix-domain socket:

```text
POST /v1/ingest/search
POST /v1/ingest/extract
POST /v1/ingest/capture
POST /v1/ingest/transcribe
POST /v1/ingest/import
GET  /v1/journal
GET  /v1/events/{id}
GET  /v1/records/{id}
GET  /v1/health
GET  /v1/ready
```

TCP, HTTP listeners, remote sockets, and provider-facing endpoints are not
service transports. Unix-domain socket service activation by local systemd is
allowed. `/v1/health` and `/v1/ready` report service health/readiness only;
they are not schedulers and do not disclose protected record metadata.

The portable defaults are `$XDG_RUNTIME_DIR/hound/houndd.sock` for the socket
and `${XDG_STATE_HOME:-$HOME/.local/state}/hound/discovery` for state. The
service fails closed when `XDG_RUNTIME_DIR` is absent; only an explicit CLI or
test override may supply a socket location. CLI and test overrides may change
locations, but never a record, entry, object, blob, or content identity. Socket
and state directories and files must be owner-only and fail closed on missing,
unsafe, or unexpectedly owned permissions. No absolute filesystem path
participates in canonical identity.

Every API call carries exactly one JSON request envelope:

```json
{
  "schema_version": "...",
  "request_id": "...",
  "idempotency_key": "...",
  "producer": { "owner_id": "...", "capability": "...", "run_id": "..." },
  "requested_access": "public|workspace|restricted",
  "policy_id": "...",
  "operation": { "name": "...", "payload": {} }
}
```

The authenticated principal comes only from the transport and is never a
caller-overridable request field. The service returns exactly one JSON response
envelope, including on a durable failure record:

```json
{
  "schema_version": "...",
  "request_id": "...",
  "ok": true,
  "outcome": "...",
  "record_ids": ["..."],
  "entry_ids": ["..."],
  "cursor": "...",
  "usage": { "requests": 0, "bytes": 0, "cost": 0 },
  "error": { "code": "...", "retryable": false, "message": "..." }
}
```

`cursor` and `error` are optional; `error` is policy-safe and contains no
protected detail. `record_ids` and `entry_ids` are empty when the caller is
not entitled to them. The CLI uses stable exits: `0` for completed and valid
read/verify/import/rebuild; `2` for an invalid CLI or request contract; `3`
for a non-disclosing unauthorized/not-found result; `4` for a durable
provider/operation failed, partial, degraded, or refused outcome; and `5` for
service-unavailable, integrity, or recovery failure. JSON still prints when a
durable failure record exists.

Transport authentication is Unix peer credentials (`SO_PEERCRED` or the
platform equivalent) only. A local caller-scope allowlist maps that OS
principal to permitted `owner_id`, capability, and access policy. The request
cannot override the authenticated principal; authorization precedes every
lookup, count, pagination calculation, and snippet evaluation.

## Immutable records and journal

Canonical evidence consists of immutable content-addressed record bytes plus an
append-only journal. SQLite and any other index are disposable projections;
they can be deleted and rebuilt from journal and record storage. A projection
is never canonical truth.

The immutable journal envelope is exactly the following. Fields inside the
listed objects are also exact; unknown usage values are omitted rather than
invented:

```json
{
  "schema_version": "...",
  "entry_id": "...",
  "sequence": 0,
  "appended_at": "...",
  "producer": {
    "owner_id": "...",
    "capability": "...",
    "run_id": "..."
  },
  "artifact": {
    "kind": "...",
    "schema": "...",
    "record_id": "...",
    "hash": "...",
    "authorized_uri": "..."
  },
  "lineage": {
    "relation": "...",
    "record_id": "...",
    "lead_id": "..."
  },
  "source": {
    "provider": "...",
    "native_id": "...",
    "canonical_url": "..."
  },
  "classification": {
    "outcome": "...",
    "evidence_status": "..."
  },
  "access": "public|workspace|restricted",
  "policy_id": "...",
  "dedupe": {
    "object_key": "...",
    "content_sha256": "..."
  },
  "usage": {
    "requests": 0,
    "bytes": 0,
    "cost": 0
  }
}
```

The canonical envelope deliberately omits `summary`, `priority`, `status`,
`next_action`, `approval`, CRM claims, wiki claims, and domain tags. Those may
exist in owner proposals or disposable consumer projections but never become
journal truth. An authorized URI is a policy-checked reference, not a promise
that a caller may dereference it.

Search, extract, capture, transcription, import, refusal, failure, and recovery
records use this envelope. Lineage is explicit and non-destructive: search
leads can lead to captures, captures can lead to extracts or transcriptions,
and every hop remains observable to an authorized principal.

## Atomic and idempotent commit semantics

Every provider attempt, including authentication failure, rate limit, timeout,
truncated bytes, model failure, refusal, partial output, and process
interruption, receives a durable immutable attempt record and journal event.
The service durably records an attempt-open marker before invoking a provider;
the provider outcome is then committed as the same attempt's immutable outcome
record. If the process dies before an outcome is received, recovery commits an
explicit interrupted outcome rather than erasing the attempt.

Each request has an idempotency key scoped to the authenticated principal,
capability, and canonical request hash. The key is commit coordination and
recovery metadata; it is not an additional canonical journal-envelope field.
The same key with the same canonical request returns the same identity and
result and does not append a second outcome; reuse of that key with a different
canonical request fails as an invalid request. Different occurrences, even with
equal content, always receive distinct observations/events.

The commit protocol is:

1. Authenticate and authorize before any provider call; canonicalize the
   request and reserve the idempotency key.
2. Durably write the attempt-open record, invoke exactly one allowed adapter,
   and durably stage returned bytes or the exact failure/partial diagnostic.
3. Atomically publish the immutable content record and its journal event with
   both durable before the response is acknowledged. No journal event may
   point to a missing record, and no completed record may claim a committed
   event that is absent.
4. On restart, reconcile staged data and the idempotency key. A complete
   staged result commits once; an incomplete provider call commits an
   interrupted/failure outcome once; a committed pair is never duplicated.
5. Rebuild projections only from committed journal events. A crash during
   projection update cannot alter record or event identity.

Crash-point tests cover before provider call, after provider return/before
   publish, after record publish/before journal fsync, after journal fsync/before
   response, and during projection rebuild. Recovery must preserve IDs, bytes,
   lineage, attempt count, and event order.

## Dedupe, identity, chronology, and cursors

Every occurrence remains a distinct observation/event. Exact blobs may share
physical storage. `object_key` groups revisions of the same logical object;
`content_sha256` identifies exact bytes. URL similarity or equality is never
destructive: URL dedupe can suppress redundant work in a projection, but it
cannot delete an occurrence, revision, lineage edge, failure, or journal event.

`journal query` and `GET /v1/journal` accept a single filter object in the
operation payload. Its only filters are: chronological `time_range`
(`appended_at` inclusive lower and exclusive upper bound); `producer`
(`owner_id`, `capability`, and/or `run_id`); `lane`; `topic`; source
`provider` and/or `canonical_url`; `entity`; `entry_id`; `record_id`;
`object_key`; `content_sha256`; classification `outcome` and/or
`evidence_status`; and `access` tier. Multiple supplied filters are ANDed;
each multi-value filter is an OR within that field. Results are authorized,
stable, chronological ascending by `(appended_at, sequence, entry_id)`, and
bounded by a high-watermark selected before evaluation. The opaque cursor uses
the existing cursor contract below, resumes strictly after its last result,
and cannot advance beyond that high-watermark.

`lane`, `topic`, and `entity` are not canonical envelope domain tags. Lane is a
deterministic access-controlled projection from producer plus policy with
provenance. Topic and entity are access-controlled owner annotation artifacts
or derived projection fields with provenance. Hound retains no saved query,
queue, acknowledgement, or subscriber state; callers retain their own
query/cursor state.

Hound issues and verifies opaque cursors bound to all of:

- service generation;
- filter hash;
- authenticated principal;
- last sequence; and
- high-watermark.

Consumers store their own cursor and ack state. Hound stores no subscriber
queue, acknowledgement, delivery state, or per-consumer progress truth.
Authorization occurs before search, count, metadata, or snippet evaluation.
Streaming uses the same cursor contract and cannot bypass access checks.
Cursor replay is deterministic: a consumer may replay safely, sees no lost
authorized events, and uses its own `entry_id`/idempotency handling to avoid
downstream duplicate effects.

## Access, retention, erasure, and privacy

The only visibility tiers are `public`, `workspace`, and `restricted`.
Uncertain classification defaults to `restricted`. A producer can set only a
visibility permitted by its policy and can never promote beyond its permitted
maximum. Promotion to `public` is a new owner-gated artifact with new identity,
lineage, and policy; it is not an in-place mutation of restricted evidence.

Authorization uses the local principal and policy before any record lookup,
search execution, count, pagination calculation, snippet generation, or
streaming delivery. An unauthorized principal learns neither existence nor
metadata: no record ID, provider, native ID, URL, timestamp, hash, size,
classification, count, total, cursor, pagination hint, snippet, or error that
distinguishes protected data is returned. Unauthorized and absent records use
the same non-disclosing result shape. Indexes must be access-scoped, and an
unauthorized count query must never run before the policy decision.

Restricted records have policy-defined retention and erasure. Erasure removes
permitted blobs and projections and appends an erasure tombstone that preserves
the record identity, lineage relation, policy, and audit fact without exposing
the erased content. The immutable journal is not rewritten. Hound stores no
caregiver runtime data and no PHI; suspected PHI is rejected or quarantined
before persistence, with no PHI in error, index, snippet, or metrics output.

## Transcription provenance

Every transcription record names the origin media capture, model/provider and
exact model version, language, segment/timing hashes, text hash, status, and
exact source lineage. Status is explicit (`completed`, `partial`, `failed`, or
`refused`); partial and failed transcripts are durable outcomes, never silently
promoted to complete evidence. A transcription cannot exist without an
authorized capture lineage, and segment hashes permit independent verification
of the relationship between source media, timings, and text.

## Workpad and approval seam

Workpad is the human-readable proposal and review surface. `plus`/`amplify` is
only an immutable, non-authoritative preference or ranking annotation. It is
never fan-out, approval, apply, publish, contact, execute, or queue authority.

Ali makes one exact approve or decline decision over immutable record IDs,
proposal hash, input hashes, and intended operation. `decisions.jsonl` is an
append-only audit log only; it is never the gate. The native owner gate
validates the exact immutable records, exact proposal, and exact Ali decision,
then alone applies the action. A receipt that the gate accepted a request and
the resulting outcome are distinct immutable records. Hound may verify and
link them but may not apply, publish, contact, execute, or enqueue the action.

## Observability, recovery, and portability

Operational telemetry must expose provider errors, spend, freshness, capture
completeness, dedupe rate, consumer lag, unprocessed demand, and journal,
index, and recovery health. Metrics are policy-filtered and contain no
protected URLs, snippets, PHI, credentials, or hidden record metadata.

Recovery is deterministic and local: restore backups, verify record hashes,
replay the journal, rebuild SQLite, and compare IDs, bytes, lineage, and
sequence. SQLite is disposable. A restored store must preserve legacy and new
record IDs and lineage without an absolute-path dependency. Backup restore,
index rebuild, and service generation changes invalidate/reissue cursors
according to the cursor binding rules.

## Audited migration inventory and ownership

The complete in-scope migration inventory is below. The named lane owner keeps
intent, cadence, curation, classification, and downstream meaning; `houndd`
owns only the adapter, acquisition, journal, access, and evidence mechanics.
The cadence-authority/category is an inventory classification, not a mutable
timer source: exact timer values remain canonical in each lane automation
contract, and Hound has no scheduler.

| Lane | Lane owner / truth owner | Cadence authority / category | Hound boundary and consumer |
| --- | --- | --- | --- |
| Pulse | `gc-web` / `givecare/pulse-daily` | daily | `houndd` acquisition and journal; Pulse remains the consumer/curator |
| Benefits radar | `gc-benefits` / `givecare/discovery-benefits` | daily | `houndd` acquisition and journal; Benefits owns candidate meaning |
| Benefits legacy | `gc-benefits` / `givecare/discovery-benefits` | on-demand/manual | `houndd` adapters replace each external read; Benefits owns finalization |
| Wiki refresh | `gc-wiki` / `givecare/refresh-wiki` | weekly | `houndd` external reads; Wiki owns refresh truth |
| Intel refresh | `gc-intel` / `givecare/intel-refresh` | daily | `houndd` external reads; Intel owns interpretation |
| Civic policy radar | `scty-civic` / `givecare/refresh-policy` | weekly | `houndd` external reads; Civic owns policy meaning |
| Weekly radar curation | `GiveCare root` / `givecare/radar-curation` | weekly | `houndd` supplies evidence; curation remains an owner job |
| Gmail/newsletters/attachments | mailbox/router owner | event-driven | `houndd` intake and journal; authorized consumers interpret |
| Manual web | research operator | on-demand | `houndd` is the sole search/extract/capture boundary |
| X | research operator | on-demand | `houndd` adapter and journal; no direct social client in consumers |
| YouTube/transcription | research operator | on-demand | `houndd` media intake/transcription and provenance |
| Atelier entity discovery | Atelier | event-driven | `houndd` external reads; Atelier owns entities |
| Helm external ingestion | Helm | event-driven/mixed | `houndd` external reads; Helm remains the truth surface |
| Signal daily | `GiveCare root` / `givecare/signal-daily` | daily | `houndd` acquisition/journal; Signal keeps cadence and meaning |

`gc-gtm`/CRM remains a consumer of authorized records. It is not an
acquisition owner and Hound performs no CRM write.

Explicitly out of scope are: `gc-sms` local/runtime retrieval; local wiki/site search;
Benefits registry query/normalization/dedupe; bench/evals; health/deploy smoke;
social publishing; CRM writes; and internal BB, Git, Discord, or calendar events.

## Exact staged order, migration, and deletion

The migration order is fixed:

1. Freeze contracts.
2. Import/mirror existing repo-local records without rewriting IDs or bytes.
3. Shadow Pulse and Benefits.
4. Cut over Pulse, then Benefits.
5. Cut over wiki/intel/Civic.
6. Cut over radar/Gmail/manual web/X/YouTube.
7. Cut over Atelier and Helm external reads.
8. Enable no-bypass enforcement.
9. Delete old paths only after a successful recovery drill and at least one
   full scheduled cycle per lane.

Signal daily follows the same owner-controlled scheduled-cycle gate in the
radar wave. “Cut over” means provider credentials are absent from the
consumer, every operation goes through `houndd`, and every result is journaled.
Deletion never means rewriting legacy records; it removes only superseded
copies after recovery and cycle evidence is retained.

Pulse parity requires the same query set, windows, and caps; explained eligible
lead differences; the same capture lineage and evidence bundle; freshness,
lane, and quality gates; no-edition and recovery behavior; downstream input
hash or adjudicated semantic equivalence; no publish during shadow; and a
cutover that works with provider credentials absent from Pulse.

Benefits parity requires the same 8 rotating queries, as-of value, and
budgets; known URL/title suppression and cap; candidate IDs, targets, and
classifications; the finalizer and human proposal/apply boundary; an explicit
degraded result when there are zero leads; and a cutover with provider
credentials absent from Benefits.

## No-bypass and acceptance discipline

No-bypass acceptance has two independent checks. A static checker scans every
migrated consumer outside the explicit `houndd` adapter allowlist for provider
credentials, provider endpoints, direct clients, prompt direct skills, and
artifacts lacking Hound IDs. Its exclusions are tests, history, local
retrieval, health, deploy, and publish paths only. Dynamic tests run every
migrated consumer with provider credentials unset and assert that it succeeds
only through the Unix socket or fails closed; no consumer may acquire directly.

Every implementation artifact, fixture, test, command, and retained evidence
bundle must trace to exactly one HSP ID in the acceptance rows below. A test
result is not evidence unless it names its fixture/test/command, expected
assertion, and retained artifact. The rows are the completion contract; all
must pass.

## Acceptance requirements

| ID | Requirement | Authoritative executable evidence/test, expected assertion, and retained artifact |
| --- | --- | --- |
| HSP-01 | There is one external-ingestion boundary after cutover: all external search, URL extraction, capture, file/media intake, and transcription goes through `houndd`-owned adapters and is journaled; `hound_cli` is repository execution only and is not an acquisition boundary. | Fixture: migrated consumer with fake provider credential and direct-client imports. Test/command: static boundary checker plus Unix-socket integration test with the credential unset. Assert: only the allowlisted `houndd` adapter reaches the provider; direct and `hound_cli` acquisition paths fail closed. Retain: boundary scan JSON and journal event bundle. |
| HSP-02 | The proof kernel preserves existing `hound_cli` semantics, legacy record IDs, hashes, exact bytes, guarded-write checks, and verification; it gains no domain logic, scheduler, lineage service, central queue, or approval DB. | Fixture: `tests/golden/config_migration` and a copied legacy run directory. Test/command: `PYTHONDONTWRITEBYTECODE=1 uv run pytest -p no:cacheprovider tests/test_orchestrator.py tests/test_runtime.py`; Assert: exact effects, run verification, and legacy hashes/bytes are unchanged. Retain: pytest output, verified run record, and hash manifest. |
| HSP-03 | `hound-research` is a thin client with the exact target CLI surface and versioned methods/paths; transport is Unix-domain socket only, systemd activation is allowed, and there is no scheduler. Every request has the exact JSON envelope (`schema_version`, `request_id`, `idempotency_key`, producer `owner_id`/capability/`run_id`, `requested_access`, `policy_id`, and operation payload); every response has `schema_version`, `request_id`, `ok`, `outcome`, `record_ids`, `entry_ids`, optional cursor, usage, and optional policy-safe error. The peer principal is transport-only; same idempotency key plus canonical request returns the same identity/result, while different canonical reuse fails. The portable XDG defaults are `$XDG_RUNTIME_DIR/hound/houndd.sock` and `${XDG_STATE_HOME:-$HOME/.local/state}/hound/discovery`, with identity-preserving CLI/test overrides and fail-closed permissions. If `XDG_RUNTIME_DIR` is absent, the service fails closed except for an explicit CLI/test override. CLI exits are exactly 0 valid completed/read/verify/import/rebuild, 2 invalid contract, 3 non-disclosing unauthorized/not-found, 4 durable failed/partial/degraded/refused, and 5 unavailable/integrity/recovery; durable failure records still print JSON. | Fixture: CLI/API golden request/response/error set, idempotency collision set, unsafe-permission set, and socket-only service unit. Test/command: CLI golden and service-contract tests. Assert: every listed command/path and envelope works only through the socket; TCP/provider endpoints and old direct commands do not; required/optional fields and exits match exactly; retry identity is stable; different-canonical key reuse fails; defaults/overrides preserve identity; and no scheduler starts. Retain: request/response/error transcript, socket-unit file, permission report, and service capability report. |
| HSP-04 | The immutable journal envelope contains exactly the required fields and omits summary, priority, status, next_action, approval, CRM/wiki claims, and domain tags from canonical truth. | Fixture: one record for each artifact kind plus an unknown-usage case. Test/command: envelope schema/negative-schema test and `journal verify`. Assert: required field set, value domains, hashes, and omission set match this contract; unknown usage is omitted. Retain: canonical envelope JSONL and verifier report. |
| HSP-05 | Provider attempts, including failures, are durable; content record plus journal event commit atomically; idempotency keys make retries one commit; all specified crash points recover without duplicate or orphan truth. | Fixture: fault-injecting adapter for success, 429, timeout, truncation, and process kill at each commit point. Test/command: atomic-commit recovery test with repeated idempotency key. Assert: one attempt/event identity, durable failure or interrupted outcome, no event without record, no acknowledged record without event, and retry returns the original identity. Retain: fault schedule, recovery journal, record hashes, and idempotency result. |
| HSP-06 | Search, extract, capture, import, and transcription lineage is exact and durable; transcription records name origin media, model/provider/version, language, segment/timing hashes, text hash, status, and source lineage; partial/failure remains explicit. | Fixture: media capture with two timed segments, partial model result, failed model result, and imported record. Test/command: provenance verifier and transcription lineage test. Assert: every edge and hash resolves, partial/failed statuses remain non-complete, and no transcription lacks its capture. Retain: lineage graph JSON, segment manifest, and verifier output. |
| HSP-07 | Every occurrence remains a distinct event; equal blobs may share storage; `object_key` groups revisions; `content_sha256` identifies bytes; URL dedupe is never destructive. | Fixture: concurrent same-content captures from two providers and two URL revisions. Test/command: concurrent dedupe test plus `journal query`. Assert: distinct entry/record identities and lineage with shared blob only where exact bytes match; no URL occurrence is deleted. Retain: event list, blob index, and dedupe report. |
| HSP-08 | `journal query`/`GET /v1/journal` has exactly these ANDed filter families (OR within a multi-value family): chronological inclusive/exclusive `appended_at` time range, producer/lane, topic, source provider/canonical URL, entity, entry ID, record ID, object key, content hash, outcome/evidence status, and access tier. Topic/entity are access-controlled owner annotations or derived projection fields with provenance, never canonical envelope domain tags. Results are authorized, stable chronological `(appended_at, sequence, entry_id)` reads bounded by a selected high-watermark; opaque cursors bind service generation, filter hash, principal, last sequence, and high-watermark. Consumers own cursor/ack/progress; Hound retains no saved query, queue, delivery, acknowledgement, or subscriber state; streaming uses the same contract. | Fixture: two principals, complete filter matrix, annotation/projection provenance, two filters, service restart, replayed stream, and independently stored consumer cursors. Test/command: query, cursor-binding, and replay tests. Assert: every filter and its ordering/high-watermark boundary is exact; unauthorized annotations and sources cannot affect results; mismatched cursor bindings fail; authorized replay has no loss; consumer-side `entry_id` handling prevents downstream duplicates; and no server query/subscriber state exists. Retain: query fixtures, provenance bundle, replay transcript, and storage inventory. |
| HSP-09 | Transport authentication is Unix peer credentials (`SO_PEERCRED` or platform equivalent) and a local caller-scope allowlist maps the authenticated OS principal to permitted `owner_id`, capability, and access policy; request fields cannot override that principal. Authorization precedes lookup, search, count, pagination, metadata, and snippet evaluation. Access is exactly public/workspace/restricted; uncertain is restricted; producers cannot exceed permitted maximum; public promotion is a new owner-gated artifact; restricted erasure uses tombstones; unauthorized principals learn no existence, metadata, counts, or snippets; no caregiver runtime data or PHI is stored. | Fixture: peer principals with distinct caller scopes, forged principal/owner fields, one record per tier, uncertain record, promotion, erased restricted record, unauthorized principal, and PHI payload. Test/command: Unix-peer ACL negative test before lookup/search/count/snippet and `journal verify`. Assert: scope mapping and principal non-override are enforced; identical non-disclosing unauthorized result shape has zero protected metadata/count/snippet leakage; policy-clamped visibility, tombstone lineage, and PHI rejection hold. Retain: redacted peer-ACL transcript, policy decision log, and tombstone record. |
| HSP-10 | Workpad remains the human-readable proposal/review surface; `plus`/`amplify` is only an immutable preference/ranking annotation; Ali makes the exact decision; `decisions.jsonl` is audit only; the native owner gate alone applies; receipt and outcome remain distinct. | Fixture: immutable records/proposal, plus annotation, exact Ali approve and decline decisions, tampered decision-log copy. Test/command: approval-binding integration test. Assert: annotation cannot fan out/approve/apply/publish/contact/execute/queue, decisions log cannot gate, exact hashes are validated by the native gate, and receipt differs from outcome. Retain: proposal, decision, gate receipt, outcome, and audit JSONL. |
| HSP-11 | Observability exposes provider errors, spend, freshness, capture completeness, dedupe rate, consumer lag, unprocessed demand, and journal/index/recovery health without protected data. | Fixture: successful, failed, partial, stale, duplicate, lagging, and unprocessed jobs. Test/command: telemetry contract test. Assert: each signal is present, numerically consistent with the fixture, access-filtered, and free of credentials/PHI/snippets. Retain: redacted metrics snapshot and consistency report. |
| HSP-12 | Failure/recovery acceptance covers concurrent same-content captures, crash after fetch/before commit, 429s, timeouts, truncated bytes, transcript failures, outage abstention, cursor replay, ACL non-leakage, backup restore, and exact-hash approval binding. | Fixture: the complete fault matrix and portable backup. Test/command: `PYTHONDONTWRITEBYTECODE=1 uv run pytest -p no:cacheprovider` plus recovery/fault integration suite. Assert: no loss, no unauthorized disclosure, no downstream duplicate effect, preserved IDs/lineage after restore, and approval rejection on any hash drift. Retain: full pytest log, fault matrix, restored-store verification, and approval failure report. |
| HSP-13 | The complete audited migration inventory is present with each lane’s explicit owner and cadence-authority/category: Pulse: `gc-web` / `givecare/pulse-daily`, daily. Benefits radar: `gc-benefits` / `givecare/discovery-benefits`, daily. Benefits legacy: `gc-benefits` / `givecare/discovery-benefits`, on-demand/manual. Wiki refresh: `gc-wiki` / `givecare/refresh-wiki`, weekly. Intel refresh: `gc-intel` / `givecare/intel-refresh`, daily. Civic policy radar: `scty-civic` / `givecare/refresh-policy`, weekly. Weekly radar curation: `GiveCare root` / `givecare/radar-curation`, weekly. Gmail/newsletters/attachments: mailbox/router owner, event-driven. Manual web, X, YouTube/transcription: research operator, on-demand. Atelier entity discovery: Atelier, event-driven. Helm external ingestion: Helm, event-driven/mixed. Signal daily: `GiveCare root` / `givecare/signal-daily`, daily. Exact timer values remain canonical only in each lane automation contract, not this inventory or Hound. `gc-gtm`/CRM remains a consumer only. | Fixture: checked-in inventory manifest mirroring the table and lane automation contracts. Test/command: inventory completeness checker. Assert: every required lane has one explicit owner, one cadence category, one consumer/boundary, and one migration stage; timer truth is absent from Hound; `gc-gtm`/CRM is consumer-only; and the explicit out-of-scope list is absent from the inventory. Retain: inventory report, owner attestations, and timer-authority references. |
| HSP-14 | Existing repo-local records are imported/mirrored without rewriting IDs or bytes; lineage and hashes survive; SQLite is disposable and rebuilds from journal/records; portability has no absolute-path dependency. | Fixture: legacy records with nontrivial bytes, IDs, lineage, and a copied store on a second path. Test/command: import, delete-index, rebuild-index, and portable restore test. Assert: byte-for-byte/hash-for-hash identity, unchanged IDs/lineage, rebuilt projection equality, and successful verification at the second path. Retain: before/after manifests, restore log, and projection diff. |
| HSP-15 | Migration follows the exact staged order: freeze contracts; import/mirror; shadow Pulse and Benefits; cut over Pulse then Benefits; wiki/intel/Civic; radar/Gmail/manual web/X/YouTube; Atelier and Helm external reads; enable no-bypass; delete only after recovery drill and one full scheduled cycle per lane. | Fixture: stage ledger with one lane per gate and scheduled-cycle evidence. Test/command: migration-order checker. Assert: no stage can be skipped/reordered, no deletion occurs before both gates, and Signal daily uses the scheduled-cycle gate. Retain: signed stage ledger, recovery-drill report, and per-lane cycle receipts. |
| HSP-16 | Pulse shadow parity requires the same query set/windows/caps, explained eligible lead differences, same capture lineage/evidence bundle, freshness/lane/quality gates, no-edition/recovery behavior, downstream input hash or adjudicated semantic equivalence, no publish during shadow, and cutover with provider credentials absent from Pulse. | Fixture: frozen Pulse shadow window with identical queries, caps, provider response variants, recovery, and publish sink. Test/command: Pulse parity comparator. Assert: every parity clause, explicit differences, equal/equivalent downstream input, zero publish, and credential-free cutover. Retain: parity report, evidence-bundle hashes, and no-publish audit. |
| HSP-17 | Benefits shadow parity requires the same 8 rotating queries/as-of/budgets, known URL/title suppression/cap, candidate IDs/targets/classifications, finalizer and human proposal/apply boundary, explicit zero-leads degraded result, and cutover with provider credentials absent from Benefits. | Fixture: eight-query Benefits shadow window with duplicates, zero-lead, finalizer, proposal, and apply cases. Test/command: Benefits parity comparator and credential-unset cutover test. Assert: all query/budget/suppression/candidate/classification/degraded/approval clauses and no direct provider access. Retain: parity report, candidate manifest, degraded-result record, and approval-bound proposal. |
| HSP-18 | No-bypass enforcement statically rejects provider credentials/endpoints/direct clients/prompt direct skills/artifacts without Hound IDs outside the explicit adapter allowlist, with exclusions only for tests/history/local retrieval/health/deploy/publish; dynamic tests run every migrated consumer with credentials unset. | Fixture: positive forbidden-pattern corpus, allowed `houndd` adapter corpus, and every migrated consumer. Test/command: static scan plus credential-unset matrix. Assert: forbidden consumers fail the scan, allowlisted adapters pass, exclusions are limited to the stated set, and every consumer either uses the socket or fails closed. Retain: scan findings, exclusion manifest, and consumer matrix. |
| HSP-19 | Domain ownership remains outside Hound: no domain logic, scheduler, approval DB, queue, CRM, wiki, Helm, Pulse curation, Benefits registry, social publishing, CRM write, or internal BB/Git/Discord/calendar event ownership is added. | Fixture: ownership map and forbidden-module/config corpus. Test/command: ownership static checker and service capability inspection. Assert: Hound exposes only evidence mechanics and the listed service contract; all domain actions remain caller/native-owner operations. Retain: ownership report and capability dump. |
| HSP-20 | Journal, records, projections, access policies, cursor recovery, and service generation are independently verifiable after crash, index rebuild, backup restore, and local migration; SQLite never becomes a source of truth. | Fixture: store with interleaved records, tombstones, failures, and stale projection. Test/command: `journal verify`, `journal rebuild-index`, restore/replay test. Assert: sequence, IDs, hashes, lineage, access decisions, and authorized cursor results match canonical journal truth after each rebuild. Retain: verification reports, replay manifest, and restored projection checksum. |
| HSP-21 | Completion is machine-verifiable: every implementation artifact/test traces to exactly one acceptance row, all rows have named executable evidence with expected assertions and retained artifacts, and the full acceptance command fails on any missing, duplicated, unordered, or unretained result. | Fixture: acceptance manifest containing every row, fixture, test, command, assertion, and artifact path. Test/command: acceptance-manifest checker followed by the full CI test command. Assert: one-to-one traceability, exactly 22 ordered IDs, all evidence artifacts exist and are retained, and no unlisted artifact is used as proof. Retain: machine-readable acceptance manifest and CI summary. |
| HSP-22 | No migration lane becomes canonical until Ali has explicitly approved the exact immutable cutover proposal; a decline blocks cutover, and the native owner gate validates the exact records/proposal/decision hashes before applying. | Fixture: Pulse and Benefits cutover proposals with exact hashes plus Ali approve/decline decisions and a changed-hash case. Test/command: cutover gate integration test. Assert: only the exact Ali approval permits cutover, decline/changed hashes block it, `decisions.jsonl` alone cannot permit it, and the applied outcome references the validated receipt. Retain: Ali decision, gate validation receipt, proposal hash manifest, and cutover outcome. |
