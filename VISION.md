# Hound canonical vision

This is the single canonical end-state document for Hound. It defines the
boundary for the guarded-write proof kernel and the separate Discovery Spine.
All other narrative docs are supporting references only.

## Purpose

Hound exists to make consequential repository work verifiable without
delegating proof to a transcript. A request becomes a bounded contract: a
reviewed capability sees a repository state, produces a proposal or receipt,
and leaves behind an immutable record that can be audited later.

The acquisition boundary is explicit. In `hound_cli`, acquisition is the
moment a declared repository capability is invoked against the owner Git tree.
In `hound_research`, acquisition is the moment a client requests search,
extract, origin capture, or media transcription from the local discovery
service. In both cases, the boundary ends at immutable evidence.

## Outcomes and Impact

The target state is simple:

- A maintainer can delegate repository work while retaining a verifiable proof
  boundary.
- Reviewers can inspect exact inputs, exact expected effects, and exact
  provenance before approving a write.
- Discovery work can accumulate into a durable local evidence system without
  turning the proof kernel into a lineage database.
- Domain repositories stop rebuilding planning, approval, provenance, and
  index machinery for themselves.
- Historical records remain checkable even after Hound evolves.

## Product Layers

- `hound_cli` is the small guarded-write proof kernel. It remains responsible
  for capability checks, read invocation receipts, deterministic write plans,
  approvals, guarded execution, and verification.
- `hound_research` is a separate discovery client and record layer. It owns the
  search, extract, origin-capture, and media-transcription workflows, plus
  record verification and import tooling.
- `houndd` is the local discovery service. It listens on a Unix-domain socket,
  speaks a versioned JSON API, and owns the append-only journal, the
  content-addressed record store, rebuildable projections, access control, and
  cursor management.
- SQLite is only a rebuildable query projection. It is disposable and must
  never be treated as the source of truth.
- Owner and domain repositories own meaning, curation, schedules, and the
  truth surfaces they already operate.
- Workpad and native gates own consequential approval.

## Roles and Ownership

Hound owns acquisition mechanics and provenance. Domain repositories own search
intent, cadence, curation, transformation, and truth. Workpad and native gates
own the approval seam for consequential actions. Helm, Wiki, and CRM remain
their existing truth surfaces rather than being replatformed into Hound.

The old no-global-lineage and no-global-service refusal still applies to the
proof kernel. `hound_cli` does not become a global lineage service. The
Discovery Spine may own a local journal and local service, but only inside the
research extension and only as a local, rebuildable, auditable subsystem.

## Operating Flow

The proof-kernel flow is:

1. A driver is checked against the manifest and owner repository.
2. A read capability is invoked and returns a receipt.
3. A write capability is planned into exact expected effects.
4. Human approval binds one exact plan when the manifest requires it.
5. The unchanged plan executes.
6. Effects are checked.
7. The run record is written and verified later if needed.

The discovery flow is:

1. A client sends a versioned JSON request to `houndd` or to a compatible
   local adapter path.
2. The request is validated, authorized, and assigned a journal position.
3. The service writes immutable content-addressed record files and appends a
   journal entry.
4. The service updates rebuildable projections, including SQLite.
5. The client receives record IDs, cursors, and any derived references.
6. Consumers replay from the journal, never from SQLite as truth.

## Inputs, Outputs, Jobs, and Record Classes

Inputs are explicit request objects, declared capability manifests, and the
owner state they bind to. Outputs are receipts, plans, approvals, execution
results, record IDs, cursors, and derived projections. A job is one request
through one service boundary with one observable result.

Record classes are:

- Search records: query, adapter, request hash, response hash, leads, and the
  fact that leads are not evidence.
- Extract records: URL, lineage, content hash, raw response hash, extracted
  documents, and derivation metadata.
- Origin capture records: source URL, retrieved time, media type, byte hash,
  blob location, and provenance.
- Media transcription records: source media reference, transcription text or
  transcript spans, timing metadata, and the exact source-to-transcript lineage.
- Failure records: operation, input hash, attempt count, diagnostics, retry
  trail, and refusal reason. Failures do not become evidence just because they
  were observed.

Canonical evidence is stored in immutable content-addressed record files.
Chronology lives in the append-only journal. Projections are derived only.

## CLI, API, and Service Responsibilities

`hound` remains the proof kernel CLI. Its stable surface is `driver check`,
`invoke`, `plan`, `approve`, `execute`, and `verify`. It must stay small and
guarded-write focused.

`hound-research` is the discovery client CLI. Its target surface covers search,
extract, origin capture, transcription, record import, and verification. Legacy
`source.*` compatibility shims may exist, but the semantics belong to the
Discovery Spine.

`houndd` owns the local service contract:

- Unix-domain-socket transport only.
- Versioned JSON requests and responses.
- Append-only journal writes.
- Content-addressed record file creation.
- Access decisions and credential isolation.
- Cursor issuance and replay.
- Projection rebuilds and recovery.
- No domain curation, no truth adjudication, no global registry.

The kernel and the service are separate responsibilities. The kernel proves a
repository operation. The service preserves discovery evidence.

## External Triggers and Cadence

Hound does not own cadence. External systems decide when work happens and pass
that work in as explicit requests.

Supported triggers are:

- direct operator CLI calls;
- domain-repo jobs and scheduled tasks;
- native-gate approvals that unlock consequential steps;
- upstream events that a caller converts into a local request; and
- replay or recovery jobs that rebuild projections from the journal.

Cadence belongs to the caller. The service only reacts to requests and never
pretends to be the scheduler.

## Journal Identity, Lineage, Dedupe, Chronology, and Cursors

The journal is the discovery truth. It is append-only, strictly ordered, and
stable across rebuilds. Every entry has an identity, a position, and references
to the content-addressed record files that support it.

Lineage is explicit and non-destructive. A search record can lead to an extract
record, which can lead to an origin capture or transcription record, and each
hop remains visible. Identical payloads may collapse to the same content hash,
but identical bytes never erase distinct journal events.

Dedupe is lossless. It is allowed to reduce duplicate storage and duplicate
projection rows, but it may not drop provenance edges, input hashes, or
chronological order. The journal must retain the fact that a duplicate arrived
even when the payload bytes were already known.

Cursors are opaque, monotonic per consumer, and independent across consumers.
One consumer's progress must not block or mutate another consumer's replay
position. Any consumer can resume from its own cursor and reconstruct the same
chronological history.

## Access, Retention, and Erasure

Access is deny by default. Read, write, replay, import, and export permissions
must all be explicit. Every tier gets only the credentials and authorities it
needs. The proof kernel, the discovery client, the local service, and each
domain repository are credential-isolated from one another.

Retention is policy-driven and record-class aware. Immutable evidence can live
for audit, but projections and caches are disposable. Erasure applies to mutable
stores and derived projections, not to rewriting the journal history. When
erasure is required, the system may delete blobs, drop projections, and leave a
redacted tombstone that preserves auditability without preserving the content.

PHI is out of bounds. Hound and the Discovery Spine do not ingest, store,
surface, or index PHI. If PHI is detected or suspected, the request is refused
or quarantined before persistence, and the caller is responsible for providing
de-identified input.

## Workpad, Amplify, Decision-Ledger, and Native-Gate Seam

Workpad is the exploration surface. Amplify is the fan-out seam that turns a
single exploration into multiple bounded work items. The decision-ledger is the
durable record of consequential approval. The native gate is the owner system
that issues that approval.

Hound may record the seam, bind to the decision, and preserve the provenance of
the resulting action. Hound does not replace the gate, the ledger, or the
human decision. Consequential approval stays native to the owner environment.

## Observability, Recovery, and Portability

The system must be observable at the request, record, and projection layers.
Useful signals include append rate, rejection counts, cursor lag, projection
freshness, record verification status, store size, and recovery duration.

Recovery must be deterministic. After a crash, the service should be able to
replay the journal, rebuild SQLite, and confirm record hashes without needing a
mutable working set. A failed append may be retried, but the retry must not
invent a new event if the original append already committed.

Portability is a design goal. The store can be copied to another machine, the
journal can be replayed there, and the projections can be rebuilt from the same
content-addressed files. No absolute-path dependency may be required for
verification.

## Staged Shadow Migration and Deletion

Migration is staged and shadowed, not rushed.

1. Import existing records into the local evidence store.
2. Run the new spine in shadow beside the existing Pulse and Benefits paths.
3. Compare outputs, provenance, and chronology until parity is stable.
4. Confirm Pulse shadow parity and Benefits shadow parity separately.
5. Approve cutover explicitly.
6. Stop all bypass writes.
7. Delete superseded duplicate state only after verification and owner
   approval.

Existing-record import is part of the plan, not an optional cleanup step. After
cutover, the old path may remain only as a read-only historical reference until
the owner authorizes deletion.

## Scope and Refusals

In scope:

- the guarded-write proof kernel;
- the Discovery Spine client, service, journal, record store, and projections;
- provenance, replay, and verification;
- local import and shadow migration tooling; and
- explicit owner approval seams.

Out of scope:

- a global lineage database;
- a remote SaaS or fleet service;
- a provider registry or hidden fallback layer;
- a scheduler, notifier, or workflow DAG engine;
- a browser platform or untrusted-code sandbox;
- ownership of domain meaning, curation, or truth;
- PHI storage or propagation; and
- bypass paths around the journal or owner gate.

Hound owns acquisition mechanics and provenance. Domain repos own search
intent, schedules, curation, transformation, and truth. Workpad and native
gates own consequential approval. Helm, Wiki, and CRM remain the truth
surfaces they already are.

## Acceptance Requirements

1. HSP-01: The system must define a single acquisition boundary for the proof
   kernel and a separate acquisition boundary for the Discovery Spine.
2. HSP-02: The small guarded-write `hound_cli` proof kernel must remain
   preserved as the repository execution boundary and must not absorb discovery
   lineage duties.
3. HSP-03: The Discovery Spine must persist an immutable append-only journal
   that is the canonical discovery truth.
4. HSP-04: Journal order must be stable, replayable, and identical across
   rebuilds on the same store.
5. HSP-05: Every record must preserve provenance from request to record file to
   journal entry to derived projection.
6. HSP-06: Extraction records and media transcription records must each carry
   explicit lineage back to their originating search, capture, or media source.
7. HSP-07: Dedupe must be lossless and non-destructive, preserving every
   provenance edge and every chronological event.
8. HSP-08: Access control must default to deny for read, write, replay, import,
   and export.
9. HSP-09: Credential isolation must keep kernel, research client, local
   service, and owner repositories from sharing credential material.
10. HSP-10: CLI behavior and service behavior must remain parity-aligned, so
    the client, the API, and the local service agree on the same record
    semantics.
11. HSP-11: Crash, retry, and index recovery must rebuild the same journal
    state and the same SQLite projection without corruption.
12. HSP-12: Observability must expose append rate, rejection counts, cursor lag,
    projection freshness, verification state, and recovery health.
13. HSP-13: Domain isolation must keep search intent, schedules, curation,
    transformation, and truth inside the owner repositories.
14. HSP-14: The Workpad seam must remain separate from consequential approval,
    and the native gate must remain the authority for that approval.
15. HSP-15: Existing-record import must support replaying historical discovery
    records into the new spine without losing their original hashes or lineage.
16. HSP-16: Pulse shadow parity must be achieved before Pulse cutover is
    allowed.
17. HSP-17: Benefits shadow parity must be achieved before Benefits cutover is
    allowed.
18. HSP-18: Independent consumer cursors must advance without blocking each
    other and must replay the same chronology from the same cursor state.
19. HSP-19: Cutover safety must forbid bypass writes after shadow mode and must
    keep the journal as the only discovery truth path.
20. HSP-20: Store portability must allow the journal and content-addressed
    record store to move between hosts and still verify.
21. HSP-21: Explicit owner cutover approval must be required before any shadow
    path becomes canonical.
22. HSP-22: Retention, erasure, and no-PHI rules must be enforced so mutable
    projections can be removed, immutable journal history remains auditable, and
    PHI never becomes persisted discovery truth.
