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
transcription are requests to `houndd`-owned adapters. Every accepted attempt
that has not failed integrity—including success, failure, refusal, partial
result, and recovered crash outcome—is journaled by `houndd` before the caller
receives a completed result. Pre-acceptance authentication, authorization,
readiness, and integrity failures create no durable attempt and use the
already-defined `400` / `404` / `503` response semantics as applicable.

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

The eventual target `hound-research` surface is exactly these operation
families:

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

This is the approved end state, not a claim that every operation is available
in Slice 3B. Slice 3B is only the first public, read-only service boundary:
`houndd serve` runs in the foreground with no daemonization or scheduler, and
`hound-research journal query` is its only client command. Existing direct
research commands remain transitional legacy commands pending an audited
migration; Slice 3B does not claim HSP completion or no-bypass cutover.

Slice 3B exposes exactly `GET /v1/journal`, `GET /v1/health`, and
`GET /v1/ready`. Route binding requires the exact method, raw path,
`operation.name`, and `producer.capability`; the journal operation is exactly
`journal.query`. Health and readiness are generic and disclose no protected
metadata. Event/record get, verify/rebuild API, providers, systemd activation,
streaming, policy writes or hot reload, durable provenance, migrations, and
no-bypass cutover are deferred from Slice 3B. Ingestion, import, and
transcription POST routes are new Slice 3C additions defined separately below;
they are not existing Slice 3B surface or evidence.

The Slice 3B API is a logical method/path contract carried only over a local
`AF_UNIX` `SOCK_STREAM`; it is not HTTP and never TCP, remote, or provider
transport. Its wire version is `houndd.uds.v1`. One connection carries exactly
one request and one response. Each frame is a four-byte unsigned big-endian
byte length followed by exactly that many bytes of canonical UTF-8 JSON. A
request frame has exactly `wire_version`, `method`, `path`, and `body`; a
response frame has exactly `wire_version`, `status`, and `body`. The encoded
JSON body is at most 1,048,576 bytes. Zero or oversize length, truncation,
invalid UTF-8, duplicate keys, noncanonical JSON, trailing bytes, a second
frame, query strings, fragments, percent-encoded paths, and alternate paths
are invalid. The client half-closes writes after its one request. The server
requires EOF before dispatch, sends at most one complete response, then
closes. Before one unique valid `request_id` is recoverable, a framing failure
closes without a response and never invents a request ID. Logical statuses are
only `200`, `400`, `404`, and `503`; they are not HTTP statuses on an HTTP
listener.

Every Slice 3B pure read carries exactly this request envelope; unknown fields
and `idempotency_key` are invalid:

```json
{
  "schema_version": "houndd.read-request.v1",
  "request_id": "...",
  "producer": { "owner_id": "...", "capability": "...", "run_id": "..." },
  "requested_access": "public|workspace|restricted",
  "policy_id": "...",
  "operation": { "name": "...", "payload": {} }
}
```

The exact Slice 3B response schema is `houndd.read-response.v1`. Its required
fields are `schema_version`, `request_id`, `ok`, `outcome`, `record_ids`,
`entry_ids`, and `usage`; its only optional fields are `result`, `cursor`,
`projection`, and policy-safe `error`; unknown fields fail. `projection` is
permitted only for the documented `intake-ledger.v1` view and is forbidden
otherwise. For a successful authorized journal query, `result` and `cursor` may
appear together; `error` appears only for an applicable non-success outcome:

```json
{
  "schema_version": "houndd.read-response.v1",
  "request_id": "...",
  "ok": true,
  "outcome": "completed",
  "record_ids": ["..."],
  "entry_ids": ["..."],
  "usage": { "requests": 0, "bytes": 0, "cost": 0 },
  "result": ["authorized canonical journal event envelopes in chronological order"],
  "cursor": "..."
}
```

For an authorized journal query without a view, `result` is the strict
chronological canonical-event array; present `entry_ids` and `record_ids` align
with it, and a present cursor is its opaque continuation cursor. The documented
intake-ledger view instead has its exact projected result and projection fields
defined below. There is no sidecar or second truth, total, or snippet. The
response's top-level IDs are empty for the generic unauthorized result.

Pure reads are fresh and stateless: a cursorless query selects a newly verified
journal snapshot/high-watermark on every invocation, so a later append may
appear in a repeated cursorless request. Only a returned cursor preserves the
original high-watermark for continuation or replay. Deterministic projection
maintenance retains no request-result state. Slice 3C durable commit operations
alone require an idempotency key scoped to kernel principal, capability, and
canonical request hash; same-key same-request replay is stable, and
changed-request reuse is rejected as a collision.

### Private intake ledger projection

Slice 3B may additionally expose a read-only `intake-ledger.v1` view on the
existing `GET /v1/journal` / `journal.query` boundary. The exact query payload
has required `filter`, optional `limit`, optional `cursor`, and one additional
optional `view` field only. When present, `view` is an exact built-in `str`
equal to `intake-ledger.v1`; any other value or type is invalid. When absent,
the existing filter/limit/cursor payload and canonical-event result behavior are
unchanged. Unknown payload fields remain invalid.

For this view only, the response is derived only from authorized journal truth
and is not a second ledger. It contains a `projection` object with exactly
`schema_version: "houndd.intake-ledger.v1"`, `integrity: "verified"`, and a
nonempty opaque `high_watermark` commitment. Its `result` is a chronological
ascending array by `(appended_at UTC, sequence, entry_id)` of rows having
exactly these fields:

```text
entry_id
appended_at
producer{owner_id, capability, run_id}
operation{capability, artifact_kind}
source{provider}
classification{outcome, evidence_status}
artifact{record_id}
lineage{relation, record_id, lead_id}
access
```

No other ledger-row fields are permitted. Present top-level `entry_ids` and
`record_ids` align with the projected rows. PHI, snippets, summaries, raw bytes,
paths, credentials, provider responses, source URLs/native IDs, authorized
URIs, and content/object hashes are omitted or redacted. A present continuation
cursor and the high-watermark commitment are opaque. The selected view is bound
into the canonical query context/filter hash and cursor, so a continuation
cannot change it; Hound stores no page, session, or query state.

Authorization happens before metadata inspection, projection, high-watermark
selection, or cursor issuance. An invalid or unsupported view or cursor is
`400`; an unauthorized or absent scope is generic `404` before projection,
high-watermark, or cursor work; readiness, integrity, recovery, policy, and
cursor-key-generation failures are `503`. Visible `integrity: verified` and
`service readiness: ready` labels are derived display states only and do not add
canonical statuses. Workpad may render this projection read-only only; it gains
no write, approval, ranking, publication, CRM, wiki, or source-dereference
authority. This section adds no new HSP completion claim.

### Slice 3C route bindings and 3C1 availability

Slice 3C reserves exactly these local `AF_UNIX` `SOCK_STREAM` POST bindings:

| Method | Raw path | Operation | Required capability |
| --- | --- | --- | --- |
| `POST` | `/v1/ingest/search` | `ingest.search` | `ingest.search` |
| `POST` | `/v1/ingest/url` | `ingest.url` | `ingest.url` |
| `POST` | `/v1/ingest/file` | `ingest.file` | `ingest.file` |
| `POST` | `/v1/ingest/media` | `ingest.media` | `ingest.media` |
| `POST` | `/v1/transcribe` | `transcribe` | `transcribe` |
| `POST` | `/v1/import-record` | `import.record` | `import.record` |

For every row, `operation.name` and `producer.capability` MUST each equal
the operation value in that row, byte-for-byte. No alias, broader capability,
caller-selected capability, or capability/operation mismatch is valid.

The first durable implementation slice, Slice 3C1, may expose only
`POST /v1/ingest/file` and `POST /v1/import-record`. The other four bindings
remain reserved but unavailable: they MUST NOT dispatch, select an adapter,
read a source, create a transaction, or create durable state. A request to an
unimplemented reserved binding receives the existing generic unavailable-route
response and no attempt. Slice 3C1 MUST NOT claim full Slice 3C completion or
availability of search, URL extraction, media capture, or transcription.

These are logical method/path routes, not HTTP, TCP, remote, provider, or
scheduler transports. They use one request and one response per connection,
canonical UTF-8 JSON, EOF-before-dispatch, exact raw path binding, and the
existing 1,048,576-byte encoded JSON body ceiling. POST support and commit
dispatch are new Slice 3C work; they do not expand or rewrite Slice 3B.

The exact durable request body is `houndd.commit-request.v1`:

```json
{
  "schema_version": "houndd.commit-request.v1",
  "request_id": "...",
  "idempotency_key": "...",
  "producer": { "owner_id": "...", "capability": "...", "run_id": "..." },
  "requested_access": "public|workspace|restricted",
  "policy_id": "...",
  "operation": { "name": "...", "payload": {} }
}
```

Unknown fields are invalid. `idempotency_key` is required for these durable
POSTs and remains forbidden in the pure-read request. The route, operation name,
and `producer.capability` bind exactly to the six mappings above. The caller
supplies one exact `policy_id`; the daemon resolves exactly that policy and
never unions policy IDs or their rules. Authorization and the effective access
ceiling occur before source lookup, record lookup, provider selection, or
provider invocation. Authorization denial or an absent protected target is a
generic logical `404` / CLI exit 3. Policy-file integrity, change, replacement,
or recovery/readiness failure is logical `503` / CLI exit 5, not an authorization
denial.

The exact durable response body is `houndd.commit-response.v1`:

```json
{
  "schema_version": "houndd.commit-response.v1",
  "request_id": "...",
  "ok": true,
  "outcome": "completed",
  "record_ids": ["..."],
  "entry_ids": ["..."],
  "usage": { "requests": 0, "bytes": 0, "cost": 0 }
}
```

`error` is the only optional field, is omitted for a completed success, and is
always policy-safe when present. Unknown fields fail. Durable responses return
IDs, outcome, usage, and optional policy-safe error only: they never return a
`result`, `cursor`, source bytes, transcript body, provider response, or other
result body. A completed outcome is logical
`200`, `ok: true`, CLI exit 0.
Every durable non-completed outcome—`failed`, `partial`, `degraded`, `refused`,
or `interrupted`—is logical `200`, `ok: false`, and CLI exit 4. Invalid framing,
envelopes, payloads, source declarations, import ID/byte conflicts, and changed
idempotency-key reuse are logical `400` / CLI exit 2. Unavailable service or
adapter readiness, integrity, recovery, or required-primitive failures before
acceptance are logical `503` / CLI exit 5 and create no durable attempt. After
acceptance, an absent adapter or adapter abstention is a durable `degraded` or
`refused` outcome, logical `200` / `ok: false` / CLI exit 4, with one final
outcome record and journal event.

The operation payloads are strict and contain no unknown fields:

- `ingest.search`: `{ "query": "...", "limit": 1..50 }`.
- `ingest.url`: `{ "url": "...", "lineage": { "kind": "direct" } }`, or
  `{ "url": "...", "lineage": { "kind": "search", "record_id": "...", "lead_id": "..." } }`;
  optional `max_pages` is bounded to 2..20. The URL uses the existing
  public-URL validator.
- `ingest.file` and `ingest.media`: `{ "source": SOURCE, "media_type": "..." }`.
- `import.record`: `{ "record_id": "...", "source": SOURCE }`.
- `transcribe`: `{ "capture_id": "..." }` and no provider/model fields.

`SOURCE` is exactly one of these shapes, with no additional fields:

```json
{ "kind": "bytes", "body_base64": "...", "sha256": "...", "byte_length": 0 }
{ "kind": "path", "path": "...", "sha256": "...", "byte_length": 0 }
```

`byte_length` is an unsigned integer from 0 through 16,777,216 (16 MiB), and
the declared SHA-256 and length must match the bytes actually read. The wire
ceiling applies to the encoded JSON body, while the 16 MiB cap applies to
decoded inline bytes, path bytes, and any adapter-returned source bytes before
staging. For an inline bytes source of decoded length `N`, acceptance requires
`4*ceil(N/3) + canonical_metadata_bytes <= 1,048,576`; the complete canonical
encoded request is authoritative. Larger approved sources use a path.
`body_base64` uses RFC 4648 standard-alphabet canonical spelling with required
padding: whitespace and alternate spellings are invalid, and decoding then
re-encoding must reproduce the supplied built-in `str` byte-for-byte.
Before request hashing or durable staging, the daemon reads/decodes SOURCE and
replaces it with exactly `{ "sha256": "...", "byte_length": N }`. `SOURCE.kind`,
`path`, and `body_base64` are excluded from canonical identity and are never
persisted, logged, returned, journaled, indexed, or placed in diagnostics.
For a path, the daemon opens the absolute owner-readable path with no symlink
following, holds that descriptor, and reads only from it. It validates a
regular-file held-FD identity and size before and after the read (including
device/inode stability), then verifies the declared digest and length; any
TOCTOU change, non-regular file, oversize, or mismatch fails closed. No source
path participates in identity.

### Slice 3C1 PHI scanner boundary

For Slice 3C1, the only source representation eligible for a `clear` result is:

- media type exactly `application/octet-stream`;
- content encoding exactly `identity`;
- decoded source bytes of length `0..16,777,216`;
- a source digest present in the local operator-provisioned clear manifest.

The inline request `body_base64` representation is transport encoding only. It
is decoded, verified, and removed before scanning; it is never the scanned
content encoding and is never persisted.

The local scanner boundary is `houndd.phi-scan.v1`:

```text
scan(data: bytes, media_type: str, encoding: str, operation: str)
    -> clear | suspected | unknown (future slices only) | error
```

For Slice 3C1, `operation` is exactly `ingest.file` or `import.record`.

The scanner is local, deterministic, bounded by the 16 MiB source limit, and
has no network, provider, model, browser, or external-process dependency. It
MUST recompute SHA-256 over the supplied bytes and compare the exact tuple
`(sha256, media_type, encoding)` with the clear manifest. The manifest is
`${state}/service/phi-clear.json`, owned by the service user, mode `0600`,
validated before readiness, and frozen for the service lifetime:

```json
{
  "schema_version": "houndd.phi-clear.v1",
  "entries": [
    {
      "sha256": "...",
      "media_type": "application/octet-stream",
      "encoding": "identity"
    }
  ]
}
```

The manifest has no other fields; entries are unique and sorted by
`(sha256, media_type, encoding)`. A `clear` result certifies only that the
exact bytes match an operator-attested non-PHI digest for the exact media type
and encoding. It does not claim that a regex, heuristic, or general-purpose
content scan has detected all PHI.

Scanner outcomes are fail-closed:

- `clear`: the request may continue.
- `suspected`: the supported representation is not certified clear.
- `error`: the scanner or clear manifest is unavailable, malformed, or
  internally inconsistent.

For `ingest.file`, `media_type` MUST therefore be exactly
`application/octet-stream`. For `import.record`, the source is implicitly
`application/octet-stream` with `identity` encoding.

Slice 3C1 has no reachable `unknown` scanner outcome. Its only supported
representation is exactly `application/octet-stream` with `identity` encoding;
an unsupported media type or encoding is an ordinary invalid request, logical
`400`, before scanner evaluation and with no durable attempt. `unknown` is
reserved solely for a future slice that expands the scanner boundary and has no
Slice 3C1 status mapping.

For both Slice 3C1 operations, after the completed-reservation replay probe has
returned no match, source authorization, held-source normalization,
length/digest verification, and scanner evaluation occur before creating the
idempotency reservation, attempt marker, staging, blob write, record write,
journal append, logging of source-derived diagnostics, or response construction.
`clear` is the only outcome that may reach acceptance.

A `suspected` result is a pre-acceptance refusal: logical `400`, `ok:false`,
`outcome:"invalid"`, policy-safe error code `"source_refused"`, empty
`record_ids` and `entry_ids`, and no durable attempt. A scanner `error` is
logical `503`, `ok:false`, `outcome:"unavailable"`, empty IDs, and no durable
attempt. None of these outcomes may persist raw bytes, source paths, Base64,
source kind, scanner diagnostics, or PHI. Slice 3C1 therefore uses no durable
PHI quarantine record; the existing bounded non-PHI-quarantine rule remains
applicable to a future accepted adapter slice.

Thus, a supported Slice 3C1 representation whose digest is absent from the
clear manifest is `suspected` and `400`/`source_refused`; a scanner or manifest
error is `503`. These are the only 3C1 scanner status mappings.

`ingest.media` creates an immutable authorized media-capture record and returns
its capture record ID. That record retains the exact source-byte hash, media
type, and source lineage. `transcribe` accepts only that ID; it must resolve to
an authorized `kind=media` capture under the effective scope with that exact
hash, type, and lineage before any model call. Provider, model, exact model
version, language, segment/timing hashes, text hash, and transcription status
are daemon-produced provenance, never caller-controlled request fields.

### Slice 3C1 operation records

The following records are strict canonical JSON objects with no unknown fields.

`houndd.file-record.v1`:

```json
{
  "schema_version": "houndd.file-record.v1",
  "attempt_id": "...",
  "request_hash": "...",
  "operation": "ingest.file",
  "outcome": "completed|failed|partial|degraded|refused|interrupted",
  "evidence_status": "clear|failure|partial|degraded|refused|interrupted",
  "source": {
    "sha256": "...",
    "byte_length": 0,
    "media_type": "application/octet-stream",
    "encoding": "identity"
  },
  "lineage": {
    "relation": "none",
    "record_id": "none",
    "lead_id": "none"
  }
}
```

`houndd.import-outcome.v1`:

```json
{
  "schema_version": "houndd.import-outcome.v1",
  "attempt_id": "...",
  "request_hash": "...",
  "operation": "import.record",
  "outcome": "completed|failed|partial|degraded|refused|interrupted",
  "evidence_status": "clear|failure|partial|degraded|refused|interrupted",
  "legacy": {
    "record_id": "...",
    "sha256": "...",
    "byte_length": 0,
    "media_type": "application/octet-stream",
    "encoding": "identity"
  },
  "lineage": {
    "relation": "...",
    "record_id": "...",
    "lead_id": "..."
  }
}
```

For `import.record`, the request's `record_id` is the supplied legacy identity,
not necessarily the byte SHA-256. The daemon verifies the declared digest and
length, preserves that ID and exact bytes create-only, and rejects an ID/byte
conflict without rewriting anything.

The file-record or import-outcome record ID is the SHA-256 of its canonical
record bytes. The file source bytes are stored as the exact content blob whose
digest is `source.sha256`. The import legacy object is stored as the exact
caller-supplied bytes at the supplied `legacy.record_id`; it is never wrapped,
rewritten, re-encoded, re-hashed into a replacement ID, or treated as the
operation outcome record.

The preserved legacy object is a payload artifact, not a second outcome and not
a second journal event. The import-outcome record is the sole operation outcome
record for the one-outcome requirement.

Authorized record URIs use exactly:

```text
houndd://record/<record_id>
```

The journal artifact for `ingest.file` is the file-record ID, with schema
`houndd.file-record.v1`, hash equal to the canonical file-record bytes, and URI
`houndd://record/<file-record-id>`. Its dedupe object key is
`file:<source-sha256>` and its `content_sha256` is the source blob digest.

The journal artifact for `import.record` is the import-outcome ID, with schema
`houndd.import-outcome.v1`, hash equal to the canonical import-outcome bytes,
and URI `houndd://record/<import-outcome-id>`. Its dedupe object key is
`legacy:<legacy-record-id>` and its `content_sha256` is the exact legacy-byte
digest. The outcome metadata's `legacy.record_id` is the reference to the
preserved raw object.

For `ingest.file`, journal `source` is exactly
`{"provider":"local","native_id":"<source-sha256>","canonical_url":"none"}`.
For `import.record`, journal `source` is exactly
`{"provider":"legacy","native_id":"<legacy-record-id>","canonical_url":"none"}`.
These are fixed provenance labels, not provider selection or network access.

An accepted Slice 3C1 attempt has exactly one final outcome record and one final
journal event. A file response contains exactly one record ID (the
file-record ID) and one entry ID. An import response contains exactly two
record IDs, in this order:

```text
[legacy-record-id, import-outcome-record-id]
```

It contains exactly one entry ID: the event for the import-outcome record.
Same-key replay returns the same response and appends neither a record nor an
event. A different key for identical legacy bytes reuses the immutable raw
legacy object but creates a distinct import-outcome record and journal
occurrence.

### Slice 3C1 lineage rules

`ingest.file` has no caller-supplied lineage and always uses the explicit
no-lineage value shown in `houndd.file-record.v1`.

`import.record` never parses arbitrary legacy bytes to infer lineage. After
authorization and source verification, the daemon selects only authorized
existing journal events for which `source.provider == "legacy"` and
`source.native_id == <supplied-legacy-record-id>`. It compares those events'
exact lineage values:

1. If no selected event exists, it uses
   `{"relation":"none","record_id":"<legacy-record-id>","lead_id":"none"}`.
2. If all selected exact lineage values agree, it reuses that exact value.
3. If selected exact lineage values disagree, lineage is ambiguous: the request
   fails closed as logical `503` before acceptance, with no reservation or
   durable state.
4. An ID/byte conflict is logical `400` before acceptance and never overwrites
   the existing object. An existing object with identical bytes is confirmed
   create-only.

This amendment clarifies that the one-outcome/one-event rule excludes the
separately preserved raw legacy payload object, while the legacy portability
requirement continues to require byte-for-byte identity, caller-supplied ID
preservation, create-only conflict handling, lineage preservation, and portable
rebuild.

Before any source I/O, a Slice 3C1 request that has passed peer authentication,
exact route/envelope validation, exact policy selection, and authorization
performs a read-only completed-reservation replay probe. The probe binds
`principal`, `producer.capability`, and `idempotency_key` to the complete
declared normalized-request identity obtainable without source bytes: the bound
route, complete `producer`, `requested_access`, exact policy ID, complete
operation/payload, and the declared source `sha256` and `byte_length`. For a
`SOURCE`, that identity uses only its declared
`{"sha256":"...","byte_length":N}` normalization; `SOURCE.kind`, `path`, and
`body_base64` remain excluded. As elsewhere, only `request_id` and
`idempotency_key` are excluded from the request identity.

An exact completed match returns the stored response without opening, decoding,
or rereading `SOURCE` and creates no state, attempt, or journal event. A
completed reservation for the same `principal`, capability, and key whose bound
declared request identity differs in any field, including route, producer,
requested access, policy ID, operation/payload, declared digest, or declared
length, is logical `400` collision and MUST NOT fall through to a new attempt.
An incomplete, noncanonical, hash-disagreeing, or otherwise tampered reservation
or reservation/open pair is an integrity failure, logical `503`, and is never a
replay. Only a no-match proceeds to normal source verification, scanner
evaluation, lineage selection, and reservation flow.

Under the transaction lock, the daemon creates and fsyncs the idempotency
reservation and private attempt-open marker as one validated pair before any
adapter call. A partial pair is an integrity failure; neither file is canonical
journal truth. The reservation/open metadata is owner-only transaction state,
not an additional journal event. After source normalization, `request_hash` is
the SHA-256 of canonical JSON containing the bound route, producer, requested
access, exact policy ID, operation, and normalized payload, excluding only
`request_id` and `idempotency_key`. The durable attempt identity is
`attempt_id = SHA256(canonical JSON({"principal": principal, "capability": capability, "idempotency_key": idempotency_key, "request_hash": request_hash}))`.

### Slice 3C1 commit ordering

For `ingest.file` and `import.record`, after the no-match result of the
completed-reservation replay probe, normalized-source PHI scanning is an
additional pre-acceptance step immediately after source verification. The
existing post-acceptance PHI-scan step remains the rule for future
adapter/provider operations. No Slice 3C1 operation may persist raw source
bytes before a `clear` result.

For Slice 3C1, authenticate the peer, validate the exact route and envelope,
resolve the one requested policy, and authorize. Then perform the read-only
completed-reservation replay probe defined above, before opening, decoding, or
rereading `SOURCE`. Only a no-match continues to normalize/read/verify/hash the
source, select import lineage, and evaluate the scanner before creating the
idempotency reservation, attempt marker, staging, blob, record, journal event,
source-derived diagnostic, or response. Only `clear` may continue. Then, under
the transaction lock, create and fsync the reservation and private open marker
as one validated pair, publish the strict operation record and exact source
object create-only, append the one final journal event, and persist the
completed response. A partial pair, hash disagreement, or ambiguous metadata
fails closed as an integrity failure.

For future adapter/provider operations, the general ordering remains:

1. Authenticate the peer, validate the exact route/envelope, resolve the one
   requested policy, authorize, then normalize/read/verify/hash any `SOURCE`
   supplied by the operation and compute the canonical request hash before any
   durable reservation.
2. Under the transaction lock, create and fsync the idempotency reservation and
   private open marker as one validated pair.
3. Invoke exactly one allowlisted adapter, with no retry, fallback, escalation,
   or caller-selected provider; after acceptance, an absent adapter or
   abstention records the durable `degraded` or `refused` outcome.
4. PHI-scan before persistence, then durably stage exact returned bytes or a
   bounded policy-safe failure/partial diagnostic.
5. Create-only publish the immutable outcome record and content blob.
6. Append and durably persist exactly one immutable journal event referencing
   that record.
7. Persist the completed idempotency response and acknowledge only when the
   record/event pair is logically crash-recoverable. Record/event publication
   is logically crash-recoverable, not filesystem-atomic.

Recovery never retries a provider call. Recovery states are exactly:
`open/no stage` becomes one explicit `interrupted` outcome; `staged` publishes
once; `record/no event` appends the verified event once; and `event/no record`,
`partial pair`, hash disagreement, or ambiguous metadata fails closed as an
integrity failure and is never silently repaired or deleted. A committed attempt
replays the same IDs without a second record, blob occurrence, or journal event.
Every accepted attempt that has not failed integrity therefore has one final
immutable outcome record and one final immutable journal event. A Slice 3C1
pre-acceptance refusal is not an accepted attempt and has no durable attempt.

Explicit Slice 3C1 deferrals are search, URL extraction, media capture,
transcription, provider/model selection, adapter retry/fallback behavior,
durable post-acceptance PHI quarantine, CLI option syntax, migration/cutover,
telemetry, and full no-bypass enforcement. Evidence for this amendment names
Slice 3C1 only and does not claim full Slice 3C availability or HSP completion.
No additional contract-level owner decision is required; the operational
prerequisite is provisioning the local clear manifest, and an absent entry
refuses the source by the fixed rules above.

This section freezes the Slice 3C contract only. It makes no HSP completion
claim and does not alter the keyless pure-read contract above.

The portable defaults are `$XDG_RUNTIME_DIR/hound/houndd.sock` for the socket
and `${XDG_STATE_HOME:-$HOME/.local/state}/hound/discovery` for state. The
service fails closed when `XDG_RUNTIME_DIR` is missing or relative unless an
explicit absolute CLI or test override supplies the socket location. Location
overrides never enter canonical identity. Runtime and state directories are
`0700`, the socket is `0600`, and the policy file is `0600`; unsafe or
unexpected ownership/permissions fail closed. No absolute filesystem path
participates in canonical identity.

The certified Linux principal is exactly `linux-uid:<decimal uid>`, from
`SO_PEERCRED` on the accepted socket before request evaluation or state access.
PID, GID, request fields, environment, and producer claims cannot override it.
The owner-only per-user boundary makes same-UID applications one cooperative
trust domain; multi-UID/application isolation is not claimed. The canonical
operator-provisioned policy is the owner-only, read-only
`${state}/service/policy.json`, schema `houndd.policy.v1`. It maps the existing
`PolicyBundle`, `PolicyRule`, and `ProducerSelector` concepts to the exact
principal/producer/tier grants and policy-ID selection semantics; its full JSON
structure remains an implementation contract rather than a competing policy
model. The daemon selects exactly one `policy_id` and never unions rules across
policy IDs. There is no policy database or write API. Policy is frozen for the
service lifetime; replacement or change makes readiness fail closed, and its
exact bytes/hash participate in backup, restore, and local-migration
verification.

`requested_access` is a disclosure ceiling, never a relabel:
`public -> {public}`, `workspace -> {public,workspace}`, and `restricted ->
{public,workspace,restricted}`. Effective readable tiers are the exact policy
grants intersected with that ceiling. An access filter outside the effective
scope returns the generic unauthorized result before journal access.
Authorization precedes journal/record lookup, filters, counts, pagination,
result construction, and cursor issuance. Completed authorized queries,
including empty queries, are logical `200` / CLI 0. Malformed
frame/envelope/path/cursor and unavailable derived filters are logical `400` /
CLI 2. Unresolved scope is generic logical `404` / CLI 3 with empty IDs and no
result, cursor, count, hint, or metadata; a resolved authorized collection with
no visible matches is completed empty / 0. Unready, integrity, recovery,
policy-file integrity/change/recovery/readiness, connection, and timeout
failures are logical `503` / CLI 5. Authorization denial or an absent protected
target is always logical `404` / CLI 3. Exit 4 is reserved for durable
failed/partial/degraded/refused/interrupted operations and is unused by Slice
3B.

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

Search, extract, capture, file, transcription, import outcome, refusal, failure,
and recovery records use this envelope. The Slice 3C1 preserved raw legacy
payload is a separate exact-byte artifact, not an operation outcome record or
journal event. Lineage is explicit and non-destructive: search leads can lead
to captures, captures can lead to extracts or transcriptions, and every hop
remains observable to an authorized principal.

## Atomic and idempotent commit semantics

Every accepted Slice 3C provider attempt that has not failed integrity,
including rate limit, timeout, truncated bytes, model failure, refusal,
partial output, adapter abstention, and process interruption, receives one
durable immutable final outcome record and one journal event. Authentication
and authorization failures are pre-acceptance and create no durable attempt
under the existing `400` / `404` semantics. A
private attempt-open marker is transaction metadata only; it is not an immutable
record or journal truth. If the process dies before an outcome is received,
recovery commits an explicit interrupted outcome rather than erasing the
attempt. Integrity-failed attempts are excluded from this final-outcome
guarantee. Slice 3C1 pre-acceptance source refusal or scanner unavailability is
not an accepted attempt and creates no durable attempt.

Only a durable commit request has an idempotency key scoped to the kernel
principal, capability, and canonical request hash. The key is commit
coordination and recovery metadata; it is not an additional canonical
journal-envelope field or a pure-read field. The same key with the same
canonical request returns the same identity and result and does not append a
second outcome; reuse of that key with a different canonical request fails as
an invalid collision. For Slice 3C1, an authorized read-only completed-
reservation probe uses the declared normalized-request identity before any
source I/O: an exact match returns the stored response, while any changed bound
field is the `400` collision and cannot create another attempt. Incomplete or
tampered reservation state is `503` integrity failure, not replay. Different
occurrences, even with equal content, always receive distinct observations/
events. These durable commit semantics are deferred from Slice 3B.

The Slice 3C1 ordering is authoritative above. For future adapter/provider
operations, the seven-step ordering there applies: authorization and source
normalization precede the reservation; one allowlisted adapter runs without
retry or fallback; the post-acceptance PHI scan precedes staging; then the
record/blob, one journal event, and idempotency response are published with
logical crash recovery.

Recovery uses the same exact state rules specified in the Slice 3C commit
ordering: `open/no stage` becomes `interrupted`; `staged` publishes once;
`record/no event` appends the verified event once; `event/no record`,
`partial pair`, hash disagreement, or ambiguous metadata fails closed.
Projection rebuild uses only committed journal events; a crash during projection
maintenance never changes canonical truth or re-invokes a provider.

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

`journal query` and `GET /v1/journal` accept an operation payload with a
required filter object. Its only filters are: chronological `time_range`
(`appended_at` inclusive lower and exclusive upper bound); `producer`
(`owner_id`, `capability`, and/or `run_id`); `lane`; `topic`; source
`provider` and/or `canonical_url`; `entity`; `entry_id`; `record_id`;
`object_key`; `content_sha256`; classification `outcome` and/or
`evidence_status`; and `access` tier. Multiple supplied filters are ANDed;
each multi-value filter is an OR within that field. Slice 3B returns
`filter_not_available` / logical 400 / CLI 2 for `lane`, `topic`, and `entity`
until durable provenance exists. Results are authorized and chronological
ascending by `(appended_at, sequence, entry_id)`. A cursorless invocation
selects a newly verified high-watermark before evaluation; only its returned
cursor preserves that high-watermark, resumes strictly after its last result,
and cannot advance beyond it.

The documented `intake-ledger.v1` view adds only its optional `view` selector to
that payload and has the exact authorized-row projection and cursor binding
defined above; it adds no filter family, count, snippet, or saved query state.

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
Streaming is deferred from Slice 3B. Cursor continuation/replay is
deterministic within its original high-watermark: a consumer may replay safely,
sees no lost authorized events, and uses its own `entry_id` handling to avoid
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
caregiver runtime data and no PHI. Suspected or confirmed PHI is rejected or
quarantined before persistence. Slice 3C1 refuses suspected or scanner error
pre-acceptance and creates no quarantine record; unsupported media or encoding
is invalid before scanner evaluation. A future accepted adapter slice may use
only a non-PHI quarantine manifest containing the hash,
length, reason, and access metadata. Raw suspected or confirmed PHI is never
persisted. No source, transcript, provider response, error, index, metric, or
response may contain PHI. Transcription records retain hashes and policy-safe
provenance only, unless a separately approved non-PHI representation is
established.

## Transcription provenance

Every transcription record names the origin media capture, model/provider and
exact model version, language, segment/timing hashes, text hash, status, and
exact source lineage. Status is explicit (`completed`, `partial`, `failed`, or
`degraded`, `refused`, or `interrupted`); partial, failed, degraded, refused,
and interrupted transcripts are durable non-completed outcomes, never silently
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

Service startup recovery and verification complete before identity load or
listening; request-time reads never repair or rebuild SQLite. Recovery is
deterministic and local: restore backups, verify record hashes, replay the
journal, rebuild SQLite, and compare IDs, bytes, lineage, and sequence. SQLite
is disposable. A restored store must preserve legacy and new record IDs and
lineage without an absolute-path dependency. Backup restore, index rebuild,
and service generation changes invalidate/reissue cursors according to the
cursor binding rules. The daemon owns transport authentication, enforcement,
identity, recovery, journal reads, and cursors; the operator owns the canonical
policy file and service lifecycle; lane owners own intent, cadence, and
consumer-held cursors.

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
| HSP-03 | Slice 3B is future-facing partial coverage only: `houndd serve` is foreground/no-scheduler and `hound-research journal query` uses exactly `GET /v1/journal`, `GET /v1/health`, and `GET /v1/ready`. It uses local `AF_UNIX` `SOCK_STREAM`, wire `houndd.uds.v1`, one length-prefixed canonical-JSON request/response per connection, strict raw method/path binding, EOF-before-dispatch, and no HTTP/TCP/remote/provider transport. Pure reads use exactly `houndd.read-request.v1`, forbid `idempotency_key`, and use strict `houndd.read-response.v1` with optional appropriate `result`, `cursor`, `projection` only for the documented partial `intake-ledger.v1` view, and policy-safe `error`; durable commit idempotency is deferred from Slice 3B. Slice 3C separately reserves the six exact POST bindings defined above; Slice 3C1 may expose only `ingest.file` and `import.record`, and this is not claimed as Slice 3B evidence or full Slice 3C completion. The XDG defaults, absolute-only explicit override, owner-only runtime/state/socket/policy permissions, and exits 0/2/3/5 apply to Slice 3B; exit 4 is unused by that slice. | Fixture: Slice 3B CLI/API golden request/response/error, frame-negative, permission, and socket-only service sets. Test/command: Slice 3B CLI and service-contract tests. Assert: the only Slice 3B public routes and envelope fields are exact; invalid framing/path/body fails as specified; pure reads retain no result state; defaults/overrides preserve identity; no scheduler or alternate transport starts; Slice 3C POST additions are tested separately; and all Slice 3B claims remain partial. Retain: request/response/error transcript, framing matrix, permission report, and service capability report. |
| HSP-04 | The immutable journal envelope contains exactly the required fields and omits summary, priority, status, next_action, approval, CRM/wiki claims, and domain tags from canonical truth. | Fixture: one record for each artifact kind plus an unknown-usage case. Test/command: envelope schema/negative-schema test and `journal verify`. Assert: required field set, value domains, hashes, and omission set match this contract; unknown usage is omitted. Retain: canonical envelope JSONL and verifier report. |
| HSP-05 | Provider attempts that have not failed integrity, including failures, are durable; outcome-record and journal-event publication is logically crash-recoverable, not filesystem-atomic; idempotency keys make retries one commit; durable `failed`, `partial`, `degraded`, `refused`, and `interrupted` outcomes use logical 200/`ok:false` and CLI exit 4; all specified crash points recover without duplicate or orphan truth. For Slice 3C1, an authorized read-only completed-reservation probe precedes source I/O; pre-acceptance source refusal, scanner suspected/error, unsupported media/encoding, and ID/byte or lineage-ambiguity refusal create no attempt; the preserved raw import payload is excluded from the one outcome-record/one-event count. The reservation and private open marker are a lock-held, fsynced validated pair and neither is journal truth. | Fixture: fault-injecting adapter for success, 429, timeout, truncation, abstention, and process kill at each commit point. Test/command: atomic-commit recovery test with repeated idempotency key. Assert: an exact completed replay returns the original response without source I/O or new state/attempt/event; any changed bound request field, digest, or length is `400` collision; incomplete/noncanonical/tampered reservation state is `503`; and accepted attempts have one attempt, one outcome record, and one journal event. Import responses preserve the raw legacy ID plus a distinct outcome ID while retaining exactly one event; durable non-completed outcome, no event without record, no acknowledged record without event, and no provider retry. Retain: fault schedule, recovery journal, record hashes, and idempotency result. |
| HSP-06 | Search, extract, capture, import, and transcription lineage is exact and durable; Slice 3C1 uses strict file and import-outcome records, preserves the raw legacy import object separately, selects authorized legacy lineage only from events where `source.provider == "legacy"` and `source.native_id == <legacy-record-id>`, uses canonical no-lineage when none exist, reuses only matching exact values, and refuses disagreement closed before acceptance; `ingest.media` creates an authorized immutable media-capture ID with exact source hash/type/lineage, and transcription records name that origin media, model/provider/version, language, segment/timing hashes, text hash, status, and source lineage; `partial`, `failed`, `degraded`, `refused`, and `interrupted` remain explicit and PHI-free. | Fixture: media capture with two timed segments, partial model result, failed model result, degraded/abstained result, interrupted result, and imported record. Test/command: provenance verifier and transcription lineage test. Assert: every edge and hash resolves, `transcribe` accepts only the authorized media-capture ID, all non-completed statuses remain non-complete, import bytes/IDs remain exact, no selected event uses an artifact identifier in place of the exact legacy source selector, ambiguous lineage fails closed, and no transcription lacks its capture or emits PHI. Retain: lineage graph JSON, segment manifest, and verifier output. |
| HSP-07 | Every occurrence remains a distinct event; equal blobs may share storage; `object_key` groups revisions; `content_sha256` identifies bytes; URL dedupe is never destructive. | Fixture: concurrent same-content captures from two providers and two URL revisions. Test/command: concurrent dedupe test plus `journal query`. Assert: distinct entry/record identities and lineage with shared blob only where exact bytes match; no URL occurrence is deleted. Retain: event list, blob index, and dedupe report. |
| HSP-08 | `journal query`/`GET /v1/journal` has the specified ANDed filter families (OR within a multi-value family), chronological ascending canonical-event results, and no totals or snippets. The documented partial `intake-ledger.v1` view is the sole exception: it returns only its allowlisted chronological authorized-row projection, with its view bound into the cursor context and no added query state. Until durable provenance exists, `lane`, `topic`, and `entity` return `filter_not_available` / logical 400 / CLI 2. A cursorless read selects a newly verified high-watermark on every invocation; only a returned opaque cursor binds service generation, filter hash, principal, last sequence, and its original high-watermark for continuation/replay. Consumers own cursors/ack/progress; Hound retains no saved query, delivery, acknowledgement, subscriber, or pure-read result state; streaming is deferred from Slice 3B. | Fixture: two principals, available-filter matrix, unavailable-derived-filter set, later append, cursor continuation/replay, and independently stored consumer cursors. Test/command: query, cursor-binding, and replay tests. Assert: filters, ordering, fresh cursorless high-watermarks, preserved cursor high-watermarks, generic authorization behavior, and no server request-result/subscriber state are exact. Retain: query fixtures, cursor transcript, and storage inventory. |
| HSP-09 | The certified Linux principal is exactly `linux-uid:<decimal uid>` from accepted-socket `SO_PEERCRED`, before request evaluation/state access; PID, GID, environment, and request/producer claims cannot override it. Owner-only runtime/state directories, socket, and canonical read-only `${state}/service/policy.json` establish a cooperative same-UID boundary only. The frozen `houndd.policy.v1` policy uses `PolicyBundle`/`PolicyRule`/`ProducerSelector` semantics; the caller supplies one exact policy ID, the daemon selects exactly that ID without unions, and policy change/integrity/recovery fails readiness. Policy grants intersect the `requested_access` disclosure ceiling; authorization precedes every source/record/provider access. Authorization denial or an absent protected target is generic 404/CLI 3; policy integrity/change/recovery is 503/CLI 5. | Fixture: distinct peer UIDs, forged identity claims, exact policy-ID rules, replacement policy, one event per tier, out-of-scope target, and unauthorized query. Test/command: Unix-peer ACL and policy-lifecycle negative tests before source/provider access. Assert: exact principal formation/non-override, one-policy selection/no unions, ceiling intersection, 404 versus 503 distinction, fail-closed replacement, and zero protected metadata/count/cursor/result leakage. Retain: redacted peer-ACL transcript, policy decision log, and readiness report. |
| HSP-10 | Workpad remains the human-readable proposal/review surface; `plus`/`amplify` is only an immutable preference/ranking annotation; Ali makes the exact decision; `decisions.jsonl` is audit only; the native owner gate alone applies; receipt and outcome remain distinct. | Fixture: immutable records/proposal, plus annotation, exact Ali approve and decline decisions, tampered decision-log copy. Test/command: approval-binding integration test. Assert: annotation cannot fan out/approve/apply/publish/contact/execute/queue, decisions log cannot gate, exact hashes are validated by the native gate, and receipt differs from outcome. Retain: proposal, decision, gate receipt, outcome, and audit JSONL. |
| HSP-11 | Observability exposes provider errors, spend, freshness, capture completeness, dedupe rate, consumer lag, unprocessed demand, and journal/index/recovery health without protected data. | Fixture: successful, failed, partial, stale, duplicate, lagging, and unprocessed jobs. Test/command: telemetry contract test. Assert: each signal is present, numerically consistent with the fixture, access-filtered, and free of credentials/PHI/snippets. Retain: redacted metrics snapshot and consistency report. |
| HSP-12 | Failure/recovery acceptance covers concurrent same-content captures, crash after fetch/before commit, 429s, timeouts, truncated bytes, transcript failures, outage abstention, cursor replay, ACL non-leakage, backup restore, exact-hash approval binding, 0/1/16 MiB source limits, base64 wire overhead, digest mismatch, held-FD nofollow regular-file TOCTOU checks, the Slice 3C1 local clear-manifest PHI gate and pre-acceptance refusal, unsupported-media/encoding invalidation before scanner evaluation, future-slice bounded non-PHI quarantine, and ambiguous record/event/lineage recovery. | Fixture: the complete fault matrix and portable backup. Test/command: `PYTHONDONTWRITEBYTECODE=1 uv run pytest -p no:cacheprovider` plus recovery/fault integration suite. Assert: no loss, no unauthorized disclosure, no `SOURCE` path/base64/kind persistence, no downstream duplicate effect, preserved IDs/lineage after restore, supported-but-unattested source is `400`/`source_refused`, scanner/manifest error is `503`, no raw bytes on 3C1 refusal, and approval rejection on any hash drift. Retain: full pytest log, fault matrix, restored-store verification, and approval failure report. |
| HSP-13 | The complete audited migration inventory is present with each lane’s explicit owner and cadence-authority/category: Pulse: `gc-web` / `givecare/pulse-daily`, daily. Benefits radar: `gc-benefits` / `givecare/discovery-benefits`, daily. Benefits legacy: `gc-benefits` / `givecare/discovery-benefits`, on-demand/manual. Wiki refresh: `gc-wiki` / `givecare/refresh-wiki`, weekly. Intel refresh: `gc-intel` / `givecare/intel-refresh`, daily. Civic policy radar: `scty-civic` / `givecare/refresh-policy`, weekly. Weekly radar curation: `GiveCare root` / `givecare/radar-curation`, weekly. Gmail/newsletters/attachments: mailbox/router owner, event-driven. Manual web, X, YouTube/transcription: research operator, on-demand. Atelier entity discovery: Atelier, event-driven. Helm external ingestion: Helm, event-driven/mixed. Signal daily: `GiveCare root` / `givecare/signal-daily`, daily. Exact timer values remain canonical only in each lane automation contract, not this inventory or Hound. `gc-gtm`/CRM remains a consumer only. | Fixture: checked-in inventory manifest mirroring the table and lane automation contracts. Test/command: inventory completeness checker. Assert: every required lane has one explicit owner, one cadence category, one consumer/boundary, and one migration stage; timer truth is absent from Hound; `gc-gtm`/CRM is consumer-only; and the explicit out-of-scope list is absent from the inventory. Retain: inventory report, owner attestations, and timer-authority references. |
| HSP-14 | Existing repo-local records are imported/mirrored through `import.record` without rewriting caller-supplied IDs or exact bytes; authorized lineage and hashes survive, absent lineage uses the explicit no-lineage value, ambiguous lineage fails closed, and the separate import-outcome record/event preserves operation metadata; SQLite is disposable and rebuilds from journal/records; portability has no absolute-path dependency. | Fixture: legacy records with nontrivial bytes, IDs, lineage, a matching clear-manifest entry, and a copied store on a second path. Test/command: create-only `import.record`, delete-index, rebuild-index, and portable restore test. Assert: byte-for-byte/hash-for-hash identity, unchanged IDs/lineage where present, exact raw-object ID preservation, ID/byte conflicts reject without overwrite, ambiguous lineage rejects before acceptance, rebuilt projection equality, and successful verification at the second path. Retain: before/after manifests, restore log, and projection diff. |
| HSP-15 | Migration follows the exact staged order: freeze contracts; import/mirror; shadow Pulse and Benefits; cut over Pulse then Benefits; wiki/intel/Civic; radar/Gmail/manual web/X/YouTube; Atelier and Helm external reads; enable no-bypass; delete only after recovery drill and one full scheduled cycle per lane. | Fixture: stage ledger with one lane per gate and scheduled-cycle evidence. Test/command: migration-order checker. Assert: no stage can be skipped/reordered, no deletion occurs before both gates, and Signal daily uses the scheduled-cycle gate. Retain: signed stage ledger, recovery-drill report, and per-lane cycle receipts. |
| HSP-16 | Pulse shadow parity requires the same query set/windows/caps, explained eligible lead differences, same capture lineage/evidence bundle, freshness/lane/quality gates, no-edition/recovery behavior, downstream input hash or adjudicated semantic equivalence, no publish during shadow, and cutover with provider credentials absent from Pulse. | Fixture: frozen Pulse shadow window with identical queries, caps, provider response variants, recovery, and publish sink. Test/command: Pulse parity comparator. Assert: every parity clause, explicit differences, equal/equivalent downstream input, zero publish, and credential-free cutover. Retain: parity report, evidence-bundle hashes, and no-publish audit. |
| HSP-17 | Benefits shadow parity requires the same 8 rotating queries/as-of/budgets, known URL/title suppression/cap, candidate IDs/targets/classifications, finalizer and human proposal/apply boundary, explicit zero-leads degraded result, and cutover with provider credentials absent from Benefits. | Fixture: eight-query Benefits shadow window with duplicates, zero-lead, finalizer, proposal, and apply cases. Test/command: Benefits parity comparator and credential-unset cutover test. Assert: all query/budget/suppression/candidate/classification/degraded/approval clauses and no direct provider access. Retain: parity report, candidate manifest, degraded-result record, and approval-bound proposal. |
| HSP-18 | No-bypass enforcement statically rejects provider credentials/endpoints/direct clients/prompt direct skills/artifacts without Hound IDs outside the explicit adapter allowlist, with exclusions only for tests/history/local retrieval/health/deploy/publish; dynamic tests run every migrated consumer with credentials unset. | Fixture: positive forbidden-pattern corpus, allowed `houndd` adapter corpus, and every migrated consumer. Test/command: static scan plus credential-unset matrix. Assert: forbidden consumers fail the scan, allowlisted adapters pass, exclusions are limited to the stated set, and every consumer either uses the socket or fails closed. Retain: scan findings, exclusion manifest, and consumer matrix. |
| HSP-19 | Domain ownership remains outside Hound: no domain logic, scheduler, approval DB, queue, CRM, wiki, Helm, Pulse curation, Benefits registry, social publishing, CRM write, or internal BB/Git/Discord/calendar event ownership is added. | Fixture: ownership map and forbidden-module/config corpus. Test/command: ownership static checker and service capability inspection. Assert: Hound exposes only evidence mechanics and the listed service contract; all domain actions remain caller/native-owner operations. Retain: ownership report and capability dump. |
| HSP-20 | Journal, records, projections, access policies, cursor recovery, service generation, and persistent service identity are independently verifiable after crash, index rebuild, backup restore, and local migration; SQLite never becomes a source of truth. Mandatory startup recovery and verification complete before identity load or listening, and request-time reads never repair or rebuild SQLite. Persistent-identity crash assertions are evaluated only after that recovery. Identity publication is certified only on a local Linux filesystem with owner-only directories and cooperative same-UID processes. New identity bytes must originate in a validated, fsynced `O_TMPFILE` opened without `O_EXCL`. Publication uses exact-held-FD linking only: either `linkat(source_fd, "", service_fd, destination, AT_EMPTY_PATH)` or a held `/proc/self/fd` directory plus `linkat(proc_self_fd_dir, "<fd>", service_fd, destination, AT_SYMLINK_FOLLOW)`. The procfs fallback is permitted only while the private source FD is held by its owning process, its numeric proc entry resolves to the expected inode, and store paths remain no-follow; procfs magic-link following is the sole exception. The linked destination must satisfy exact inode/content/mode/link-count postconditions. If direct linking is unavailable, procfs is required. Hard links, `renameat2(RENAME_EXCHANGE)`, `renameat2(RENAME_NOREPLACE)`, and directory `fsync` are publication primitives required when publication or recovery exercises them; they are not preflighted for a clean read-only identity load. Lifetime `flock` is required. Missing required primitives fail unavailable; uncertified remote/NFS filesystems are outside the claim. No named-temp fallback is allowed; only `identity.json` is canonical. Temporary old/new witnesses may exist during recovery, and only clean/quiescent copy relocation is supported. Lasting observable namespace replacements are preserved in evidence and rejected as canonical. Cooperative same UID excludes fully restored swaps, in-place forgery, and the final validation-to-unlink race; hostile same UID requires a distinct UID and no quarantine auto-unlink. | Fixture: store with interleaved records, tombstones, failures, stale projection, real subprocess crash matrix, required-primitive failures, clean and in-flight relocation copies, and quarantine inventory. Test/command: `journal verify`, `journal rebuild-index`, restore/replay test, and a real-subprocess identity publication/recovery matrix. Assert: sequence, IDs, hashes, lineage, access decisions, and authorized cursor results match canonical journal truth after each rebuild; recovery/verification precede identity loading and listening; request-time reads never repair/rebuild; clean identity state relocates; in-flight copies, missing required primitives, and lasting observable namespace replacements fail closed without adopting or deleting unverified bytes; excluded same-UID races are documented rather than claimed detected. Retain: verification reports, replay manifest, restored projection checksum, crash matrix, identity-state manifest, and preserved-quarantine inventory. |
| HSP-21 | Completion is machine-verifiable: every implementation artifact/test traces to exactly one acceptance row, all rows have named executable evidence with expected assertions and retained artifacts, and the full acceptance command fails on any missing, duplicated, unordered, or unretained result. | Fixture: acceptance manifest containing every row, fixture, test, command, assertion, and artifact path. Test/command: acceptance-manifest checker followed by the full CI test command. Assert: one-to-one traceability, exactly 22 ordered IDs, all evidence artifacts exist and are retained, and no unlisted artifact is used as proof. Retain: machine-readable acceptance manifest and CI summary. |
| HSP-22 | No migration lane becomes canonical until Ali has explicitly approved the exact immutable cutover proposal; a decline blocks cutover, and the native owner gate validates the exact records/proposal/decision hashes before applying. | Fixture: Pulse and Benefits cutover proposals with exact hashes plus Ali approve/decline decisions and a changed-hash case. Test/command: cutover gate integration test. Assert: only the exact Ali approval permits cutover, decline/changed hashes block it, `decisions.jsonl` alone cannot permit it, and the applied outcome references the validated receipt. Retain: Ali decision, gate validation receipt, proposal hash manifest, and cutover outcome. |
