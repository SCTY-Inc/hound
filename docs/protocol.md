# Hound protocol v1

Diátaxis: reference

Hound uses strict JSON objects. Unknown fields at the driver manifest and driver
response boundaries are rejected. JSON is canonicalized with sorted keys,
compact separators, UTF-8, finite numbers, and SHA-256 hashes.

## Driver manifest

`hound.driver.v1` requires:

- `id`: stable driver identifier.
- `protocol`: exactly `hound.protocol.v1`.
- `owner.repo`: repository locator relative to the manifest directory; it may
  traverse upward but must resolve to the exact owner Git root at runtime.
- `exec`: non-empty literal argv list.
- `capabilities`: operation keys mapped to `effect: read|write` and
  `gate: none|human`; each capability may add an `env_allowlist`.

Optional fields are `run_root`, `source`, `write_scopes`,
`ignored_snapshot_excludes`, `timeouts_seconds`, and `env_allowlist`. The top-
level environment allowlist is global; a driver operation receives its union
with that capability's allowlist. Driver processes receive a fixed system
`PATH`; `PATH` cannot be allowlisted. The owner Git repository is the read trust
boundary. Hound does not accept narrower read scopes because it cannot enforce
them as a filesystem boundary.

Hound normally mutation-snapshots tracked, untracked, and ignored owner files.
`ignored_snapshot_excludes` removes explicit relative prefixes only from the
ignored-file portion of that snapshot. Tracked files below an excluded prefix
remain included. Excluded ignored content is outside Hound's mutation monitor;
manifests must restrict this to disposable dependencies and caches, never
canonical state, outputs, captures, or run records.

## Driver request

The core sends `hound.driver.request.v1` with a mode:

- `check`: protocol handshake.
- `read`: direct read-capability invocation.
- `plan`: deterministic write proposal.
- `execute`: the exact accepted driver plan and its plan ID.

Operation requests may include `operation`, `as_of`, and `input`. Execute also
includes `plan_id` and `driver_plan`.

## Driver response

```json
{
  "schema_version": "hound.driver.response.v1",
  "ok": true,
  "outcome": "completed",
  "data_schema": "owner.result.v1",
  "data": {},
  "artifacts": [],
  "proofs": [],
  "diagnostics": []
}
```

Allowed outcomes are `planned`, `completed`, `no-change`, `no-edition`, `held`,
and `failed`; `ok` must agree with the outcome. A plan response places its
owner-specific deterministic proposal in `data`; `expected_writes` is the one
standardized planning field.

## Plan and approval

`hound.plan.v2` binds:

- Hound kernel version and source hash;
- driver ID and canonical manifest hash;
- a combined digest of the fixed system path and allowlisted environment state;
- operation, effect, gate, and explicit `as_of`;
- input value and hash;
- Git HEAD plus tracked working bytes/modes, staged and unstaged diffs, and
  nonignored untracked-file hashes;
- write scopes and their hash; and
- one complete authoritative proposal response, including expected writes,
  diagnostics, proofs, and artifacts visible to the reviewer.

Allowlisted values are not stored in cleartext. Because a digest of a low-
entropy value can be guessed offline, avoid allowlisting incidental flags; the
allowlist is for credentials and configuration whose exact state must be bound
to approval.

The `plan_id` is the canonical hash of the remaining plan. Before execution,
Hound verifies repository state and reruns planning; the new plan must be byte-for-
byte equivalent.

`hound.approval.v1` binds the reviewer and approval time to the plan ID, driver,
operation, and write-scope hash. An optional timezone-aware `expires_at` is
enforced. Approval artifacts are local workflow witnesses, not digital signatures.

## Run record

Each execution creates one directory named by its plan ID. It contains the
driver manifest, plan, request, optional approval, result, and a strict hash
index. Existing run directories are never reused. New `hound.run.result.v2`
files do not contain their filesystem location, so a copied record remains
verifiable. `hound verify` rejects missing or unexpected files and recomputes
the index hashes and cross-document bindings.

The approval is self-hashed; the index binds the plan ID and hashes every run
record. These are local witnesses rather than signatures. Verification
establishes strict internal consistency; authenticity requires an external
digest anchor controlled outside the owner filesystem.

## Evidence, adapters, and source composition

`hound.lead.v1` is always `not-evidence`. `hound.capture.v1` addresses raw
bytes by SHA-256, binds retrieval provenance in a distinct capture ID, and uses
create-only blobs and manifests.

Hound has no provider request protocol or provider registry. Every network
implementation is an explicit adapter manifest using the web adapter protocol
below.

An owner opts into source composition with one top-level object:

```json
{
  "source": {
    "schema_version": "hound.source.v2",
    "adapters": {
      "search": "adapters/search.json",
      "extract": "adapters/extract.json"
    }
  }
}
```

The owner must declare all three source operations as reads:

- `source.discover` returns bounded `{adapter,input}` searches. Hound runs them
  sequentially and returns immutable search-record/lead references without
  deduplicating same-URL results from different records.
- `source.capture` selects exact `{search_record_id,lead_id,adapter}` references.
  Hound verifies each parent and invokes one explicit extract adapter. There is
  no origin, provider, or browser fallback.
- `source.inspect` verifies every referenced search and extract record, rebuilds
  the evidence bundle from those immutable files, and only then invokes owner
  interpretation.

Owners that need authoritative origin bytes use the separate create-only
capture primitive or a typed direct-source adapter. Search output never becomes
evidence by itself.

## Web adapter protocol

Hound exposes three web operations: `web.search`, `web.extract`, and
`web.interact`. An adapter is an ordinary reviewed `hound.driver.v1` executable
that declares one of those read capabilities. The existing driver subprocess,
environment allowlist, timeout, output bound, mutation check, and process cleanup
are the adapter boundary; there is no second plugin runtime.

The corresponding agent-facing commands are `hound search`, `hound extract`, and
`hound interact`. Provider implementations live in the separate
`hound_web_adapters` package namespace, so changing one does not alter guarded-
write kernel identity. Each command accepts an explicit adapter manifest and
invokes only its matching capability. Hound never selects or escalates adapters
implicitly.

A successful adapter response uses `data_schema: "hound.web.adapter.v1"` and:

```json
{
  "schema_version": "hound.web.adapter.v1",
  "retrieved_at": "2026-07-21T12:00:00Z",
  "raw": {
    "media_type": "application/json",
    "body_base64": "e30=",
    "sha256": "..."
  },
  "output": {},
  "usage": {"requests": 1, "bytes": 2}
}
```

The raw body is the exact provider response or a canonical envelope containing
all exact responses for a multi-request operation. Hound decodes it, recomputes
its digest and byte count, and stores it unchanged. Adapter credentials must not
appear in any response or diagnostic.

`output` is operation-specific:

- Adapters return `hound.web.search.v1` with bounded `hound.lead.v1` objects.
  Hound's immutable `hound.web.search.v2` record assigns each accepted lead a
  content-bound `hound.lead.v2` ID. Both declare `trust: "untrusted"` and
  `evidence_status: "not-evidence"`; query and engine attribution remain
  attached. Search input may include a bounded adapter-owned `options` object. SearXNG accepts either
  explicit engines or categories, plus language, day/month/year range,
  safe-search level, and `max_pages` from 1 through 5. Engine bangs, language
  prefixes, and timeout controls are rejected in query text so routing remains
  explicit. Its output preserves configuration hash, completed pages,
  suggestions, corrections, and unresponsive-engine diagnostics.
- `hound.web.extract.v1` contains known-URL documents with markdown, markdown
  digest, public links, metadata, and `evidence_class: "provider-derived"`.
  Input lineage is mandatory: either an explicit direct root or an exact search
  record and lead ID whose URL Hound verifies. One URL is normal. A bounded set
  is valid only when the input declares `max_pages`; Hound's ceiling is 20.
- `hound.web.interact.v1` contains one explicit browser action and its resulting
  session/tab references or bounded snapshot. It declares
  `evidence_class: "provider-derived"`. The initial protocol permits only
  anonymous `open`, `snapshot`, `click`, `type`, `scroll`, and `close`; typing
  cannot submit a form.

Search has a ceiling of 50 leads. Provider request count, response bytes,
extraction page count, and browser action/time budgets are validated rather than
trusted from prose. Public target URLs use one strict parser boundary:
browser-divergent backslashes, control/space characters, malformed or private
hosts, embedded credentials, and ambiguous secret parameters are rejected.
Operator-configured adapter service endpoints are outside owner-driver input and
may resolve to loopback.

## Web provenance records

Every attempt, including a failed adapter invocation, creates one immutable
content-addressed run directory. The runtime freezes the manifest once and
returns a kernel-owned invocation receipt binding that exact manifest,
repository fingerprint, allowlisted-environment digest, kernel identity,
response hashes, and cleanup proof. The web record stores that receipt directly;
it never reconstructs adapter state in a second pass.

The record contains the adapter manifest, adapter Git identity, canonical
request, exact adapter response or local failure, raw bytes, normalized output,
kernel identity, record descriptor, and strict hash index.
The record ID binds all of those identities and hashes. The command response
returns `output_path` plus a bounded context view: long markdown and snapshots
are truncated to 12,000 characters, links to 100 entries, and screenshot bytes
are omitted. The complete validated output remains in the immutable
`output.json` record and can be read explicitly.

`hound verify` recognizes web records and checks their file set, hashes,
record ID, raw-body digest, output digest, adapter-manifest binding, request and
operation agreement, derivation metadata, and directory name. Search records are
never evidence. Firecrawl markdown and Camofox observations remain explicitly
provider-derived unless a separate origin capture retained origin bytes.

Web output is always labeled untrusted. This label is an observable contract,
not a claim that Hound can control how another model harness assembles its
prompt. The caller remains responsible for keeping web data outside instruction,
credential, and control channels.
