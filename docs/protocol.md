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

Optional fields are `run_root`, `capture_root`, `write_scopes`,
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
and `failed`. A plan response places its owner-specific deterministic proposal in
`data`; `expected_writes` is the one standardized planning field.

## Plan and approval

`hound.plan.v1` binds:

- Hound kernel version and source hash;
- driver ID and canonical manifest hash;
- a combined digest of the fixed system path and allowlisted environment state;
- operation, effect, gate, and explicit `as_of`;
- input value and hash;
- Git HEAD plus tracked working bytes/modes, staged and unstaged diffs, and
  nonignored untracked-file hashes;
- write scopes and their hash;
- expected writes and the driver-owned plan.
- the complete standardized planning response, including diagnostics, proofs,
  and artifacts visible to the reviewer.

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
index. Existing run directories are never reused. `hound run verify` rejects
missing or unexpected files and recomputes the index hashes and cross-document
bindings.

The approval is self-hashed; the index binds the plan ID and hashes every run
record. These are local witnesses rather than signatures. Verification
establishes strict internal consistency; authenticity requires an external
digest anchor controlled outside the owner filesystem.

## Evidence and providers

- `hound.lead.v1` is explicitly `not-evidence`.
- `hound.capture.v1` addresses raw bytes by SHA-256, binds retrieval provenance in
  a distinct capture ID, and uses create-only blobs and manifests.
- `hound.provider.request.v1` supports the built-in `web` pack (Exa and
  Firecrawl) and `scholarly` pack (arXiv Atom API). Every operation, nested Exa
  content object, and arXiv query field uses a positive field allowlist.
- Public URLs use one strict parser boundary: browser-divergent backslashes,
  control/space characters, malformed host labels, private hosts, embedded
  credentials, and ambiguous semicolon parameters are rejected.
- Firecrawl requests are restricted to passive search/scrape fields; browser
  actions, custom headers, proxy overrides, and disabled TLS are excluded.
- `hound.provider.response.v1` includes the source-pack ID, canonical request
  hash, raw provider data, and normalized leads for searches, but never the
  provider credential.

### Standard source composition

An owner opts into kernel composition by declaring all three source
capabilities with `"composition":"hound.source.v1"`. Partial opt-in is invalid.
For an opted-in driver, `hound source discover|capture|inspect` are
kernel-composed read operations, not plain driver pass-throughs:

- The owner `source.discover` adapter returns
  `hound.source.discovery-spec.v1`: validated provider search requests plus
  positive `max_requests`, `max_leads`, and `max_bytes` limits. Hound executes
  them and returns `hound.source.discovery.v1` with the successful request/
  response pairs, deduplicated leads, measured usage, and provider diagnostics.
- The caller passes that discovery inside `hound.source.capture.input.v1`. The
  owner `source.capture` adapter returns `hound.source.capture-spec.v1` with a
  `captures` array of unique `{url, mode}` objects. `mode` is `provider-result`
  for a native API document or `origin` for a selected web page. Origin capture
  attempts direct HTTP plus Scrapling extraction first and passive Firecrawl
  scraping second. Hound stores the exact fetched bytes under `capture_root` and
  binds the extracted inline document hash, method, and attempts in manifest
  metadata. Failed origins remain diagnostics and do not fall back to discovery
  excerpts. An empty successful discovery remains an empty capture set so the
  owner can reach its ordinary no-result outcome instead of failing the protocol.
- The owner-specific inspect input must contain that capture set. Before calling
  `source.inspect`, Hound recomputes each inline document hash against manifest
  metadata, then verifies the create-only raw blob and manifest in `capture_root`.

The owner adapters remain mutation-checked read capabilities and never receive
provider credentials. The kernel-owned capture-store write is the deliberate
exception to read-mode owner immutability. Partial provider failure preserves
only matching successful request/response pairs; all-request failure and every
budget or capture-integrity violation fail closed.

Without the composition marker, source capabilities keep their existing
owner-defined pass-through behavior.
