# Goal: hard-cut Hound to one honest execution and acquisition core

Status: **Implementation verified — production cutover blocked on SearXNG service and Firecrawl quota**

## Outcome

Hound has one invocation boundary, one adapter protocol, three explicit web
jobs, a thin source lifecycle made only from web-record references, portable
sealed records, and a capability-driven owner CLI. The legacy provider runtime,
provider packs, hidden source fallbacks, and duplicated owner-operation routing
are deleted in the same coordinated migration as all known owner call sites.

## Acceptance criteria

1. Decoded adapter payloads containing any credential-classified allowlisted
   value are rejected before any durable record is written; a deterministic regression
   test proves the prior base64 bypass.
2. Every successful web record binds the exact manifest, repository state, and
   environment digest returned by the invocation that produced its response;
   there is no pre-invocation `_adapter_state` decision site.
3. `search`, `extract`, and `interact` remain separate and never escalate
   implicitly. Extracted URLs bind either an exact search-record/lead parent or
   an explicit direct root.
4. Source discovery and capture use adapter manifests and immutable web-record
   references. Capture selects exact lead IDs, not URLs. Camofox is not a source
   fallback.
5. `providers.py`, provider packs, `hound provider run`, and
   `hound.provider.*` execution tests are deleted. Provider implementations do
   not contribute to guarded-write kernel identity.
6. New write records verify after being copied to a different directory. Frozen
   v1 verification behavior remains readable where fixtures require it.
7. Owner operations are invoked through `invoke`, `plan`, `execute`, `approve`,
   and `verify`; corpus and edition names are no longer duplicated in Hound's
   command registry. Source and the three web primitives remain explicit.
8. GC-web Pulse, GC-Intel, GC-wiki, GC-Benefits, and the shared Hound skill use
   the new commands/contracts. Unrelated dirty files remain untouched.
9. Hound and owner deterministic suites, formatting/lint, package build, clean
   install, installed-console smoke, and a faux-adapter end-to-end run pass
   without paid API calls.

## Core

- strict manifest/driver protocol;
- one executor plus invocation receipt and supervisor;
- `search`, `extract`, `interact`;
- thin `source discover|capture|inspect` composition over web records;
- guarded `plan → approve → execute → verify` writes;
- create-only captures and sealed records.

## Refusals

- No provider registry or provider-specific transport in core: explicit adapter
  manifests compose through the driver protocol.
- No hidden fallback or escalation: the owner selects each search/extract or
  interaction adapter.
- No scheduler, service manager, workflow DB, MCP surface, or claimed sandbox:
  use cron/systemd/tmux/files/OS isolation.
- No permanent compatibility aliases: this is a coordinated pre-1.0 hard cut.
- No mutable record database: files and content hashes remain the state.

## Tasks

| ID | Status | Contract | Proof |
|---|---|---|---|
| T1 | complete | Make runtime invocation receipts authoritative and close decoded credential leakage. | Red tests for base64 secret and state mismatch, then focused runtime/web tests. |
| T2 | complete | Add exact web lineage and source-v2 record composition; delete provider runtime/packs. Depends on T1. | Full faux discover → capture → inspect test, duplicate-URL parent test, no provider imports/files. |
| T3 | complete | Move adapter implementation package outside kernel identity; make write records portable and simplify verification. Depends on T1. | Kernel identity isolation and copied-record verification tests. |
| T4 | complete | Replace owner-domain CLI registry with capability-driven invoke/plan/execute/approve/verify while retaining source/web primitives. Depends on T2/T3 contracts. | CLI contract and installed-console tests. |
| T5 | complete | Atomically migrate known owner manifests, scripts, tests, docs, and shared skill without touching unrelated work. Depends on T2/T4. | Owner driver checks and deterministic owner suites. |
| V | complete | Run all acceptance gates and inspect the final diff for subtraction. Depends on T1–T5. | Criterion 9 plus file/LOC and decision-site audit. |

## Verification evidence

- Hound: **259 passed**; Black 25.1.0, Ruff 0.11.0, and `git diff
  --check` pass.
- The former 6,578-line kernel is 4,536 lines. Provider implementations are
  1,005 lines in a separate package namespace. Whole-product Python fell to
  5,541 lines: about 31% less kernel and 16% less total implementation.
- The 1,629-line provider/source-pack island, Scrapling and its seven transitive
  dependencies, provider CLI, and owner-domain CLI registry are gone.
- GC-web Pulse: **145 passed** plus TypeScript typecheck. GC-Intel: **17
  passed**. GC-wiki's full contract suite passed. GC-Benefits: **1,901 passed**.
- All four owner driver checks and representative read invocations passed.
- A pinned local SearXNG completed the real Pulse source-v2 discovery path:
  six search records, six `not-evidence` leads, zero diagnostics; every record
  verified. No Firecrawl credit was used.
- Wheel and source distribution built. A dependency-free clean environment
  installed both console scripts and completed faux search → exact lead →
  extract → inspect → record verification. The wheel contains no provider
  runtime or source packs.
- All temporary Hound containers were removed. Relevant owner files were
  migrated without reverting or staging unrelated dirty work.

Production cutover is intentionally not performed: the enabled Pulse timer
still needs a persistent pinned SearXNG endpoint, and Firecrawl previously
reported overdrawn credits. The migrated conductor points at this verified
worktree Hound, but it must not be shipped or allowed to reach its next scheduled
run until those external services are ready or the migration is held back.

## Deliberately retained defenses

- The repository fingerprint and mutation snapshot remain separate because they
  protect approval drift and per-invocation mutation at different moments.
- The web root lock remains until measured concurrency proves it is a bottleneck;
  it currently supplies simple cross-call throttling and atomic browser budgets.
- `raw.bin` and `output.json` remain directly visible even though the adapter
  envelope also contains them. Human inspectability wins over storage golf.
- `adapter_cli` remains as the shared extension-facing driver wrapper, but it and
  provider code are outside guarded-write kernel identity.

## Critical invariants to review by hand

- credential omission on rejected invocations;
- manifest/environment/repository identity receipt;
- search lead ID and extract-parent binding;
- plan/approval/replan equality and write-scope checks;
- record publication, symlink rejection, and portable verification.
