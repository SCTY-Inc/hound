# How to consume the houndd journal

<!-- Diátaxis: how-to -->

Read new `journal.query` entries from a running `houndd` once per invocation,
resume across restarts, and never lose or silently duplicate an entry's
effect. The reference implementation is `examples/consumer/consumer.py`; this
page is the operating discipline around it. Every lane migrating onto Hound
follows this pattern instead of re-deriving it.

## Prerequisites

- A running `houndd` and its `AF_UNIX` socket path.
- An `owner_id` / `policy_id` pair the daemon's policy authorizes for
  `journal.query` reads of the producer(s) you need.
- `examples/consumer/consumer.py` importable (it depends only on the standard
  library and `hound_client`).

## Choose a cursor state file location

One state file per lane, never shared. Use:

```text
<lane-state-dir>/<owner_id>-<policy_id>.consumer-state.json
```

The file holds exactly `{"cursor": "<opaque-string>"}` or `{"cursor": null}`.
Treat it as lane-private state, not a durable record: it is safe to delete
(the next run resnapshots from the start) but never safe to hand-edit its
`cursor` value, since the token is opaque and authenticated by houndd.

## Run one poll

```bash
uv run python examples/consumer/consumer.py \
  --socket /run/user/1000/hound/houndd.sock \
  --state-file /path/to/lane-state-dir/reader-policy-reader.consumer-state.json \
  --output /path/to/lane-state-dir/reader.jsonl \
  --owner-id reader \
  --policy-id policy-reader \
  --run-id "$(uuidgen)"
```

Each invocation fetches and applies exactly one page (`--limit`, default 50)
of new entries, then persists the resulting cursor. Schedule it externally
(cron, systemd timer, bb automation) at the interval your lane needs; `houndd`
has no built-in scheduler or push channel.

## Replay discipline: process, then persist

`run_once` applies every entry in the page to the lane's own idempotent
output *before* it writes the new cursor to the state file. This order is
deliberate:

- If the process crashes after applying entries but before the cursor write
  lands, the next run re-reads the same page using the *old* cursor. This is
  at-least-once delivery.
- If the lane's own apply step is idempotent (an upsert keyed by `entry_id`, a
  dedup ledger, whatever it already uses), a redelivered page has no
  duplicate effect. At-least-once delivery plus idempotent processing is
  exactly-once in outcome, without needing a distributed transaction between
  houndd and the lane's own state.

Never persist the cursor before processing succeeds — that direction loses
entries permanently on a crash instead of merely redelivering them.

## Restart behavior

houndd persists its service identity (and the cursor-signing keys derived
from it) to the same state root the journal lives in. A daemon restart over
that same state root does not by itself invalidate outstanding cursors: a
lane can stop, resume `houndd`, and continue polling with its last persisted
cursor exactly as before.

A cursor is bound to the high-watermark that existed when it (or its
cursorless parent query) was first issued. Paging through a bound cursor
never surfaces entries appended after that watermark, even after new pages
keep returning further results — that's expected, not a bug. When a page
comes back with no `cursor` field, the lane has drained everything visible at
that watermark. Persist `cursor: null` for that page (the reference consumer
does this automatically) so the *next* invocation issues a fresh cursorless
query and picks up a new watermark, including anything appended since. Because
this resnapshot revisits the filtered history from the start, expect it to
redeliver already-processed entries for a few subsequent pages until it
catches up again — idempotent processing is what makes that safe.

## Choosing an order (and switching safely)

`journal.query` accepts an optional `order`: `"ascending"` (the default,
oldest-first — what the reference consumer above always uses) or
`"descending"` (newest-first, added in hound B14 for lanes that only care
about recent activity, e.g. a review surface). Pass it through
`hound_client`'s `journal_query(..., order=...)`.

A cursor is bound to the order that minted it. houndd folds `order` into the
same `filter_hash` domain that already binds a cursor to its filter, so a
cursor minted under one order is rejected outright if replayed under the
other — the same `CursorRejectedError` the reference consumer already
handles by resnapshotting cursorless (see above). Legacy cursors minted
before `order` existed keep their original digest domain unchanged, so
nothing already deployed broke when B14 shipped.

**The consequence for a lane's own state file**: never just start passing a
different `order` to a lane that already has a persisted, non-null cursor.
Reset it first — delete the lane's `consumer-state.json` (or otherwise set
its `cursor` back to `null`) before the first query under the new order.
This is the same resnapshot path already used for an exhausted or rejected
cursor, and the same idempotent-processing guarantee is what makes the
resulting redelivery of already-seen entries safe rather than a source of
duplicate effects.

A consumer that never persists a cursor across invocations at all — for
example an on-demand, request-scoped read-through that always walks from a
fresh cursorless query — has nothing to reset and no cross-order hazard to
begin with; the caveat above only binds lanes that adopt the per-lane state
file in the first place.

## When the cursor is rejected

An unrecoverable cursor (malformed, or bound to an identity/key generation
that no longer exists) reads as one logical outcome: `400 invalid` on a
request that carried a cursor. There is no partial-resume path for a
rejected cursor. Resnapshot from the start: drop the cursor, issue a fresh
cursorless query, and let idempotent processing absorb whatever gets
redelivered. `consumer.query_journal` raises `CursorRejectedError` for this
case, and `run_once` already retries once, cursorless, before giving up.
