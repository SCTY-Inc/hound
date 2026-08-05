# pulse: full cycle evidence
Ali decided the semantics on 2026-08-05 (GOALIE.md decision row D11): at the
migrated gate, `full_cycle` means "one real end-to-end run" — the Phase M
replan's own wording — not necessarily a bb-scheduled cycle. benefits-radar's
scheduled-cycle evidence remains valid as a superset. That decision names this
lane's qualifying run explicitly: "Pulse qualifies on run pulse-2026-08-04."

The run, verified 2026-08-05 in the production discovery journal
(~/.local/state/hound/discovery/journal/events.jsonl, producer.run_id=
pulse-2026-08-04, producer.owner_id=gc-web): 28 journal entries — 8
ingest.search and 20 ingest.url — every one classification.outcome=completed
with evidence_status=clear, i.e. zero failures, all under policy_id=atum-owner
and access=public, appended 2026-08-04T11:04:17Z–11:05:50Z. Providers recorded
on the source rows are exa (the 8 searches) and firecrawl (the 20 captures),
both reached through houndd rather than by the lane; the lane itself holds no
such credential (see credential-unset.md and static-no-direct-provider.md in
this directory).

GOALIE.md row M2 records the same cycle from the lane side — "full evidence
stage through the production daemon — 8 searches, 128 leads, 20 captures, 0
failures, 19 retained" — where the 128 leads and 19 retained are lane-side
curation counts held by gc-web, not journal rows; the journal is authoritative
only for the 8 searches, 20 captures, and 0 failures reproduced above. M2 also
records the defects found and fixed during this live proof: bb held-answer
object-vs-string normalization at lane intake, hound_research 5s exchange
timeouts raised to 180s commit / 60s read, and non-deterministic acquisition
run IDs replaced by the deterministic pulse-<date> v3 key namespace that gives
this run its ID.
