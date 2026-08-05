# pulse: recovery-drill evidence
The consolidated E5 fault matrix (repos/hound/tests/test_e5_fault_matrix.py,
inventory at repos/hound/tests/evidence/e5/matrix-inventory.json,
schema hound.e5.matrix-inventory.v1, status
matrix_complete_with_one_known_defect) covers all 19 HSP-12 demand rows,
including the ones the two operations this lane uses (ingest.search and
ingest.url) depend on: concurrent same-content captures, crash after
fetch/before commit, 429s, timeouts, truncated bytes, outage abstention,
cursor replay, digest mismatch, backup restore, and ambiguous
record/event/lineage recovery.

Scope note on the one known defect: the matrix pins e5-defect-1
(src/houndd/projection.py::_derive_rows crashes on projection rebuild after a
completed transcription) as a strict xfail. It does not reach this lane —
pulse acquires only through ingest.search and ingest.url, confirmed by the 28
journal entries for run pulse-2026-08-04 (20 ingest.url + 8 ingest.search, no
transcribe), and pulse's audio path is Deepgram text-to-speech in
repos/givecare/gc-web/packages/pulse-pipeline/pipeline/run-audio.ts, not
houndd transcription, so no transcript: object_key is ever produced under this
owner. The E1 matrix independently proves the lane fails closed rather than
hanging when the daemon has no adapter
(repos/hound/migration/evidence/e1/no-bypass-matrix.json, lane row pulse;
ok=false outcome=degraded exit=4 in 0.28s).
