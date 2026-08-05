# pulse: credential-unset evidence
Re-proven fresh for the E1 consolidation at
repos/hound/migration/evidence/e1/no-bypass-matrix.json, lane row pulse
(owner gc-web): `hound-research ingest search --owner-id gc-web --policy-id
atum-owner --query "caregiver respite programs"` run 2026-08-04T15:20Z against
an ephemeral keyless houndd returned ok=false outcome=degraded exit=4 in 0.28s
and still journaled the attempt. The matrix classifies this as
degraded (adapter_absent) — fails closed, no hang, no direct network reach.
The raw daemon response is retained at
repos/hound/migration/evidence/e1/raw/gc-web-search.json
(request_id e1-search-gc-web, usage requests=0 bytes=0 cost=0).

The matrix records that the keyless property is process-wide, not per-request:
houndd.adapter_host.AdapterHost.from_env snapshots ADAPTER_ENV_KEYS once at
process start, so ingest.search/ingest.url had no registered adapter for the
daemon's whole lifetime. The matrix also notes this is an owner-level proof —
gc-web is the shared owner of both pulse and civic-policy-radar, and one run
covers both lanes' acquisition path.
