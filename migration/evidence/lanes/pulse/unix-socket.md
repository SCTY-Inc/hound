# pulse: unix-socket evidence
Acquisition executes over the houndd Unix socket. The lane driver
repos/givecare/gc-web/scripts/pulse-lane.sh binds
hound_socket="${PULSE_HOUND_SOCKET:-/run/user/1000/hound/houndd.sock}" (line 43)
and drives every acquisition through hound-research at
/home/deploy/.local/bin/hound-research (lines 36, 489, 521); when the socket is
absent the lane logs reason=houndd-socket-absent and stops (line 460) rather
than falling back to a provider. The E1 matrix
(repos/hound/migration/evidence/e1/no-bypass-matrix.json, lane row pulse)
records the cutover commit as gc-web
6fb4ac98645664568c2f1138d3900c0d5d8abfba, "feat(pulse): acquire only through
houndd, delete the direct-provider path" (2026-08-04T04:13:31Z, verified),
with follow-up fixes 1475e6d/dbfb1f0 and both shadow timers deleted
(GOALIE.md row M2).

Live production writes through the socket: the discovery journal at
~/.local/state/hound/discovery/journal/events.jsonl carries 28 entries with
producer.owner_id=gc-web and producer.run_id=pulse-2026-08-04, all
policy_id=atum-owner, appended 2026-08-04T11:04:17Z–11:05:50Z (inspected
2026-08-05).
