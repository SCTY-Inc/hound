"""HSP-11: policy-filtered operational telemetry derived from truth the daemon already holds.

Every signal here is computed fresh from the journal's own verified events,
the disposable projection, and a plain integrity verdict -- never from a
second bookkeeping store. Nothing in this module is persisted between calls,
so it needs no liveness bound of its own. A snapshot carries counts, sums,
rates, and one timestamp; it never carries a URL, a snippet, a credential, or
any other record content, matching the same header-only shape
``authorize_event_header`` already authorizes for journal reads.

The six HSP-05 outcomes partition into exactly three of the signals below
(provider errors, capture completeness, unprocessed demand), so every
authorized event is counted in its outcome tally and in exactly one of those
three buckets.

Consumer lag has no server-held subscriber state to read (HSP-08: Hound
retains no saved query, delivery, acknowledgement, or subscriber state), so
this module reports the one lag every daemon-internal consumer of the
journal already has: the disposable projection itself, which a live commit
now keeps current (B11) but which drifts after any path that does not run
through it (B9). ``consumer_lag`` is therefore the count of the caller's own
authorized entries the index has not yet absorbed, computed the same way
B9/B11 already reason about index staleness -- not a claim about any
external, unmodeled consumer.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .access import PrincipalScope, authorize_event_header
from . import HounddStore
from .verify import verify_store

TELEMETRY_REPORT_SCHEMA = "houndd.telemetry-snapshot.v1"

# The complete HSP-05 durable outcome vocabulary, always reported even at zero
# so a caller never has to guess whether an absent key means zero or unknown.
_OUTCOMES: tuple[str, ...] = ("completed", "partial", "failed", "degraded", "refused", "interrupted")
_PROVIDER_ERROR_OUTCOMES = frozenset({"failed", "refused"})
_UNPROCESSED_OUTCOMES = frozenset({"partial", "degraded", "interrupted"})


class TelemetryError(ValueError):
    """A telemetry read payload does not satisfy its exact contract."""


def parse_telemetry_request(payload: Any) -> None:
    """A telemetry payload is exactly the empty object, like the maintenance reads."""

    if type(payload) is not dict or payload:
        raise TelemetryError("telemetry read payload has missing or unknown fields")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _rate(count: int, total: int) -> float:
    return count / total if total else 0.0


def _adapted_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """Shape one disposable-index row into the header ``authorize_event_header`` reads.

    The projection stores the same producer identity flat (``owner_id``,
    ``capability``, ``run_id``) instead of nested; this is the only
    difference from a journal event header.
    """

    return {
        "access": row["access"],
        "policy_id": row["policy_id"],
        "producer": {"owner_id": row["owner_id"], "capability": row["capability"], "run_id": row["run_id"]},
    }


def compute_snapshot(
    store: HounddStore,
    scope: PrincipalScope,
    *,
    state_root: str | Path,
    events: tuple[Mapping[str, Any], ...],
) -> dict[str, Any]:
    """Compute one telemetry snapshot over exactly the caller's authorized events.

    ``events`` is the same freshly verified journal snapshot the journal
    read routes already build (``reads.verified_events``); this function
    never re-reads the journal itself, so it is exactly as fresh and exactly
    as expensive as one journal read.
    """

    authorized = tuple(event for event in events if authorize_event_header(scope, event))
    total = len(authorized)

    outcome_counts: dict[str, int] = {outcome: 0 for outcome in _OUTCOMES}
    dedupe_counts: dict[str, int] = {}
    cost: int | float = 0
    requests: int | float = 0
    byte_count: int | float = 0
    freshest: str | None = None
    for event in authorized:
        outcome = event["classification"]["outcome"]
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        digest = event["dedupe"]["content_sha256"]
        dedupe_counts[digest] = dedupe_counts.get(digest, 0) + 1
        usage = event.get("usage") or {}
        cost += usage.get("cost", 0) or 0
        requests += usage.get("requests", 0) or 0
        byte_count += usage.get("bytes", 0) or 0
        appended_at = event["appended_at"]
        if freshest is None or appended_at > freshest:
            freshest = appended_at

    provider_errors = sum(outcome_counts[outcome] for outcome in _PROVIDER_ERROR_OUTCOMES)
    unprocessed = sum(outcome_counts[outcome] for outcome in _UNPROCESSED_OUTCOMES)
    completed = outcome_counts["completed"]
    duplicate_events = sum(count - 1 for count in dedupe_counts.values() if count > 1)

    authorized_entry_ids = {event["entry_id"] for event in authorized}
    indexed_entry_ids = {row["entry_id"] for row in store.projection.rows() if authorize_event_header(scope, _adapted_row(row))}
    lag = len(authorized_entry_ids - indexed_entry_ids)

    journal_valid = verify_store(state_root, projection=False)["valid"] is True

    return {
        "schema_version": TELEMETRY_REPORT_SCHEMA,
        "generated_at": _now(),
        "total_events": total,
        "outcomes": outcome_counts,
        "provider_errors": {"count": provider_errors, "rate": _rate(provider_errors, total)},
        "capture_completeness": {"count": completed, "rate": _rate(completed, total)},
        "unprocessed_demand": {"count": unprocessed, "rate": _rate(unprocessed, total)},
        "dedupe": {"duplicate_events": duplicate_events, "distinct_content": len(dedupe_counts), "rate": _rate(duplicate_events, total)},
        "spend": {"cost": cost, "requests": requests, "bytes": byte_count},
        "freshness": {"freshest_capture_at": freshest},
        "consumer_lag": {"unindexed_events": lag, "index_current": lag == 0},
        "recovery": {"journal_valid": journal_valid},
    }


__all__ = [
    "TELEMETRY_REPORT_SCHEMA",
    "TelemetryError",
    "compute_snapshot",
    "parse_telemetry_request",
]
