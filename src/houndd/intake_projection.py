"""Pure, allowlisted rendering of authorized journal query rows.

This module deliberately knows nothing about journals, records, SQLite, paths,
or cursor issuance.  It only maps already-authorized ``QueryItem`` values into
the small private intake-ledger display schema.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from .contracts import canonical_bytes
from .query_engine import QueryItem, QueryPage


class IntakeProjectionError(ValueError):
    """An authorized item cannot safely form a ledger display row."""


_ROW_FIELDS = frozenset(
    {
        "entry_id",
        "appended_at",
        "producer",
        "operation",
        "source",
        "classification",
        "artifact",
        "lineage",
        "access",
    }
)


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise IntakeProjectionError(f"{label} must be a non-empty built-in string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise IntakeProjectionError(f"{label} is not valid Unicode") from error
    return value


def _mapping(value: object, label: str, fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise IntakeProjectionError(f"{label} is not a canonical mapping")
    if any(type(key) is not str for key in value):
        raise IntakeProjectionError(f"{label} keys are invalid")
    return value


def _row(item: QueryItem) -> dict[str, Any]:
    if type(item) is not QueryItem:
        raise IntakeProjectionError("ledger projection requires exact query items")
    event = item.event
    if not isinstance(event, Mapping):  # defensively unreachable after QueryItem
        raise IntakeProjectionError("query item event is invalid")
    producer = _mapping(event.get("producer"), "producer", frozenset({"owner_id", "capability", "run_id"}))
    artifact = _mapping(event.get("artifact"), "artifact", frozenset({"kind", "schema", "record_id", "hash", "authorized_uri"}))
    source = _mapping(event.get("source"), "source", frozenset({"provider", "native_id", "canonical_url"}))
    classification = _mapping(event.get("classification"), "classification", frozenset({"outcome", "evidence_status"}))
    lineage = _mapping(event.get("lineage"), "lineage", frozenset({"relation", "record_id", "lead_id"}))
    return {
        "entry_id": _text(event.get("entry_id"), "entry_id"),
        "appended_at": _text(event.get("appended_at"), "appended_at"),
        "producer": {
            "owner_id": _text(producer["owner_id"], "producer.owner_id"),
            "capability": _text(producer["capability"], "producer.capability"),
            "run_id": _text(producer["run_id"], "producer.run_id"),
        },
        "operation": {
            "capability": _text(producer["capability"], "operation.capability"),
            "artifact_kind": _text(artifact["kind"], "operation.artifact_kind"),
        },
        "source": {"provider": _text(source["provider"], "source.provider")},
        "classification": {
            "outcome": _text(classification["outcome"], "classification.outcome"),
            "evidence_status": _text(classification["evidence_status"], "classification.evidence_status"),
        },
        "artifact": {"record_id": _text(artifact["record_id"], "artifact.record_id")},
        "lineage": {
            "relation": _text(lineage["relation"], "lineage.relation"),
            "record_id": _text(lineage["record_id"], "lineage.record_id"),
            "lead_id": _text(lineage["lead_id"], "lineage.lead_id"),
        },
        "access": _text(event.get("access"), "access"),
    }


def project_intake_ledger_page(page: QueryPage) -> tuple[dict[str, Any], ...]:
    """Return canonical, deep-copied display rows for one authorized page."""

    if type(page) is not QueryPage:
        raise IntakeProjectionError("ledger projection requires an exact query page")
    rows = tuple(_row(item) for item in page.items)
    # Normalize every scalar/container to the plain JSON graph that reaches the
    # wire.  This is both a deep-copy and a final no-subclass boundary.
    try:
        normalized = json.loads(canonical_bytes(list(rows)).decode("utf-8"))
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise IntakeProjectionError("ledger projection is not canonical JSON") from error
    if type(normalized) is not list or any(type(row) is not dict or set(row) != _ROW_FIELDS for row in normalized):
        raise IntakeProjectionError("ledger projection row schema is invalid")
    return tuple(normalized)


__all__ = ["IntakeProjectionError", "project_intake_ledger_page"]
