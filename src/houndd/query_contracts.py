"""HSP-08 pure journal-query request and filter contracts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


class QueryContractError(ValueError):
    """A journal-query value does not satisfy the strict request contract."""


_REQUEST_FIELDS = frozenset({"filter", "limit", "cursor"})
_FILTER_FIELDS = frozenset(
    {
        "time_range",
        "producer",
        "lane",
        "topic",
        "source",
        "entity",
        "entry_id",
        "record_id",
        "object_key",
        "content_sha256",
        "classification",
        "access",
    }
)
_PRODUCER_FIELDS = ("owner_id", "capability", "run_id")
_SOURCE_FIELDS = ("provider", "canonical_url")
_CLASSIFICATION_FIELDS = ("outcome", "evidence_status")
_DIRECT_FILTER_FIELDS = (
    "lane",
    "topic",
    "entity",
    "entry_id",
    "record_id",
    "object_key",
    "content_sha256",
    "access",
)
_ACCESS_TIERS = frozenset({"public", "workspace", "restricted"})
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
_AWARE_ISO_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}(?::?\d{2})?)",
    re.ASCII,
)


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise QueryContractError(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise QueryContractError(f"{label} keys must be strings")
    return value


def _strict_fields(
    value: Mapping[str, Any],
    *,
    allowed: frozenset[str] | set[str],
    required: frozenset[str] | set[str] = frozenset(),
    label: str,
) -> None:
    missing = required - value.keys()
    unknown = value.keys() - allowed
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {sorted(missing)!r}")
        if unknown:
            details.append(f"unknown {sorted(unknown)!r}")
        raise QueryContractError(f"{label} has {' and '.join(details)}")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise QueryContractError(f"{label} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise QueryContractError(f"{label} must contain valid Unicode") from error
    return value


def _request_values(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise QueryContractError(f"{label} must be a non-empty list of strings")
    normalized = tuple(sorted({_text(item, f"{label}[]") for item in value}))
    return normalized


def _model_values(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise QueryContractError(f"{label} must be a non-empty tuple of strings")
    return tuple(sorted({_text(item, f"{label}[]") for item in value}))


def _normalize_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, datetime):
        raise QueryContractError(f"{label} must be an aware datetime")
    try:
        offset = value.utcoffset()
    except (OverflowError, ValueError) as error:
        raise QueryContractError(f"{label} must be an aware datetime") from error
    if value.tzinfo is None or offset is None:
        raise QueryContractError(f"{label} must be an aware datetime")
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError) as error:
        raise QueryContractError(f"{label} cannot be represented in UTC") from error


def parse_utc_instant(value: Any, label: str = "timestamp") -> datetime:
    """Parse one timezone-aware ISO-8601 string and normalize it to UTC."""

    text = _text(value, label)
    if _AWARE_ISO_PATTERN.fullmatch(text) is None:
        raise QueryContractError(f"{label} must be an aware ISO-8601 timestamp")
    iso_value = f"{text[:-1]}+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(iso_value)
    except (OverflowError, ValueError) as error:
        raise QueryContractError(f"{label} must be an aware ISO-8601 timestamp") from error
    try:
        return _normalize_datetime(parsed, label)
    except QueryContractError as error:
        raise QueryContractError(f"{label} must be an aware ISO-8601 timestamp") from error


def _canonical_instant(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class TimeRange:
    """An inclusive UTC lower bound and exclusive UTC upper bound."""

    lower: datetime
    upper: datetime

    def __post_init__(self) -> None:
        lower = _normalize_datetime(self.lower, "time_range.from")
        upper = _normalize_datetime(self.upper, "time_range.to")
        if lower >= upper:
            raise QueryContractError("time_range.from must be earlier than time_range.to")
        object.__setattr__(self, "lower", lower)
        object.__setattr__(self, "upper", upper)

    @property
    def canonical(self) -> dict[str, str]:
        return {"from": _canonical_instant(self.lower), "to": _canonical_instant(self.upper)}

    def contains(self, value: str | datetime) -> bool:
        """Apply the exact lower-inclusive, upper-exclusive boundary."""

        if isinstance(value, str):
            instant = parse_utc_instant(value, "appended_at")
        else:
            instant = _normalize_datetime(value, "appended_at")
        return self.lower <= instant < self.upper


@dataclass(frozen=True, slots=True)
class ProducerFilter:
    owner_id: tuple[str, ...] | None = None
    capability: tuple[str, ...] | None = None
    run_id: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if all(getattr(self, field) is None for field in _PRODUCER_FIELDS):
            raise QueryContractError("producer must contain at least one selector")
        for field in _PRODUCER_FIELDS:
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _model_values(value, f"producer.{field}"))

    @property
    def canonical(self) -> dict[str, list[str]]:
        return {
            field: list(value)
            for field in _PRODUCER_FIELDS
            if (value := getattr(self, field)) is not None
        }


@dataclass(frozen=True, slots=True)
class SourceFilter:
    provider: tuple[str, ...] | None = None
    canonical_url: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if all(getattr(self, field) is None for field in _SOURCE_FIELDS):
            raise QueryContractError("source must contain at least one selector")
        for field in _SOURCE_FIELDS:
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _model_values(value, f"source.{field}"))

    @property
    def canonical(self) -> dict[str, list[str]]:
        return {
            field: list(value)
            for field in _SOURCE_FIELDS
            if (value := getattr(self, field)) is not None
        }


@dataclass(frozen=True, slots=True)
class ClassificationFilter:
    outcome: tuple[str, ...] | None = None
    evidence_status: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if all(getattr(self, field) is None for field in _CLASSIFICATION_FIELDS):
            raise QueryContractError("classification must contain at least one selector")
        for field in _CLASSIFICATION_FIELDS:
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _model_values(value, f"classification.{field}"))

    @property
    def canonical(self) -> dict[str, list[str]]:
        return {
            field: list(value)
            for field in _CLASSIFICATION_FIELDS
            if (value := getattr(self, field)) is not None
        }


@dataclass(frozen=True, slots=True)
class QueryFilter:
    time_range: TimeRange | None = None
    producer: ProducerFilter | None = None
    lane: tuple[str, ...] | None = None
    topic: tuple[str, ...] | None = None
    source: SourceFilter | None = None
    entity: tuple[str, ...] | None = None
    entry_id: tuple[str, ...] | None = None
    record_id: tuple[str, ...] | None = None
    object_key: tuple[str, ...] | None = None
    content_sha256: tuple[str, ...] | None = None
    classification: ClassificationFilter | None = None
    access: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        for field, expected in (
            ("time_range", TimeRange),
            ("producer", ProducerFilter),
            ("source", SourceFilter),
            ("classification", ClassificationFilter),
        ):
            value = getattr(self, field)
            if value is not None and not isinstance(value, expected):
                raise QueryContractError(f"{field} must be a {expected.__name__}")
        for field in _DIRECT_FILTER_FIELDS:
            value = getattr(self, field)
            if value is not None:
                normalized = _model_values(value, field)
                if field in {"entry_id", "content_sha256"} and any(
                    _SHA256_PATTERN.fullmatch(item) is None for item in normalized
                ):
                    raise QueryContractError(f"{field} must contain lowercase SHA-256 digests")
                if field == "access" and any(item not in _ACCESS_TIERS for item in normalized):
                    raise QueryContractError("access contains an unsupported tier")
                object.__setattr__(self, field, normalized)

    @property
    def canonical(self) -> dict[str, Any]:
        value: dict[str, Any] = {}
        if self.time_range is not None:
            value["time_range"] = self.time_range.canonical
        if self.producer is not None:
            value["producer"] = self.producer.canonical
        for field in ("lane", "topic"):
            if (items := getattr(self, field)) is not None:
                value[field] = list(items)
        if self.source is not None:
            value["source"] = self.source.canonical
        for field in ("entity", "entry_id", "record_id", "object_key", "content_sha256"):
            if (items := getattr(self, field)) is not None:
                value[field] = list(items)
        if self.classification is not None:
            value["classification"] = self.classification.canonical
        if self.access is not None:
            value["access"] = list(self.access)
        return value

    @property
    def filter_hash(self) -> str:
        encoded = json.dumps(
            self.canonical,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def hash(self) -> str:
        return self.filter_hash


@dataclass(frozen=True, slots=True)
class QueryRequest:
    filter: QueryFilter
    limit: int = 50
    cursor: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.filter, QueryFilter):
            raise QueryContractError("filter must be a QueryFilter")
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or not 1 <= self.limit <= 100:
            raise QueryContractError("limit must be an integer from 1 through 100")
        if self.cursor is not None:
            _text(self.cursor, "cursor")

    @property
    def filter_hash(self) -> str:
        return self.filter.filter_hash

    @property
    def canonical(self) -> dict[str, Any]:
        value: dict[str, Any] = {"filter": self.filter.canonical, "limit": self.limit}
        if self.cursor is not None:
            value["cursor"] = self.cursor
        return value


def _parse_nested_values(
    value: Any,
    *,
    fields: tuple[str, ...],
    label: str,
) -> dict[str, tuple[str, ...] | None]:
    nested = _object(value, label)
    allowed = frozenset(fields)
    _strict_fields(nested, allowed=allowed, label=label)
    if not nested:
        raise QueryContractError(f"{label} must contain at least one selector")
    return {
        field: _request_values(nested[field], f"{label}.{field}") if field in nested else None
        for field in fields
    }


def parse_query_filter(value: Any) -> QueryFilter:
    """Validate and normalize the exact HSP-08 filter object."""

    source = _object(value, "filter")
    _strict_fields(source, allowed=_FILTER_FIELDS, label="filter")

    values: dict[str, Any] = {}
    if "time_range" in source:
        time_value = _object(source["time_range"], "filter.time_range")
        _strict_fields(
            time_value,
            allowed={"from", "to"},
            required={"from", "to"},
            label="filter.time_range",
        )
        values["time_range"] = TimeRange(
            parse_utc_instant(time_value["from"], "filter.time_range.from"),
            parse_utc_instant(time_value["to"], "filter.time_range.to"),
        )
    if "producer" in source:
        values["producer"] = ProducerFilter(
            **_parse_nested_values(source["producer"], fields=_PRODUCER_FIELDS, label="filter.producer")
        )
    for field in ("lane", "topic"):
        if field in source:
            values[field] = _request_values(source[field], f"filter.{field}")
    if "source" in source:
        values["source"] = SourceFilter(
            **_parse_nested_values(source["source"], fields=_SOURCE_FIELDS, label="filter.source")
        )
    for field in ("entity", "entry_id", "record_id", "object_key", "content_sha256"):
        if field in source:
            values[field] = _request_values(source[field], f"filter.{field}")
    if "classification" in source:
        values["classification"] = ClassificationFilter(
            **_parse_nested_values(
                source["classification"],
                fields=_CLASSIFICATION_FIELDS,
                label="filter.classification",
            )
        )
    if "access" in source:
        access = _request_values(source["access"], "filter.access")
        if any(item not in _ACCESS_TIERS for item in access):
            raise QueryContractError("filter.access contains an unsupported tier")
        values["access"] = access
    return QueryFilter(**values)


def parse_query_request(value: Any) -> QueryRequest:
    """Validate a request payload containing only filter, limit, and cursor."""

    request = _object(value, "query request")
    _strict_fields(request, allowed=_REQUEST_FIELDS, required={"filter"}, label="query request")
    limit = request.get("limit", 50)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise QueryContractError("query request.limit must be an integer from 1 through 100")
    cursor = request.get("cursor")
    if "cursor" in request:
        cursor = _text(cursor, "query request.cursor")
    return QueryRequest(filter=parse_query_filter(request["filter"]), limit=limit, cursor=cursor)


__all__ = [
    "ClassificationFilter",
    "ProducerFilter",
    "QueryContractError",
    "QueryFilter",
    "QueryRequest",
    "SourceFilter",
    "TimeRange",
    "parse_query_filter",
    "parse_query_request",
    "parse_utc_instant",
]
