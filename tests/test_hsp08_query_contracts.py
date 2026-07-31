"""HSP-08: pure, strict, immutable journal-query request contracts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from houndd.query_contracts import (
    QueryContractError,
    QueryFilter,
    QueryRequest,
    TimeRange,
    parse_query_request,
    parse_utc_instant,
)


_CANONICAL_SHA256 = "a" * 64


def test_hsp08_minimal_query_uses_default_limit_and_is_immutable() -> None:
    query = parse_query_request({"filter": {}})

    assert query == QueryRequest(filter=QueryFilter())
    assert query.limit == 50
    assert query.cursor is None
    assert query.filter.canonical == {}
    assert len(query.filter_hash) == 64
    with pytest.raises(FrozenInstanceError):
        query.limit = 51  # type: ignore[misc]


@pytest.mark.parametrize(
    ("family", "value", "expected"),
    [
        (
            "time_range",
            {"from": "2026-07-31T01:00:00+01:00", "to": "2026-07-31T02:00:00+01:00"},
            {"from": "2026-07-31T00:00:00.000000Z", "to": "2026-07-31T01:00:00.000000Z"},
        ),
        (
            "producer",
            {"owner_id": ["owner-b", "owner-a"], "capability": ["search"], "run_id": ["run"]},
            {"owner_id": ["owner-a", "owner-b"], "capability": ["search"], "run_id": ["run"]},
        ),
        ("lane", ["benefits", "pulse"], ["benefits", "pulse"]),
        ("topic", ["access", "care"], ["access", "care"]),
        (
            "source",
            {"provider": ["exa"], "canonical_url": ["https://example.test/Z", "https://example.test/a"]},
            {"provider": ["exa"], "canonical_url": ["https://example.test/Z", "https://example.test/a"]},
        ),
        ("entity", ["entity"], ["entity"]),
        ("entry_id", [_CANONICAL_SHA256], [_CANONICAL_SHA256]),
        ("record_id", ["record"], ["record"]),
        ("object_key", ["object"], ["object"]),
        ("content_sha256", [_CANONICAL_SHA256], [_CANONICAL_SHA256]),
        (
            "classification",
            {"outcome": ["completed"], "evidence_status": ["evidence"]},
            {"outcome": ["completed"], "evidence_status": ["evidence"]},
        ),
        ("access", ["restricted", "public", "workspace"], ["public", "restricted", "workspace"]),
    ],
)
def test_hsp08_exact_filter_family_matrix_normalizes(family: str, value: object, expected: object) -> None:
    query = parse_query_request({"filter": {family: value}})

    assert query.filter.canonical == {family: expected}


def test_hsp08_multivalue_or_and_cross_field_and_have_one_canonical_hash() -> None:
    left = parse_query_request(
        {
            "filter": {
                "producer": {
                    "owner_id": ["owner-b", "owner-a", "owner-b"],
                    "capability": ["search", "capture", "search"],
                },
                "lane": ["pulse", "benefits", "pulse"],
                "source": {"provider": ["firecrawl", "exa", "exa"]},
                "classification": {"outcome": ["partial", "completed", "partial"]},
            },
            "limit": 1,
            "cursor": "old-page",
        }
    )
    right = parse_query_request(
        {
            "cursor": "another-page",
            "limit": 100,
            "filter": {
                "classification": {"outcome": ["completed", "partial"]},
                "source": {"provider": ["exa", "firecrawl"]},
                "lane": ["benefits", "pulse"],
                "producer": {
                    "capability": ["capture", "search"],
                    "owner_id": ["owner-a", "owner-b"],
                },
            },
        }
    )

    assert left.filter == right.filter
    assert left.filter_hash == right.filter_hash
    assert left.filter.producer is not None
    assert left.filter.producer.owner_id == ("owner-a", "owner-b")
    assert left.filter.producer.capability == ("capture", "search")
    assert left.filter.lane == ("benefits", "pulse")

    different = parse_query_request({"filter": {"lane": ["benefits", "radar"]}})
    assert different.filter_hash != left.filter_hash


def test_hsp08_timestamp_offsets_hash_as_the_same_utc_instants_and_boundaries_are_exact() -> None:
    offset = parse_query_request(
        {
            "filter": {
                "time_range": {
                    "from": "2026-07-31T05:30:00+05:30",
                    "to": "2026-07-31T06:30:00+05:30",
                }
            }
        }
    )
    utc = parse_query_request(
        {
            "filter": {
                "time_range": {
                    "from": "2026-07-31T00:00:00Z",
                    "to": "2026-07-31T01:00:00+00:00",
                }
            }
        }
    )

    assert offset.filter_hash == utc.filter_hash
    time_range = offset.filter.time_range
    assert time_range is not None
    assert time_range.lower == datetime(2026, 7, 31, tzinfo=UTC)
    assert time_range.upper == datetime(2026, 7, 31, 1, tzinfo=UTC)
    assert time_range.contains("2026-07-31T00:00:00Z") is True
    assert time_range.contains("2026-07-31T00:59:59.999999Z") is True
    assert time_range.contains("2026-07-31T01:00:00Z") is False
    assert time_range.contains("2026-07-30T23:59:59.999999Z") is False


def test_hsp08_arbitrary_strings_and_urls_are_not_normalized() -> None:
    query = parse_query_request(
        {
            "filter": {
                "source": {"canonical_url": ["HTTPS://Example.test/%7eA", "https://example.test/~A"]},
                "topic": [" Topic", "topic"],
            },
            "cursor": " cursor remains exact ",
        }
    )

    assert query.filter.source is not None
    assert query.filter.source.canonical_url == ("HTTPS://Example.test/%7eA", "https://example.test/~A")
    assert query.filter.topic == (" Topic", "topic")
    assert query.cursor == " cursor remains exact "


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, value)
        for field in ("entry_id", "content_sha256")
        for value in ("A" * 64, "a" * 63, "g" * 64)
    ],
)
def test_hsp08_query_parser_rejects_noncanonical_sha256_filters(field: str, value: str) -> None:
    with pytest.raises(QueryContractError):
        parse_query_request({"filter": {field: [value]}})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, value)
        for field in ("entry_id", "content_sha256")
        for value in ("A" * 64, "a" * 63, "g" * 64)
    ],
)
def test_hsp08_direct_query_filter_rejects_noncanonical_sha256_values(field: str, value: str) -> None:
    with pytest.raises(QueryContractError):
        QueryFilter(**{field: (value,)})


def test_hsp08_sha256_filters_accept_canonical_values_without_constraining_ids() -> None:
    parsed = parse_query_request(
        {
            "filter": {
                "entry_id": [_CANONICAL_SHA256],
                "content_sha256": [_CANONICAL_SHA256],
                "record_id": ["arbitrary-record"],
                "object_key": ["arbitrary/object-key"],
            }
        }
    )
    direct = QueryFilter(
        entry_id=(_CANONICAL_SHA256,),
        content_sha256=(_CANONICAL_SHA256,),
        record_id=("arbitrary-record",),
        object_key=("arbitrary/object-key",),
    )

    assert parsed.filter == direct
    assert parsed.filter.canonical == {
        "entry_id": [_CANONICAL_SHA256],
        "content_sha256": [_CANONICAL_SHA256],
        "record_id": ["arbitrary-record"],
        "object_key": ["arbitrary/object-key"],
    }


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"filter": None},
        {"filter": []},
        {"filter": {}, "unknown": True},
        {"filter": {}, "principal": "forged"},
        {"filter": {}, "uid": 1000},
        {"filter": {}, "peer": "forged"},
        {"filter": {}, "policy_grant": "forged"},
        {"filter": {}, "generation": "forged"},
        {"filter": {}, "key": "forged"},
        {"filter": {}, "offset": 0},
        {"filter": {}, "count": True},
        {"filter": {}, "total": True},
        {"filter": {}, "page": 2},
        {"filter": {}, "page_hint": "next"},
        {"filter": {}, "limit": None},
        {"filter": {}, "limit": True},
        {"filter": {}, "limit": 0},
        {"filter": {}, "limit": 101},
        {"filter": {}, "limit": 1.0},
        {"filter": {}, "limit": "50"},
        {"filter": {}, "cursor": None},
        {"filter": {}, "cursor": ""},
        {"filter": {}, "cursor": ["cursor"]},
    ],
)
def test_hsp08_request_shape_and_pagination_fail_closed(payload: object) -> None:
    with pytest.raises(QueryContractError):
        parse_query_request(payload)


@pytest.mark.parametrize(
    "filter_value",
    [
        {"unknown": ["value"]},
        {1: ["value"]},
        {"lane": None},
        {"lane": "pulse"},
        {"lane": ()},
        {"lane": []},
        {"lane": [""]},
        {"lane": ["pulse", None]},
        {"lane": ["pulse", 1]},
        {"access": ["private"]},
        {"producer": None},
        {"producer": []},
        {"producer": {}},
        {"producer": {"unknown": ["value"]}},
        {"producer": {"owner_id": []}},
        {"producer": {"owner_id": "owner"}},
        {"producer": {"owner_id": [""]}},
        {"source": {}},
        {"source": {"canonical_url": None}},
        {"source": {"provider": ["exa"], "native_id": ["native"]}},
        {"classification": {}},
        {"classification": {"outcome": [], "evidence_status": ["evidence"]}},
        {"classification": {"status": ["complete"]}},
        {"time_range": None},
        {"time_range": []},
        {"time_range": {}},
        {"time_range": {"from": "2026-07-31T00:00:00Z"}},
        {
            "time_range": {
                "from": "2026-07-31T00:00:00Z",
                "to": "2026-08-01T00:00:00Z",
                "timezone": "UTC",
            }
        },
        {"time_range": {"from": None, "to": "2026-08-01T00:00:00Z"}},
        {"time_range": {"from": "not-a-time", "to": "2026-08-01T00:00:00Z"}},
        {"time_range": {"from": "2026-07-31T00:00:00", "to": "2026-08-01T00:00:00Z"}},
        {"time_range": {"from": "2026-08-01T00:00:00Z", "to": "2026-08-01T00:00:00Z"}},
        {"time_range": {"from": "2026-08-02T00:00:00Z", "to": "2026-08-01T00:00:00Z"}},
    ],
)
def test_hsp08_filter_values_fail_closed(filter_value: object) -> None:
    with pytest.raises(QueryContractError):
        parse_query_request({"filter": filter_value})


def test_hsp08_direct_time_range_and_timestamp_helpers_validate_awareness() -> None:
    assert parse_utc_instant("2026-07-31T01:00:00+01:00") == datetime(2026, 7, 31, tzinfo=UTC)
    with pytest.raises(QueryContractError):
        parse_utc_instant(datetime(2026, 7, 31))
    with pytest.raises(QueryContractError):
        TimeRange(datetime(2026, 7, 31), datetime(2026, 8, 1, tzinfo=UTC))


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-07-31/00:00:00Z",
        "2026-07-31\n00:00:00Z",
        "2026-07-31\x0000:00:00Z",
        "2026-07-31🙂00:00:00Z",
        "2026-07-31T00:00:00.0000001Z",
    ],
)
def test_hsp08_timestamp_parser_rejects_non_contract_separators_and_unsupported_precision(
    timestamp: str,
) -> None:
    with pytest.raises(QueryContractError):
        parse_utc_instant(timestamp)
