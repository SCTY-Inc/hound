"""GOALIE B13: ``ingest.search`` carries a bounded, additive ``options`` object.

The editorial week a caller declares (category, published-date window, location)
must survive as a provider-received bound *and* as durable record provenance,
without invalidating a single search record committed before options existed.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from houndd.adapter_host import AdapterFailed, AdapterHost
from houndd.adapter_validation import (
    AdapterOutcomeError,
    validate_adapter_outcome,
    validate_adapter_record,
    validate_search_options,
)
from houndd.commit import CommitContractError, parse_commit_request, resolve_route
from houndd.commit_runtime import CommitIntegrityError, CommitRuntime
from houndd.contracts import canonical_bytes, canonical_hash
from houndd.verify import verify_store

from tests.test_cli_ingest_web import StubHoundd, _commit_response, _envelope_args, run_research_cli
from tests.test_slice3c2_adapter_commit import PRINCIPAL, _FauxHost, _frame, _request, _scope, _state


# The shape the Pulse discovery spec produces: one editorial week, one category.
OPTIONS: dict[str, Any] = {
    "category": "news",
    "startPublishedDate": "2026-07-27T00:00:00Z",
    "endPublishedDate": "2026-08-03T00:00:00Z",
    "includeDomains": ["kff.org", "healthaffairs.org"],
    "userLocation": "US",
    "type": "auto",
}
LEGACY_FIXTURE = Path(__file__).parent / "fixtures" / "b13_legacy_search_records.json"
# Every field a search record carried before B13.  Options must never join it.
PRE_B13_FIELDS = frozenset({
    "attempt_id",
    "byte_length",
    "content_sha256",
    "evidence_status",
    "leads",
    "limit",
    "lineage",
    "operation",
    "outcome",
    "provider",
    "query",
    "reason",
    "request_hash",
    "retrieved_at",
    "schema_version",
})


def _oversized_options() -> dict[str, Any]:
    """Options every vocabulary rule accepts and the byte bound still refuses."""

    return {
        "includeDomains": [f"{'a' * 480}{index:03d}.test" for index in range(100)],
        "excludeDomains": [f"{'b' * 480}{index:03d}.test" for index in range(100)],
    }


def _payload(options: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"query": "caregiver respite", "limit": 5}
    if options is not None:
        payload["options"] = deepcopy(options)
    return payload


def _committed_search(state: Path, *, options: dict[str, Any] | None, key: str) -> tuple[CommitRuntime, dict[str, Any], _FauxHost]:
    """Run one accepted search commit and return its runtime, record, and host."""

    request, route = _request("ingest.search", key=key, payload=_payload(options))
    host = _FauxHost("ingest.search")
    runtime = CommitRuntime(state)
    response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
    assert response["outcome"] == "completed"
    record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
    return runtime, record, host


# --------------------------------------------------------------- wire payload


def test_the_options_free_payload_is_still_the_canonical_payload() -> None:
    """The pre-B13 wire shape must survive byte-for-byte."""

    route = resolve_route("POST", "/v1/ingest/search", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.search", key="k", request_id="r", payload=_payload())["body"], route)

    assert dict(request.payload) == {"query": "caregiver respite", "limit": 5}


def test_the_wire_payload_accepts_and_retains_bounded_options() -> None:
    route = resolve_route("POST", "/v1/ingest/search", require_available=True)
    request = parse_commit_request(_frame(operation="ingest.search", key="k", request_id="r", payload=_payload(OPTIONS))["body"], route)

    assert dict(request.payload) == {"query": "caregiver respite", "limit": 5, "options": OPTIONS}


@pytest.mark.parametrize(
    "options",
    (
        pytest.param({"category": "gossip"}, id="unknown-category"),
        pytest.param({"type": "deep"}, id="unsupported-search-type"),
        pytest.param({"neuralQuery": True}, id="unknown-field"),
        pytest.param({"startPublishedDate": "2026-08-03T00:00:00Z", "endPublishedDate": "2026-07-27T00:00:00Z"}, id="reversed-window"),
        pytest.param({"startPublishedDate": "last tuesday"}, id="unparseable-date"),
        pytest.param({"userLocation": "usa"}, id="non-two-letter-location"),
        pytest.param({"includeDomains": ["kff.org"], "excludeDomains": ["kff.org"]}, id="overlapping-domains"),
        pytest.param({"includeDomains": []}, id="empty-domain-list"),
        pytest.param({"category": "company", "endPublishedDate": "2026-08-03T00:00:00Z"}, id="category-refuses-dates"),
        pytest.param([], id="not-an-object"),
        pytest.param("news", id="not-an-object-string"),
        pytest.param(None, id="null"),
    ),
)
def test_the_wire_payload_refuses_options_outside_the_provider_vocabulary(options: object) -> None:
    route = resolve_route("POST", "/v1/ingest/search", require_available=True)
    body = _frame(operation="ingest.search", key="k", request_id="r", payload={"query": "q", "limit": 5, "options": options})["body"]

    with pytest.raises(CommitContractError, match="ingest.search.options is invalid"):
        parse_commit_request(body, route)


def test_the_wire_payload_refuses_options_beyond_the_shared_byte_bound() -> None:
    route = resolve_route("POST", "/v1/ingest/search", require_available=True)
    body = _frame(operation="ingest.search", key="k", request_id="r", payload={"query": "q", "limit": 5, "options": _oversized_options()})["body"]

    with pytest.raises(CommitContractError, match="too large"):
        parse_commit_request(body, route)


def test_the_options_vocabulary_is_the_adapter_vocabulary() -> None:
    """One vocabulary: the daemon's validator is the exa adapter's normalizer."""

    from hound_web_adapters._http import AdapterError
    from hound_web_adapters.exa import normalize_search_options

    assert validate_search_options(OPTIONS) == OPTIONS
    assert normalize_search_options(OPTIONS) == OPTIONS
    with pytest.raises(AdapterError):
        normalize_search_options({"category": "gossip"})
    with pytest.raises(AdapterOutcomeError):
        validate_search_options({"category": "gossip"})


# ---------------------------------------------------- canonical replay bounds


def test_the_runtime_refuses_a_canonical_payload_whose_options_were_tampered_with() -> None:
    """Replay revalidates the stored canonical payload, not just the wire one."""

    with pytest.raises(CommitIntegrityError, match="canonical ingest.search options are invalid"):
        CommitRuntime._validate_adapter_payload("ingest.search", {"query": "q", "limit": 5, "options": {"category": "gossip"}})
    with pytest.raises(CommitIntegrityError, match="canonical ingest.search payload is invalid"):
        CommitRuntime._validate_adapter_payload("ingest.search", {"query": "q", "limit": 5, "region": "US"})
    assert CommitRuntime._validate_adapter_payload("ingest.search", {"query": "q", "limit": 5}) == {"query": "q", "limit": 5}


# -------------------------------------------------------- provider forwarding


def test_the_adapter_host_forwards_options_into_the_provider_request() -> None:
    calls: list[dict[str, Any]] = []
    response = json.dumps({"results": [{"id": "https://example.test/a", "url": "https://example.test/a", "title": "A"}]}).encode()

    def transport(**call: Any) -> tuple[int, bytes]:
        calls.append(call)
        return 200, response

    host = AdapterHost.from_env({"EXA_API_KEY": "key"}, transport=transport)
    result = host.invoke("ingest.search", _payload(OPTIONS))

    assert result.outcome == "completed"
    provider_request = json.loads(calls[0]["body"])
    assert provider_request["category"] == "news"
    assert provider_request["startPublishedDate"] == "2026-07-27T00:00:00Z"
    assert provider_request["endPublishedDate"] == "2026-08-03T00:00:00Z"
    assert provider_request["includeDomains"] == ["kff.org", "healthaffairs.org"]
    assert provider_request["userLocation"] == "US"
    assert provider_request["query"] == "caregiver respite" and provider_request["numResults"] == 5


def test_the_adapter_host_sends_no_option_fields_when_the_payload_has_none() -> None:
    calls: list[dict[str, Any]] = []
    response = json.dumps({"results": [{"id": "https://example.test/a", "url": "https://example.test/a", "title": "A"}]}).encode()

    def transport(**call: Any) -> tuple[int, bytes]:
        calls.append(call)
        return 200, response

    AdapterHost.from_env({"EXA_API_KEY": "key"}, transport=transport).invoke("ingest.search", _payload())

    provider_request = json.loads(calls[0]["body"])
    assert set(provider_request) == {"query", "numResults", "type", "contents"}


def test_the_adapter_host_refuses_options_the_provider_would_reject() -> None:
    def transport(**_: Any) -> tuple[int, bytes]:
        raise AssertionError("an invalid option must not reach the provider")

    host = AdapterHost.from_env({"EXA_API_KEY": "key"}, transport=transport)

    with pytest.raises(AdapterFailed):
        host.invoke("ingest.search", _payload({"category": "gossip"}))


# ------------------------------------------------------------ record binding


def test_a_committed_record_retains_its_options_and_the_adapter_received_them(tmp_path: Path) -> None:
    runtime, record, host = _committed_search(_state(tmp_path), options=OPTIONS, key="options")
    try:
        assert record["options"] == OPTIONS
        assert host.calls == [{"query": "caregiver respite", "limit": 5, "options": OPTIONS}]
        assert set(record) == PRE_B13_FIELDS | {"options"}
        assert canonical_hash(record) == runtime.journal.entries()[0]["artifact"]["record_id"]  # type: ignore[union-attr]
    finally:
        runtime.close()


def test_a_committed_record_without_options_keeps_the_pre_b13_field_set(tmp_path: Path) -> None:
    runtime, record, host = _committed_search(_state(tmp_path), options=None, key="plain")
    try:
        assert set(record) == PRE_B13_FIELDS
        assert host.calls == [{"query": "caregiver respite", "limit": 5}]
    finally:
        runtime.close()


def test_a_store_holding_both_record_shapes_verifies(tmp_path: Path) -> None:
    """The offline verify pattern over a store with and without options."""

    state = _state(tmp_path)
    runtime, _, _ = _committed_search(state, options=OPTIONS, key="options")
    runtime.close()
    runtime, _, _ = _committed_search(state, options=None, key="plain")
    try:
        assert len(runtime.journal.entries()) == 2  # type: ignore[union-attr]
    finally:
        runtime.close()

    assert verify_store(state, projection=False)["valid"] is True
    assert verify_store(state)["valid"] is True


@pytest.mark.parametrize(
    "tamper",
    (
        pytest.param(lambda record: record["options"].__setitem__("category", "publication"), id="changed-category"),
        pytest.param(lambda record: record["options"].__setitem__("endPublishedDate", "2026-08-04T00:00:00Z"), id="widened-window"),
        pytest.param(lambda record: record.pop("options"), id="dropped-options"),
    ),
)
def test_a_tampered_record_no_longer_binds_its_request(tmp_path: Path, tamper: Any) -> None:
    runtime, record, _ = _committed_search(_state(tmp_path), options=OPTIONS, key="options")
    try:
        record_id = canonical_hash(record)
        event = deepcopy(runtime.journal.entries()[0])  # type: ignore[union-attr]
        payload = _payload(OPTIONS)
        tampered = deepcopy(record)
        tamper(tampered)

        # The request binding fails on its own terms...
        with pytest.raises(AdapterOutcomeError, match="does not bind its request"):
            validate_adapter_record(tampered, expected_operation="ingest.search", expected_payload=payload)
        # ...and the record hash refuses the mutation independently.
        assert canonical_hash(tampered) != record_id
        with pytest.raises(AdapterOutcomeError):
            validate_adapter_outcome(tampered, event, record_id=record_id)
    finally:
        runtime.close()


def test_a_record_that_invents_options_the_request_never_carried_is_refused(tmp_path: Path) -> None:
    runtime, record, _ = _committed_search(_state(tmp_path), options=None, key="plain")
    try:
        forged = deepcopy(record) | {"options": OPTIONS}
        with pytest.raises(AdapterOutcomeError, match="does not bind its request"):
            validate_adapter_record(forged, expected_operation="ingest.search", expected_payload=_payload())
    finally:
        runtime.close()


def test_a_record_holding_options_outside_the_vocabulary_is_refused(tmp_path: Path) -> None:
    runtime, record, _ = _committed_search(_state(tmp_path), options=None, key="plain")
    try:
        for options in ({"category": "gossip"}, {"neuralQuery": True}, _oversized_options(), None, "news"):
            with pytest.raises(AdapterOutcomeError, match="search options are"):
                validate_adapter_record(deepcopy(record) | {"options": options}, expected_operation="ingest.search")
    finally:
        runtime.close()


def test_the_record_field_set_stays_closed_around_options(tmp_path: Path) -> None:
    """Widening for ``options`` must not have opened the record to anything else."""

    runtime, record, _ = _committed_search(_state(tmp_path), options=OPTIONS, key="options")
    try:
        for extra in ("region", "userLocation", "provider_request"):
            with pytest.raises(AdapterOutcomeError, match="invalid shape"):
                validate_adapter_record(deepcopy(record) | {extra: "x"}, expected_operation="ingest.search")
        with pytest.raises(AdapterOutcomeError, match="invalid shape"):
            validate_adapter_record({key: value for key, value in record.items() if key != "query"}, expected_operation="ingest.search")
    finally:
        runtime.close()


def test_an_extract_record_may_not_carry_search_options(tmp_path: Path) -> None:
    """``options`` is a search field; the URL record shape is untouched."""

    state = _state(tmp_path)
    request, route = _request("ingest.url", key="url")
    runtime = CommitRuntime(state)
    try:
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_FauxHost("ingest.url"), scope=_scope())
        record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
        with pytest.raises(AdapterOutcomeError, match="invalid shape"):
            validate_adapter_record(record | {"options": OPTIONS}, expected_operation="ingest.url")
    finally:
        runtime.close()


# ------------------------------------------------ pre-B13 record compatibility


def _legacy_pairs() -> list[dict[str, Any]]:
    pairs = json.loads(LEGACY_FIXTURE.read_text(encoding="utf-8"))["pairs"]
    assert len(pairs) >= 4
    return pairs


def test_the_legacy_fixture_is_the_production_pre_b13_record_shape() -> None:
    outcomes = set()
    for pair in _legacy_pairs():
        assert set(pair["record"]) == PRE_B13_FIELDS
        assert pair["record"]["schema_version"] == "houndd.search-record.v1"
        outcomes.add(pair["record"]["outcome"])
    assert {"completed", "interrupted"} <= outcomes


def test_every_pre_b13_production_record_still_binds_its_journal_event() -> None:
    """The exact check verify_store runs per record, over real committed truth."""

    for pair in _legacy_pairs():
        outcome = validate_adapter_outcome(pair["record"], pair["event"], record_id=pair["record_id"])
        assert outcome.operation == "ingest.search" and outcome.provider == "exa"
        assert canonical_hash(pair["record"]) == pair["record_id"]


def test_a_pre_b13_record_still_binds_an_options_free_request() -> None:
    for pair in _legacy_pairs():
        record = pair["record"]
        validate_adapter_record(
            record,
            record_id=pair["record_id"],
            expected_operation="ingest.search",
            expected_payload={"query": record["query"], "limit": record["limit"]},
        )


def test_a_pre_b13_record_does_not_bind_a_request_that_declared_options() -> None:
    record = _legacy_pairs()[0]["record"]

    with pytest.raises(AdapterOutcomeError, match="does not bind its request"):
        validate_adapter_record(
            record,
            expected_operation="ingest.search",
            expected_payload={"query": record["query"], "limit": record["limit"], "options": OPTIONS},
        )


# ------------------------------------------------------------ client and CLI


def test_the_client_commit_path_passes_options_through_untouched(tmp_path: Path) -> None:
    from hound_client import HounddClient

    from tests.test_hound_client import StubHoundd as ClientStub, _commit_response as client_response, _framed

    socket_path = tmp_path / "houndd.sock"
    stub = ClientStub(socket_path, _framed(client_response(request_id="req-1", record_ids=["rec-1"])))

    record_id = HounddClient(socket_path, owner_id="lane-owner", policy_id="policy-1").commit(
        path="/v1/ingest/search",
        capability="ingest.search",
        payload=_payload(OPTIONS),
        idempotency_key="key-1",
        request_id="req-1",
        run_id="run-1",
    )
    stub.join()

    assert record_id == "rec-1"
    assert stub.request_frame["body"]["operation"]["payload"] == {"query": "caregiver respite", "limit": 5, "options": OPTIONS}


def test_the_research_cli_sends_options_json_as_the_payload_options(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]))

    code, _, stderr = run_research_cli(
        "ingest", "search",
        *_envelope_args(socket_path),
        "--query", "caregiver respite",
        "--limit", "5",
        "--options-json", json.dumps(OPTIONS),
    )
    stub.join()

    assert code == 0, stderr
    assert stub.request_frame["body"]["operation"]["payload"] == {"query": "caregiver respite", "limit": 5, "options": OPTIONS}


def test_the_research_cli_omits_options_when_none_are_given(tmp_path: Path) -> None:
    socket_path = tmp_path / "houndd.sock"
    stub = StubHoundd(socket_path, _commit_response(request_id="req-1", ok=True, outcome="completed", record_ids=["rec-1"], entry_ids=["entry-1"]))

    code, _, stderr = run_research_cli("ingest", "search", *_envelope_args(socket_path), "--query", "x")
    stub.join()

    assert code == 0, stderr
    assert stub.request_frame["body"]["operation"]["payload"] == {"query": "x", "limit": 10}


@pytest.mark.parametrize(
    "raw",
    (
        pytest.param("{not json", id="unparseable"),
        pytest.param('["news"]', id="not-an-object"),
        pytest.param('{"category": "gossip"}', id="unknown-category"),
        pytest.param('{"neuralQuery": true}', id="unknown-field"),
    ),
)
def test_the_research_cli_refuses_bad_options_before_any_connection(tmp_path: Path, raw: str) -> None:
    socket_path = tmp_path / "houndd.sock"  # never bound: no stub server is started

    code, stdout, stderr = run_research_cli(
        "ingest", "search",
        *_envelope_args(socket_path),
        "--query", "x",
        "--options-json", raw,
    )

    assert code == 2
    assert stdout == ""
    assert json.loads(stderr)["schema_version"] == "hound.error.v1"


def test_the_wire_body_bound_still_covers_an_options_bearing_request() -> None:
    """A request the daemon would accept must also fit the encoded wire bound."""

    body = _frame(operation="ingest.search", key="k", request_id="r", payload=_payload(OPTIONS))["body"]

    assert len(canonical_bytes(body)) < 1_048_576
