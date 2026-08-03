"""Slice 3C2 adapter operations: in-daemon search and URL extraction."""

from __future__ import annotations

import hashlib
import json
import ast
import os
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from houndd import HounddStore
from houndd.adapter_host import (
    ADAPTER_ENV_KEYS,
    AdapterAbstained,
    AdapterFailed,
    AdapterHost,
    AdapterHostError,
    AdapterResult,
    AdapterUnavailable,
)
from houndd.adapter_validation import AdapterOutcomeError, validate_adapter_outcome
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.commit import AVAILABLE_ROUTE_BINDINGS, CommitContractError, parse_commit_request, resolve_route
from houndd.commit_runtime import CommitRefusal, CommitRuntime, CommitUnavailable
from houndd.contracts import canonical_bytes, make_journal_envelope
from houndd.phi import PhiInputError, scan_text
from houndd.service import HounddService
from houndd.verify import verify_store


PRINCIPAL = f"linux-uid:{os.getuid()}"
SEARCH_CONTENT = canonical_bytes({
    "schema_version": "houndd.search-content.v1",
    "leads": [{"schema_version": "hound.lead.v1", "url": "https://example.test/a", "title": "A"}],
    "provider": "exa",
    "query": "caregiver respite",
    "limit": 5,
    "retrieved_at": "2026-08-03T00:00:00Z",
})
URL_CONTENT = b"# Respite care\n\nEligibility details."
LEADS = ({"url": "https://example.test/a", "title": "A", "native_id": "exa-1"},)


def _policy() -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [
            {
                "subject": PRINCIPAL,
                "claim_selector": {"owner_id": "writer", "capability": capability, "run_id": None},
                "policy_id": "write-policy",
                "event_producer_selectors": [{"owner_id": "writer", "capability": selector, "run_id": None} for selector in ("ingest.search", "ingest.url")],
                "readable_tiers": ["public"],
                "allowed_output_tiers": ["public"],
            }
            for capability in ("ingest.search", "ingest.url")
        ],
    }


def _state(tmp_path: Path, *, clear_manifest: bool = False) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    HounddStore(root).close()
    service = root / "service"
    service.mkdir(mode=0o700)
    (service / "policy.json").write_bytes(canonical_bytes(_policy()))
    (service / "policy.json").chmod(0o600)
    if clear_manifest:
        (service / "phi-clear.json").write_bytes(canonical_bytes({"schema_version": "houndd.phi-clear.v1", "entries": []}))
        (service / "phi-clear.json").chmod(0o600)
    return root


def _scope() -> PrincipalScope:
    tiers = frozenset({"public"})
    return PrincipalScope(
        principal=AuthenticatedPrincipal(PRINCIPAL),
        readable_tiers=tiers,
        permitted_event_selectors=tuple(EventSelector("write-policy", ProducerSelector("writer", capability, None), tiers) for capability in ("ingest.search", "ingest.url")),
    )


def _frame(*, operation: str, key: str, request_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if payload is None:
        payload = {"query": "caregiver respite", "limit": 5} if operation == "ingest.search" else {"url": "https://example.test/a", "lineage": {"kind": "direct"}}
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": "/v1/ingest/search" if operation == "ingest.search" else "/v1/ingest/url",
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": key,
            "producer": {"owner_id": "writer", "capability": operation, "run_id": "run"},
            "requested_access": "public",
            "policy_id": "write-policy",
            "operation": {"name": operation, "payload": payload},
        },
    }


def _request(operation: str, *, key: str, request_id: str = "one", payload: dict[str, Any] | None = None):
    route = resolve_route("POST", "/v1/ingest/search" if operation == "ingest.search" else "/v1/ingest/url", require_available=True)
    return parse_commit_request(_frame(operation=operation, key=key, request_id=request_id, payload=payload)["body"], route), route


def _result(operation: str, *, outcome: str = "completed", content: bytes | None = None) -> AdapterResult:
    if operation == "ingest.search":
        return AdapterResult("ingest.search", outcome, content or SEARCH_CONTENT, "application/json", "2026-08-03T00:00:00Z", 1, 0, LEADS)
    return AdapterResult("ingest.url", outcome, content or URL_CONTENT, "text/markdown", "2026-08-03T00:00:00Z", 1, 0)


class _FauxHost(AdapterHost):
    """One faux adapter that records every invocation it receives."""

    def __init__(self, operation: str, *, outcome: str = "completed", content: bytes | None = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []

        def adapter(payload: Any) -> AdapterResult:
            self.calls.append(dict(payload))
            if len(self.calls) > 1:
                raise AssertionError("an accepted attempt invoked its adapter more than once")
            if error is not None:
                raise error
            return _result(operation, outcome=outcome, content=content)

        super().__init__({operation: adapter})


_faux = _FauxHost


# ---------------------------------------------------------------- happy path


@pytest.mark.parametrize("operation", ("ingest.search", "ingest.url"))
def test_slice3c2_completed_commit_publishes_one_record_one_event_and_replays(tmp_path: Path, operation: str) -> None:
    state = _state(tmp_path)
    request, route = _request(operation, key="live")
    host = _faux(operation)
    runtime = CommitRuntime(state)
    try:
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert response["ok"] is True and response["outcome"] == "completed"
        assert len(response["record_ids"]) == 1 and len(response["entry_ids"]) == 1
        content = SEARCH_CONTENT if operation == "ingest.search" else URL_CONTENT
        assert response["usage"] == {"requests": 1, "bytes": len(content), "cost": 0}

        record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
        assert record["schema_version"] == ("houndd.search-record.v1" if operation == "ingest.search" else "houndd.url-record.v1")
        assert record["provider"] == ("exa" if operation == "ingest.search" else "firecrawl")
        assert record["content_sha256"] == hashlib.sha256(content).hexdigest() and record["byte_length"] == len(content)
        assert record["reason"] == "none" and record["evidence_status"] == "clear"
        if operation == "ingest.search":
            assert record["leads"] == [dict(lead) for lead in LEADS]
            assert record["query"] == "caregiver respite" and record["limit"] == 5
        else:
            assert record["url"] == "https://example.test/a"
        assert runtime.records.blobs.get(record["content_sha256"]) == content  # type: ignore[union-attr]

        event = runtime.journal.entries()[0]  # type: ignore[union-attr]
        assert event["artifact"]["kind"] == ("search" if operation == "ingest.search" else "extract")
        assert event["source"]["provider"] == record["provider"]
        assert event["source"]["canonical_url"] == ("none" if operation == "ingest.search" else "https://example.test/a")

        replay = runtime.probe(request, route, principal=PRINCIPAL)
        assert replay.response_template is not None and replay.response_template["record_ids"] == response["record_ids"]
        again = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert again == response and len(runtime.journal.entries()) == 1  # type: ignore[union-attr]
        assert len(host.calls) == 1
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


# ------------------------------------------------- durable non-completed set


@pytest.mark.parametrize(
    ("error", "outcome", "reason"),
    (
        (AdapterFailed("provider exchange failed", requests=1), "failed", "provider_failed"),
        (AdapterFailed("provider timed out", requests=1), "failed", "provider_failed"),
        (AdapterFailed("provider result is invalid", requests=1), "failed", "provider_failed"),
        (AdapterAbstained("provider abstained", requests=1), "refused", "provider_abstained"),
        (AdapterUnavailable("no adapter is bound"), "degraded", "adapter_absent"),
    ),
)
def test_slice3c2_provider_conditions_are_durable_outcomes_never_retries(tmp_path: Path, error: Exception, outcome: str, reason: str) -> None:
    state = _state(tmp_path)
    request, route = _request("ingest.search", key="fault")
    host = _faux("ingest.search", error=error)
    runtime = CommitRuntime(state)
    try:
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert response["ok"] is False and response["outcome"] == outcome
        assert len(response["record_ids"]) == 1 and len(response["entry_ids"]) == 1
        assert response["usage"] == {"requests": getattr(error, "requests", 0), "bytes": 0, "cost": 0}
        record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
        assert record["outcome"] == outcome and record["reason"] == reason
        assert record["content_sha256"] == "none" and record["byte_length"] == 0 and record["leads"] == []
        assert not runtime.records.blobs.digests()  # type: ignore[union-attr]
        assert len(host.calls) == 1
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


def test_slice3c2_absent_adapter_never_invokes_a_provider(tmp_path: Path) -> None:
    state = _state(tmp_path)
    request, route = _request("ingest.url", key="absent")
    runtime = CommitRuntime(state)
    try:
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=AdapterHost({}), scope=_scope())
        assert response["outcome"] == "degraded" and response["ok"] is False
        assert runtime.records.read_json(response["record_ids"][0])["reason"] == "adapter_absent"  # type: ignore[union-attr]
    finally:
        runtime.close()


# ------------------------------------------------------------- PHI scanner v2


@pytest.mark.parametrize(
    ("data", "expected"),
    (
        (b"nothing sensitive here", "clear"),
        (b"contact 123-45-6789 today", "suspected"),
        ("SSN 987-65-4321".encode("utf-8"), "suspected"),
        (b"1234-56-7890 is not an SSN", "clear"),
        (b"MRN: AB-99321", "suspected"),
        (b"Medical Record Number 77421", "suspected"),
        (b"mrn", "clear"),
        (b"\xff\xfe\x00bad", "error"),
    ),
)
def test_slice3c2_text_scanner_is_deterministic_and_local(data: bytes, expected: str) -> None:
    assert scan_text(data, "text/markdown", "ingest.url") == expected


def test_slice3c2_text_scanner_rejects_unsupported_representations() -> None:
    for media_type, operation in (("application/octet-stream", "ingest.url"), ("text/markdown", "ingest.file")):
        with pytest.raises(PhiInputError):
            scan_text(b"x", media_type, operation)
    with pytest.raises(PhiInputError):
        scan_text("text", "text/markdown", "ingest.url")  # type: ignore[arg-type]


def test_slice3c2_suspected_content_quarantines_without_persisting_raw_bytes(tmp_path: Path) -> None:
    state = _state(tmp_path)
    suspected = b"# Intake\n\nPatient SSN 123-45-6789 and MRN 4471."
    request, route = _request("ingest.url", key="phi")
    host = _faux("ingest.url", content=suspected)
    runtime = CommitRuntime(state)
    try:
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert response["ok"] is False and response["outcome"] == "refused"
        assert len(response["record_ids"]) == 1 and len(response["entry_ids"]) == 1
        record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
        assert record == {
            "schema_version": "houndd.quarantine-record.v1",
            "attempt_id": record["attempt_id"],
            "request_hash": record["request_hash"],
            "operation": "ingest.url",
            "outcome": "refused",
            "evidence_status": "refused",
            "quarantine": {"content_sha256": hashlib.sha256(suspected).hexdigest(), "byte_length": len(suspected), "reason": "phi_suspected", "access": "public"},
            "lineage": {"relation": "none", "record_id": "none", "lead_id": "none"},
        }
        assert not runtime.records.blobs.digests()  # type: ignore[union-attr]
        stored = b"".join(path.read_bytes() for path in sorted((state / "records").iterdir()))
        stored += b"".join(path.read_bytes() for path in sorted((state / "commit3c1" / "open").iterdir()))
        stored += b"".join(path.read_bytes() for path in sorted((state / "journal").rglob("*")) if path.is_file())
        assert b"123-45-6789" not in stored and suspected not in stored
        event = runtime.journal.entries()[0]  # type: ignore[union-attr]
        assert event["classification"] == {"outcome": "refused", "evidence_status": "refused"}
        assert event["artifact"]["schema"] == "houndd.quarantine-record.v1"
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


def test_slice3c2_scanner_error_stages_nothing_and_recovers_interrupted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _state(tmp_path)
    request, route = _request("ingest.search", key="scanner-error")
    monkeypatch.setattr("houndd.commit_runtime.scan_text", lambda *_: "error")
    runtime = CommitRuntime(state)
    try:
        with pytest.raises(CommitUnavailable):
            runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.search"), scope=_scope())
        assert not runtime.records.blobs.digests()  # type: ignore[union-attr]
        assert not runtime.journal.entries()  # type: ignore[union-attr]
    finally:
        runtime.close()
    monkeypatch.undo()
    recovered = CommitRuntime(state)
    try:
        assert [entry["outcome"] for entry in recovered.reconcile()] == ["interrupted"]
        replay = recovered.probe(request, route, principal=PRINCIPAL)
        assert replay.response_template is not None and replay.response_template["outcome"] == "interrupted"
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


# ------------------------------------------------------------ crash recovery


@pytest.mark.parametrize("phase", ("after_reservation", "after_open", "after_adapter", "after_plan", "after_content", "after_record", "after_journal"))
@pytest.mark.parametrize("operation", ("ingest.search", "ingest.url"))
def test_slice3c2_crash_at_every_commit_point_recovers_exactly_once(tmp_path: Path, phase: str, operation: str) -> None:
    state = _state(tmp_path)
    request, route = _request(operation, key="crash")
    invocations: list[int] = []

    def adapter(_payload: Any) -> AdapterResult:
        invocations.append(1)
        return _result(operation)

    def crash(reached: str) -> None:
        if reached == phase:
            raise RuntimeError("simulated process death")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=AdapterHost({operation: adapter}), scope=_scope())
    finally:
        runtime.close()

    if phase == "after_reservation":
        # A lone reservation is a partial pair: integrity failure, never replay.
        with pytest.raises(Exception):
            CommitRuntime(state).close()
        return

    recovered = CommitRuntime(state)
    try:
        assert len(recovered.reconcile()) == 1
        assert len(recovered.journal.entries()) == 1  # type: ignore[union-attr]
        replay = recovered.probe(request, route, principal=PRINCIPAL)
        assert replay.response_template is not None
        expected = "interrupted" if phase in {"after_open", "after_adapter", "after_plan"} else "completed"
        assert replay.response_template["outcome"] == expected
        assert len(replay.response_template["record_ids"]) == 1 and len(replay.response_template["entry_ids"]) == 1
        # Recovery never re-invokes the adapter.
        assert len(invocations) == (0 if phase == "after_open" else 1)
        assert recovered.reconcile() == [] and len(recovered.journal.entries()) == 1  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


def test_slice3c2_interrupted_recovery_publishes_no_content_blob(tmp_path: Path) -> None:
    state = _state(tmp_path)
    request, route = _request("ingest.url", key="open-crash")

    def crash(reached: str) -> None:
        if reached == "after_plan":
            raise RuntimeError("simulated process death")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.url"), scope=_scope())
    finally:
        runtime.close()
    recovered = CommitRuntime(state)
    try:
        recovered.reconcile()
        record = recovered.records.read_json(recovered.journal.entries()[0]["artifact"]["record_id"])  # type: ignore[union-attr]
        assert record["outcome"] == "interrupted" and record["evidence_status"] == "interrupted"
        assert record["reason"] == "interrupted" and record["content_sha256"] == "none"
        assert not recovered.records.blobs.digests()  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


# ------------------------------------------------------------------- lineage


def test_slice3c2_url_lineage_binds_only_an_authorized_search_record(tmp_path: Path) -> None:
    state = _state(tmp_path)
    search_request, search_route = _request("ingest.search", key="parent")
    runtime = CommitRuntime(state)
    try:
        search = runtime.execute_adapter(search_request, search_route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.search"), scope=_scope())
        parent = search["record_ids"][0]

        direct, url_route = _request("ingest.url", key="direct")
        first = runtime.execute_adapter(direct, url_route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.url"), scope=_scope())
        assert runtime.records.read_json(first["record_ids"][0])["lineage"] == {"relation": "none", "record_id": "none", "lead_id": "none"}  # type: ignore[union-attr]

        bound, _ = _request("ingest.url", key="bound", payload={"url": "https://example.test/a", "lineage": {"kind": "search", "record_id": parent, "lead_id": "exa-1"}})
        second = runtime.execute_adapter(bound, url_route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.url"), scope=_scope())
        record = runtime.records.read_json(second["record_ids"][0])  # type: ignore[union-attr]
        assert record["lineage"] == {"relation": "search", "record_id": parent, "lead_id": "exa-1"}
        assert runtime.journal.get(second["entry_ids"][0])["lineage"] == record["lineage"]  # type: ignore[union-attr]

        unknown, _ = _request("ingest.url", key="unknown", payload={"url": "https://example.test/a", "lineage": {"kind": "search", "record_id": "f" * 64, "lead_id": "exa-1"}})
        with pytest.raises(CommitRefusal):
            runtime.execute_adapter(unknown, url_route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.url"), scope=_scope())

        unscoped, _ = _request("ingest.url", key="unscoped", payload={"url": "https://example.test/a", "lineage": {"kind": "search", "record_id": parent, "lead_id": "exa-1"}})
        with pytest.raises(CommitRefusal):
            runtime.execute_adapter(unscoped, url_route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.url"), scope=None)

        assert len(runtime.journal.entries()) == 3  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


# ------------------------------------------------------------------ payloads


def test_slice3c2_routes_are_available_and_payloads_are_strict() -> None:
    assert {binding.operation for binding in AVAILABLE_ROUTE_BINDINGS} >= {"ingest.search", "ingest.url"}
    for payload in (
        {"query": "x"},
        {"query": "x", "limit": 0},
        {"query": "x", "limit": 51},
        {"query": "x", "limit": True},
        {"query": "", "limit": 5},
        {"query": "x", "limit": 5, "extra": 1},
    ):
        with pytest.raises((CommitContractError, TypeError)):
            _request("ingest.search", key="k", payload=payload)
    for payload in (
        {"url": "https://example.test/a"},
        {"url": "http://127.0.0.1/a", "lineage": {"kind": "direct"}},
        {"url": "file:///etc/passwd", "lineage": {"kind": "direct"}},
        {"url": "https://example.test/a", "lineage": {"kind": "other"}},
        {"url": "https://example.test/a", "lineage": {"kind": "search", "record_id": "short", "lead_id": "l"}},
        {"url": "https://example.test/a", "lineage": {"kind": "direct"}, "max_pages": 1},
        {"url": "https://example.test/a", "lineage": {"kind": "direct"}, "max_pages": 21},
    ):
        with pytest.raises((CommitContractError, TypeError)):
            _request("ingest.url", key="k", payload=payload)
    request, route = _request("ingest.url", key="k", payload={"url": "https://example.test/a", "lineage": {"kind": "direct"}, "max_pages": 3})
    assert request.source is None
    assert request.canonical_dict(route)["operation"]["payload"] == {"url": "https://example.test/a", "lineage": {"kind": "direct"}, "max_pages": 3}


def test_slice3c2_request_identity_excludes_only_request_and_key_ids() -> None:
    first, route = _request("ingest.search", key="a", request_id="one")
    second, _ = _request("ingest.search", key="b", request_id="two")
    changed, _ = _request("ingest.search", key="a", request_id="one", payload={"query": "caregiver respite", "limit": 6})
    assert first.request_hash(route) == second.request_hash(route)
    assert first.request_hash(route) != changed.request_hash(route)


# -------------------------------------------------------------- adapter host


def test_slice3c2_host_binds_only_provisioned_credentials_and_refuses_selection() -> None:
    def transport(**_call: object) -> tuple[int, bytes]:
        pytest.fail("adapter-host binding tests must not open a provider connection")

    assert AdapterHost.from_env({}, transport=transport).operations == frozenset()
    assert AdapterHost.from_env({"EXA_API_KEY": "k"}, transport=transport).operations == frozenset({"ingest.search"})
    assert AdapterHost.from_env({"FIRECRAWL_API_KEY": "k"}, transport=transport).operations == frozenset({"ingest.url"})
    assert ADAPTER_ENV_KEYS == ("EXA_API_KEY", "FIRECRAWL_API_KEY", "FIRECRAWL_ENDPOINT")
    with pytest.raises(AdapterHostError):
        AdapterHost({"ingest.file": lambda _payload: _result("ingest.search")})
    with pytest.raises(AdapterUnavailable):
        AdapterHost({}).invoke("ingest.search", {"query": "x", "limit": 1})
    with pytest.raises(AdapterFailed):
        AdapterHost({"ingest.url": lambda _payload: _result("ingest.search")}).invoke("ingest.url", {"url": "https://example.test/a"})


def test_slice3c2_injected_exa_transport_failure_is_one_failed_outcome(tmp_path: Path) -> None:
    """A fake transport proves the production Exa binding cannot use the internet."""

    state = _state(tmp_path)
    request, route = _request("ingest.search", key="transport")
    calls: list[dict[str, object]] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(call)
        return 503, b'{"error":"unavailable"}'

    runtime = CommitRuntime(state)
    try:
        host = AdapterHost.from_env({"EXA_API_KEY": "test-key"}, transport=transport)
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert response["ok"] is False and response["outcome"] == "failed"
        assert response["usage"]["requests"] == 1
        assert len(calls) == 1
        assert runtime.records.read_json(response["record_ids"][0])["reason"] == "provider_failed"  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


# ------------------------------------------------------------------- service


@pytest.mark.parametrize("clear_manifest", (False, True))
def test_slice3c2_service_dispatches_both_routes_with_or_without_a_clear_manifest(tmp_path: Path, clear_manifest: bool) -> None:
    state = _state(tmp_path, clear_manifest=clear_manifest)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    host = AdapterHost({"ingest.search": lambda _payload: _result("ingest.search"), "ingest.url": lambda _payload: _result("ingest.url")})
    service = HounddService(state_root=state, socket_path=runtime_dir / "houndd.sock", adapter_host=host)
    principal = AuthenticatedPrincipal(PRINCIPAL)
    try:
        search = service._dispatch(principal, _frame(operation="ingest.search", key="s", request_id="one"))
        assert search["status"] == 200 and search["body"]["ok"] is True
        url = service._dispatch(principal, _frame(operation="ingest.url", key="u", request_id="two"))
        assert url["status"] == 200 and url["body"]["ok"] is True
        replay = service._dispatch(principal, _frame(operation="ingest.search", key="s", request_id="three"))
        assert replay["body"]["record_ids"] == search["body"]["record_ids"]
        assert len(service.store.journal.entries()) == 2  # type: ignore[union-attr]
    finally:
        service.close()


def test_slice3c2_service_maps_degraded_and_unresolved_lineage(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime_dir / "houndd.sock", adapter_host=AdapterHost({}))
    principal = AuthenticatedPrincipal(PRINCIPAL)
    try:
        degraded = service._dispatch(principal, _frame(operation="ingest.search", key="d", request_id="one"))
        assert degraded["status"] == 200 and degraded["body"]["ok"] is False and degraded["body"]["outcome"] == "degraded"
        refused = service._dispatch(principal, _frame(operation="ingest.url", key="l", request_id="two", payload={"url": "https://example.test/a", "lineage": {"kind": "search", "record_id": "e" * 64, "lead_id": "x"}}))
        assert refused["status"] == 400 and refused["body"]["error"]["code"] == "invalid_request"
        assert refused["body"]["record_ids"] == [] and refused["body"]["entry_ids"] == []
        assert len(service.store.journal.entries()) == 1  # type: ignore[union-attr]
    finally:
        service.close()


def test_slice3c2_service_freezes_provider_credentials_at_startup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = _state(tmp_path)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    for key in ADAPTER_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    service = HounddService(state_root=state, socket_path=runtime_dir / "houndd.sock")
    try:
        assert service.adapter_host.operations == frozenset()
        monkeypatch.setenv("EXA_API_KEY", "late")
        assert service.adapter_host.operations == frozenset()
        degraded = service._dispatch(AuthenticatedPrincipal(PRINCIPAL), _frame(operation="ingest.search", key="frozen", request_id="one"))
        assert degraded["body"]["outcome"] == "degraded"
    finally:
        service.close()


def test_slice3c2_real_process_kill_recovers_one_outcome_without_reinvoking(tmp_path: Path) -> None:
    """A genuine process death leaves recoverable on-disk state, not a rerun."""

    state = _state(tmp_path)
    marker = tmp_path / "invocations"
    script = f"""
import os, sys
sys.path.insert(0, {str(Path(__file__).parents[1] / "src")!r})
sys.path.insert(0, {str(Path(__file__).parent)!r})
from houndd.adapter_host import AdapterHost, AdapterResult
from houndd.commit_runtime import CommitRuntime
from test_slice3c2_adapter_commit import PRINCIPAL, SEARCH_CONTENT, LEADS, _request, _scope

def adapter(payload):
    open({str(marker)!r}, "a").write("x")
    return AdapterResult("ingest.search", "completed", SEARCH_CONTENT, "application/json", "2026-08-03T00:00:00Z", 1, 0, LEADS)

request, route = _request("ingest.search", key="kill")
runtime = CommitRuntime({str(state)!r}, fault_hook=lambda phase: os._exit(9) if phase == "after_content" else None)
runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=AdapterHost({{"ingest.search": adapter}}), scope=_scope())
"""
    killed = subprocess.run([sys.executable, "-c", script], capture_output=True)
    assert killed.returncode == 9, killed.stderr.decode()
    assert marker.read_text() == "x"

    request, route = _request("ingest.search", key="kill")
    recovered = CommitRuntime(state)
    try:
        assert [entry["outcome"] for entry in recovered.reconcile()] == ["completed"]
        replay = recovered.probe(request, route, principal=PRINCIPAL)
        assert replay.response_template is not None and replay.response_template["outcome"] == "completed"
        assert marker.read_text() == "x"
        assert len(recovered.journal.entries()) == 1  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


def test_slice3c2_verifier_rejects_semantically_malformed_adapter_outcome(tmp_path: Path) -> None:
    """The journal can be byte-valid while an adapter record is not meaningful."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        record = {
            "schema_version": "houndd.search-record.v1",
            "attempt_id": "a" * 64,
            "request_hash": "b" * 64,
            "operation": "ingest.search",
            "outcome": "failed",
            "evidence_status": "failure",
            "reason": "not-an-allowed-reason",
            "provider": "exa",
            "retrieved_at": "",
            "query": 7,
            "limit": -1,
            "leads": [],
            "content_sha256": "none",
            "byte_length": 0,
            "lineage": {"relation": "none", "record_id": "none", "lead_id": "none"},
        }
        stored = runtime.records.put_json(record)  # type: ignore[union-attr]
        runtime.journal.append(  # type: ignore[union-attr]
            make_journal_envelope(
                sequence=0,
                appended_at="2026-08-03T00:00:00Z",
                producer={"owner_id": "writer", "capability": "ingest.search", "run_id": "run"},
                artifact={"kind": "search", "schema": "houndd.search-record.v1", "record_id": stored.record_id, "hash": stored.record_id, "authorized_uri": f"houndd://record/{stored.record_id}"},
                lineage=record["lineage"],
                source={"provider": "exa", "native_id": stored.record_id, "canonical_url": "none"},
                classification={"outcome": "failed", "evidence_status": "failure"},
                access="public",
                policy_id="write-policy",
                dedupe={"object_key": f"search-outcome:{stored.record_id}", "content_sha256": stored.record_id},
                usage={"requests": 1, "bytes": 0, "cost": 0},
            )
        )
    finally:
        runtime.close()

    assert verify_store(state, projection=False)["valid"] is False


@pytest.mark.parametrize(
    "mutate",
    (
        lambda record, _event: record.update({"reason": "provider_failed"}),
        lambda record, _event: record.update({"retrieved_at": "not-a-timestamp"}),
        lambda record, _event: record.update({"query": 7}),
        lambda record, _event: record.update({"limit": True}),
        lambda record, _event: record["leads"][0].update({"unexpected": "field"}),
        lambda record, _event: record.update({"document": {}}),
        lambda record, _event: record.update({"content_sha256": "A" * 64}),
        lambda _record, event: event["usage"].update({"requests": True}),
        lambda _record, event: event["source"].update({"provider": "other"}),
    ),
)
def test_slice3c2_shared_validator_closes_semantic_record_and_journal_fields(
    tmp_path: Path,
    mutate: Any,
) -> None:
    """Commit and verify use the same closed validator for every durable field."""

    state = _state(tmp_path)
    request, route = _request("ingest.search", key="strict-fields")
    runtime = CommitRuntime(state)
    try:
        response = runtime.execute_adapter(
            request,
            route,
            principal=PRINCIPAL,
            access="public",
            adapter_host=_faux("ingest.search"),
            scope=_scope(),
        )
        record_id = response["record_ids"][0]
        record = runtime.records.read_json(record_id)  # type: ignore[union-attr]
        event = runtime.journal.entries()[0]  # type: ignore[union-attr]
    finally:
        runtime.close()

    validate_adapter_outcome(record, event, record_id=record_id)
    malformed_record = deepcopy(record)
    malformed_event = deepcopy(event)
    mutate(malformed_record, malformed_event)
    with pytest.raises(AdapterOutcomeError):
        validate_adapter_outcome(malformed_record, malformed_event, record_id=record_id)


def test_no_test_constructs_a_live_provider_client_without_an_injected_transport() -> None:
    """Keep the focused and full suite offline even if a fixture is removed."""

    provider_calls = {
        "hound_web_adapters.exa.search",
        "hound_web_adapters.firecrawl.extract",
        "hound_web_adapters.camofox.interact",
    }

    def name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = name(node.value)
            return f"{parent}.{node.attr}" if parent is not None else None
        return None

    def imported_names(tree: ast.Module) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname is not None:
                        aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                for alias in node.names:
                    local = alias.asname or alias.name
                    aliases[local] = f"{node.module}.{alias.name}"
        return aliases

    violations: list[str] = []
    for path in Path(__file__).parent.rglob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases = imported_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = name(node.func)
            if function is None:
                continue
            head, *tail = function.split(".", 1)
            function = ".".join((aliases.get(head, head), *tail))
            keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg is not None}
            if function in provider_calls:
                transport = keywords.get("transport")
                transport_name = name(transport) if transport is not None else None
                if transport is None or transport_name in {"request", "_http.request", "hound_web_adapters._http.request"}:
                    violations.append(f"{path.name}:{node.lineno} {function}")
            if function == "houndd.adapter_host.AdapterHost.from_env":
                transport = keywords.get("transport")
                transport_name = name(transport) if transport is not None else None
                if transport is None or transport_name in {"request", "_http.request", "hound_web_adapters._http.request"}:
                    violations.append(f"{path.name}:{node.lineno} {function}")
    assert violations == []


@pytest.mark.parametrize("operation", ("ingest.search", "ingest.url"))
def test_slice3c2_verifier_rejects_duplicate_and_relabelled_adapter_events(tmp_path: Path, operation: str) -> None:
    state = _state(tmp_path)
    request, route = _request(operation, key="verify")
    runtime = CommitRuntime(state)
    try:
        runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_faux(operation), scope=_scope())
        original = runtime.journal.entries()[0]  # type: ignore[union-attr]
        runtime.journal.append(make_journal_envelope(  # type: ignore[union-attr]
            sequence=1,
            appended_at="2026-08-03T00:00:01Z",
            producer=original["producer"],
            artifact={**original["artifact"], "schema": "houndd.quarantine-record.v1"},
            lineage=original["lineage"],
            source=original["source"],
            classification=original["classification"],
            access=original["access"],
            policy_id=original["policy_id"],
            dedupe=original["dedupe"],
            usage=original["usage"],
        ))
    finally:
        runtime.close()
    report = verify_store(state, projection=False)
    assert report["valid"] is False
    assert any("schema does not bind" in failure for failure in report["failures"])


def test_slice3c2_tampered_open_placeholder_never_becomes_the_replayed_answer(tmp_path: Path) -> None:
    """The open-phase reservation template is discarded, never honoured."""

    state = _state(tmp_path)
    request, route = _request("ingest.search", key="tamper")

    def crash(reached: str) -> None:
        if reached == "after_open":
            raise RuntimeError("simulated process death")

    runtime = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.search"), scope=_scope())
    finally:
        runtime.close()

    name = next(iter((state / "commit3c1" / "reservations").iterdir()))
    reservation = json.loads(name.read_bytes())
    reservation["response"] = {"ok": True, "outcome": "completed", "record_ids": ["f" * 64], "entry_ids": ["e" * 64], "usage": {"requests": 9, "bytes": 9, "cost": 9}}
    name.write_bytes(canonical_bytes(reservation))

    recovered = CommitRuntime(state)
    try:
        assert [entry["outcome"] for entry in recovered.reconcile()] == ["interrupted"]
        replay = recovered.probe(request, route, principal=PRINCIPAL)
        assert replay.response_template is not None
        assert replay.response_template["outcome"] == "interrupted" and replay.response_template["record_ids"] != ["f" * 64]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


def test_slice3c2_verifier_rejects_a_staged_record_without_its_blob(tmp_path: Path) -> None:
    state = _state(tmp_path)
    request, route = _request("ingest.search", key="blobless")
    runtime = CommitRuntime(state)
    try:
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.search"), scope=_scope())
        digest = runtime.records.read_json(response["record_ids"][0])["content_sha256"]  # type: ignore[union-attr]
    finally:
        runtime.close()
    (state / "blobs" / digest).unlink()
    report = verify_store(state, projection=False)
    assert report["valid"] is False
    assert any("journal artifact verification" in failure for failure in report["failures"])


def test_slice3c2_journal_query_projects_adapter_rows(tmp_path: Path) -> None:
    state = _state(tmp_path)
    request, route = _request("ingest.search", key="projected")
    runtime = CommitRuntime(state)
    try:
        runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_faux("ingest.search"), scope=_scope())
    finally:
        runtime.close()
    store = HounddStore(state)
    try:
        store.rebuild_index()
        assert verify_store(state)["valid"] is True
    finally:
        store.close()
