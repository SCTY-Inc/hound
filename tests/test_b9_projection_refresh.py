"""GOALIE B9: the disposable index refreshes inside the durable commit path.

The journal stays the sole canonical truth.  These tests pin three separable
claims: an index-backed read sees a commit with no restart, a refresh that
fails never damages a commit whose event is already durable, and a crash in
the append-then-refresh window recovers through the existing reconcile path.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

from houndd import HounddStore
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.commit import normalize_source, parse_commit_request, resolve_route
from houndd.commit_runtime import CommitRuntime
from houndd.contracts import canonical_bytes
from houndd.projection import Projection, ProjectionError
from houndd.verify import verify_store


PRINCIPAL = f"linux-uid:{os.getuid()}"
DATA = b"b9 certified source"


def _policy() -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [{
            "subject": PRINCIPAL,
            "claim_selector": {"owner_id": "writer", "capability": "ingest.file", "run_id": None},
            "policy_id": "write-policy",
            "event_producer_selectors": [{"owner_id": "writer", "capability": "ingest.file", "run_id": None}],
            "readable_tiers": ["public"],
            "allowed_output_tiers": ["public"],
        }],
    }


def _state(tmp_path: Path, data: bytes = DATA) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    HounddStore(root).close()
    service = root / "service"
    service.mkdir(mode=0o700)
    (service / "policy.json").write_bytes(canonical_bytes(_policy()))
    (service / "policy.json").chmod(0o600)
    (service / "phi-clear.json").write_bytes(canonical_bytes({
        "schema_version": "houndd.phi-clear.v1",
        "entries": [{"sha256": hashlib.sha256(data).hexdigest(), "media_type": "application/octet-stream", "encoding": "identity"}],
    }))
    (service / "phi-clear.json").chmod(0o600)
    return root


def _scope() -> PrincipalScope:
    tiers = frozenset({"public"})
    return PrincipalScope(
        principal=AuthenticatedPrincipal(PRINCIPAL),
        readable_tiers=tiers,
        permitted_event_selectors=(EventSelector("write-policy", ProducerSelector("writer", "ingest.file", None), tiers),),
    )


def _request(key: str, request_id: str, data: bytes = DATA):
    """Return one parsed ingest.file commit request plus its route."""

    route = resolve_route("POST", "/v1/ingest/file", require_available=True)
    body = {
        "schema_version": "houndd.commit-request.v1",
        "request_id": request_id,
        "idempotency_key": key,
        "producer": {"owner_id": "writer", "capability": "ingest.file", "run_id": "run"},
        "requested_access": "public",
        "policy_id": "write-policy",
        "operation": {"name": "ingest.file", "payload": {
            "media_type": "application/octet-stream",
            "source": {
                "kind": "bytes",
                "body_base64": base64.b64encode(data).decode("ascii"),
                "sha256": hashlib.sha256(data).hexdigest(),
                "byte_length": len(data),
            },
        }},
    }
    return parse_commit_request(body, route), route


def _commit(runtime: CommitRuntime, key: str, request_id: str, data: bytes = DATA) -> dict[str, object]:
    request, route = _request(key, request_id, data)
    source = normalize_source(request.source.to_wire())
    return runtime.execute(request, route, principal=PRINCIPAL, access="public", source=source, scanner_clear=True, scope=_scope())


def _index_entry_ids(root: Path) -> list[str]:
    with Projection(root) as projection:
        return [row["entry_id"] for row in projection.rows()]


def test_b9_commit_is_visible_to_the_index_without_a_restart(tmp_path: Path) -> None:
    """Contract: the index sees a commit with no recovery and no rebuild call."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        first = _commit(runtime, "b9-one", "one")
        assert _index_entry_ids(state) == first["entry_ids"]
        assert verify_store(state)["valid"] is True

        second = _commit(runtime, "b9-two", "two", data=b"b9 second source")
        assert _index_entry_ids(state) == first["entry_ids"] + second["entry_ids"]
        assert verify_store(state)["valid"] is True
    finally:
        runtime.close()


def test_b9_replayed_commit_leaves_the_index_correct(tmp_path: Path) -> None:
    """A replay publishes nothing new, so the index must not gain a row."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        first = _commit(runtime, "b9-replay", "one")
        replayed = _commit(runtime, "b9-replay", "one")
        assert replayed["entry_ids"] == first["entry_ids"]
        assert _index_entry_ids(state) == first["entry_ids"]
        assert verify_store(state)["valid"] is True
    finally:
        runtime.close()


def test_b9_adapter_commit_is_visible_to_the_index_without_a_restart(tmp_path: Path) -> None:
    """The adapter commit path shares the one refresh seam."""

    from houndd.adapter_host import AdapterHost, AdapterResult
    from tests import test_slice3c2_adapter_commit as slice3c2

    state = slice3c2._state(tmp_path)
    request, route = slice3c2._request("ingest.search", key="b9-adapter")
    host = AdapterHost({"ingest.search": lambda payload: AdapterResult(
        "ingest.search", "completed", slice3c2.SEARCH_CONTENT, "application/json", "2026-08-03T00:00:00Z", 1, 0, slice3c2.LEADS,
    )})
    runtime = CommitRuntime(state)
    try:
        response = runtime.execute_adapter(request, route, principal=slice3c2.PRINCIPAL, access="public", adapter_host=host, scope=slice3c2._scope())
        assert _index_entry_ids(state) == response["entry_ids"]
        assert verify_store(state)["valid"] is True
    finally:
        runtime.close()


def test_b9_refresh_failure_never_fails_the_committed_event(tmp_path: Path) -> None:
    """The projection is disposable: its failure cannot break a durable commit."""

    state = _state(tmp_path)
    calls: list[str] = []

    def broken(self: Projection, journal: object, records: object, **_: object) -> dict[str, object]:
        calls.append("attempted")
        raise ProjectionError("simulated projection failure")

    runtime = CommitRuntime(state)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(Projection, "rebuild", broken)
            response = _commit(runtime, "b9-broken", "one")
        assert calls == ["attempted"]
        assert response["ok"] is True
        assert [entry["entry_id"] for entry in runtime.journal.entries()] == response["entry_ids"]  # type: ignore[union-attr]
        assert verify_store(state, projection=False)["valid"] is True
        assert _index_entry_ids(state) == []

        # The failure latches nothing: the next commit refreshes the whole index.
        second = _commit(runtime, "b9-recovered", "two", data=b"b9 after failure")
        assert _index_entry_ids(state) == response["entry_ids"] + second["entry_ids"]
        assert verify_store(state)["valid"] is True
    finally:
        runtime.close()


def test_b9_crash_between_journal_append_and_refresh_recovers(tmp_path: Path) -> None:
    """A real process death in the refresh window leaves a recoverable store."""

    state = _state(tmp_path)
    script = f"""
import os, sys
sys.path.insert(0, {str(Path(__file__).parents[1] / "src")!r})
sys.path.insert(0, {str(Path(__file__).parent)!r})
from houndd.commit_runtime import CommitRuntime
from test_b9_projection_refresh import _commit

runtime = CommitRuntime({str(state)!r}, fault_hook=lambda phase: os._exit(9) if phase == "after_journal" else None)
_commit(runtime, "b9-crash", "one")
"""
    killed = subprocess.run([sys.executable, "-c", script], capture_output=True)
    assert killed.returncode == 9, killed.stderr.decode()

    # The journal already holds the event; only the disposable index lags.
    assert verify_store(state, projection=False)["valid"] is True
    assert _index_entry_ids(state) == []

    recovered = CommitRuntime(state)
    try:
        assert [entry["outcome"] for entry in recovered.reconcile()] == ["completed"]
        entry_ids = [entry["entry_id"] for entry in recovered.journal.entries()]  # type: ignore[union-attr]
        assert _index_entry_ids(state) == entry_ids
        assert verify_store(state)["valid"] is True
    finally:
        recovered.close()
