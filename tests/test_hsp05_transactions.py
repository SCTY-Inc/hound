"""HSP-05: atomic/idempotent transaction and crash-recovery evidence."""

from __future__ import annotations

import json
import pytest
import os
import subprocess
import sys
from pathlib import Path

from houndd import (
    FAULT_AFTER_JOURNAL,
    FAULT_AFTER_PROVIDER,
    FAULT_AFTER_RECORD,
    FAULT_BEFORE_PROVIDER,
    canonical_hash,
    HounddStore,
    IdempotencyConflict,
    InjectedCrash,
    TransactionError,
)


def _request(*, request_id: str = "request", key: str = "key", value: str = "x") -> dict[str, object]:
    return {
        "schema_version": "houndd.request.v1",
        "request_id": request_id,
        "idempotency_key": key,
        "producer": {"owner_id": "owner", "capability": "capture", "run_id": "run"},
        "requested_access": "workspace",
        "policy_id": "policy",
        "operation": {"name": "capture", "payload": {"value": value}},
    }


@pytest.mark.parametrize("fault", [FAULT_BEFORE_PROVIDER, FAULT_AFTER_PROVIDER, FAULT_AFTER_RECORD, FAULT_AFTER_JOURNAL])
def test_hsp05_process_kill_equivalent_crash_points_recover_one_durable_commit(tmp_path, fault: str) -> None:
    store = HounddStore(tmp_path / "store")
    request = _request()
    transaction = store.begin(request, principal="peer:one", capability="capture")
    with pytest.raises(InjectedCrash):
        transaction.commit(record={"schema_version": "houndd.capture.v1", "value": "x"}, blob=b"same", fault=fault)

    recovered = store.recover()
    assert len(recovered) == 1
    assert len(store.journal.entries()) == 1
    response = recovered[0]
    assert response["record_ids"] and response["entry_ids"]
    assert response["outcome"] == ("interrupted" if fault == FAULT_BEFORE_PROVIDER else "completed")
    retry = store.begin(request, principal="peer:one", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "different"}, blob=b"different"
    )
    assert retry == response
    assert store.verify()["valid"] is True


@pytest.mark.parametrize("fault", [FAULT_BEFORE_PROVIDER, FAULT_AFTER_PROVIDER, FAULT_AFTER_RECORD, FAULT_AFTER_JOURNAL])
def test_hsp05_real_process_kill_recovers_once_and_preserves_retry_identity(tmp_path, fault: str) -> None:
    root = tmp_path / "killed-store"
    request = _request()
    child = """
import os
import sys
from houndd import HounddStore, InjectedCrash

root, fault = sys.argv[1:]
request = {
    "schema_version": "houndd.request.v1",
    "request_id": "request",
    "idempotency_key": "key",
    "producer": {"owner_id": "owner", "capability": "capture", "run_id": "run"},
    "requested_access": "workspace",
    "policy_id": "policy",
    "operation": {"name": "capture", "payload": {"value": "x"}},
}
try:
    HounddStore(root).begin(request, principal="peer:one", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "x"}, blob=b"same", fault=fault
    )
except InjectedCrash:
    os._exit(90)
os._exit(2)
"""
    environment = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
    killed = subprocess.run(
        [sys.executable, "-c", child, str(root), fault],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert killed.returncode == 90

    recovered_store = HounddStore(root)
    recovered = recovered_store.recover()
    assert len(recovered) == 1
    assert len(recovered_store.records.record_ids()) == 1
    assert len(recovered_store.journal.entries()) == 1
    retry = recovered_store.begin(request, principal="peer:one", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "different"}, blob=b"different"
    )
    assert retry == recovered[0]
    assert recovered_store.verify()["valid"] is True


def test_hsp05_failures_are_records_and_key_collision_fails_closed(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    request = _request(key="failure")
    response = store.begin(request, principal="peer:one", capability="capture").commit(
        outcome="failed", evidence_status="failure", record={"schema_version": "houndd.failure.v1", "code": "timeout"}
    )
    assert response["ok"] is False
    assert response["outcome"] == "failed"
    assert response["record_ids"] and response["entry_ids"]
    with pytest.raises(IdempotencyConflict):
        store.begin(_request(key="failure", value="changed"), principal="peer:one", capability="capture")


def test_hsp05_idempotency_replay_tamper_matrix_fails_closed(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    request = _request(key="matrix")
    expected = store.begin(request, principal="peer:one", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "x"}, blob=b"same"
    )
    stage_file = next((store.root / "transactions" / "stages").glob("*.json"))
    idempotency_file = next((store.root / "transactions" / "idempotency").glob("*.json"))
    original_stage = stage_file.read_text(encoding="utf-8")
    original_idempotency = idempotency_file.read_text(encoding="utf-8")

    cases = [
        (
            "forged_response",
            lambda stage, idempotency: (
                idempotency["response"].__setitem__("entry_ids", ["forged-entry"]),
                idempotency["response"].__setitem__("record_ids", ["forged-record"]),
            ),
        ),
        (
            "scope_fields",
            lambda stage, idempotency: idempotency.__setitem__("principal", "forged-principal"),
        ),
        (
            "transaction_id",
            lambda stage, idempotency: stage.__setitem__("transaction_id", "forged-transaction"),
        ),
        (
            "stage_envelope",
            lambda stage, idempotency: (
                stage["envelope"]["classification"].__setitem__("outcome", "failed"),
                stage["envelope"].__setitem__(
                    "entry_id",
                    canonical_hash({key: value for key, value in stage["envelope"].items() if key != "entry_id"}),
                ),
            ),
        ),
        (
            "missing_counterpart",
            lambda stage, idempotency: idempotency_file.unlink(),
        ),
    ]

    for _, mutate in cases:
        stage_file.write_text(original_stage, encoding="utf-8")
        stage_file.chmod(0o600)
        idempotency_file.write_text(original_idempotency, encoding="utf-8")
        idempotency_file.chmod(0o600)
        stage = json.loads(stage_file.read_text(encoding="utf-8"))
        idempotency = json.loads(idempotency_file.read_text(encoding="utf-8"))
        mutate(stage, idempotency)
        if stage_file.exists():
            stage_file.write_text(json.dumps(stage), encoding="utf-8")
            stage_file.chmod(0o600)
        if idempotency_file.exists():
            idempotency_file.write_text(json.dumps(idempotency), encoding="utf-8")
            idempotency_file.chmod(0o600)
        with pytest.raises(TransactionError):
            store.begin(request, principal="peer:one", capability="capture").commit(
                record={"schema_version": "houndd.capture.v1", "value": "retry"}, blob=b"retry"
            )
        assert store.verify()["valid"] is False

    stage_file.write_text(original_stage, encoding="utf-8")
    stage_file.chmod(0o600)
    idempotency_file.write_text(original_idempotency, encoding="utf-8")
    idempotency_file.chmod(0o600)
    assert store.begin(request, principal="peer:one", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "x"}, blob=b"same"
    ) == expected


@pytest.mark.parametrize(
    ("outcome", "diagnostic"),
    [
        ("failed", {"error_kind": "http", "http_status": 429}),
        ("failed", {"error_kind": "timeout", "elapsed_seconds": 30}),
        ("partial", {"error_kind": "truncated", "received_bytes": 5, "expected_bytes": 10}),
        ("partial", {"error_kind": "partial", "received_bytes": 5}),
        ("refused", {"error_kind": "policy_refusal"}),
        ("interrupted", {"error_kind": "process_interrupted"}),
    ],
)
def test_hsp05_provider_failure_matrix_is_explicit_and_durable(tmp_path, outcome: str, diagnostic: dict[str, object]) -> None:
    store = HounddStore(tmp_path / outcome)
    key = f"{outcome}-{diagnostic['error_kind']}"
    response = store.begin(_request(key=key), principal="peer:one", capability="capture").commit(
        outcome=outcome,
        evidence_status="failure" if outcome in {"failed", "refused", "interrupted"} else "partial",
        record={"schema_version": "houndd.failure.v1", "provider_outcome": outcome, "diagnostic": diagnostic},
    )
    assert response["ok"] is False
    assert response["outcome"] == outcome
    assert len(store.journal.entries()) == 1
    assert store.records.read_json(response["record_ids"][0])["payload"]["diagnostic"] == diagnostic
    store.rebuild_index()
    assert store.verify()["valid"] is True


@pytest.mark.parametrize("head_state", ["missing", "stale"])
def test_hsp05_missing_or_stale_head_reconciles_without_verify_repair(tmp_path, head_state: str) -> None:
    store = HounddStore(tmp_path / "store")
    response = store.begin(_request(key=head_state), principal="peer:one", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "x"}, blob=b"same"
    )
    head_path = store.journal.head_path
    original_head = json.loads(head_path.read_text(encoding="utf-8"))
    if head_state == "missing":
        head_path.unlink()
    else:
        original_head["sequence"] = 99
        head_path.write_text(json.dumps(original_head), encoding="utf-8")

    assert store.verify()["valid"] is False
    if head_state == "missing":
        assert not head_path.exists()
    else:
        assert head_path.exists()

    recovered = store.recover()
    assert recovered == []
    assert store.journal.entries()[0]["entry_id"] == response["entry_ids"][0]
    assert store.verify()["valid"] is True


def test_hsp05_idempotency_scope_uses_authenticated_principal_not_request_owner(tmp_path) -> None:
    store = HounddStore(tmp_path / "store")
    request = _request()
    first = store.begin(request, principal="transport:actual", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "x"}, blob=b"x"
    )
    second = store.begin({**request, "request_id": "retry"}, principal="transport:actual", capability="capture").commit(
        record={"schema_version": "houndd.capture.v1", "value": "forged-owner"}, blob=b"other"
    )
    assert second == first
