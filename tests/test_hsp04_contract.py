"""HSP-04: canonical envelope and journal omission evidence."""

from __future__ import annotations

import pytest

from houndd import (
    ContractError,
    canonical_hash,
    canonical_json,
    make_journal_envelope,
    validate_journal_envelope,
    validate_request,
)


def _journal(kind: str = "capture", outcome: str = "completed") -> dict[str, object]:
    return make_journal_envelope(
        sequence=0,
        appended_at="2026-07-31T00:00:00Z",
        producer={"owner_id": "owner", "capability": "capture", "run_id": "run"},
        artifact={
            "kind": kind,
            "schema": f"houndd.{kind}.v1",
            "record_id": "a" * 64,
            "hash": "b" * 64,
            "authorized_uri": "houndd://records/a",
        },
        lineage={"relation": "none", "record_id": "a" * 64, "lead_id": "none"},
        source={"provider": "provider", "native_id": "native", "canonical_url": "https://example.test/a"},
        classification={"outcome": outcome, "evidence_status": "evidence" if outcome == "completed" else "failure"},
        access="public",
        policy_id="policy",
        dedupe={"object_key": "object", "content_sha256": "c" * 64},
        usage={"requests": 1, "bytes": 12, "cost": None, "provider_units": 99},
    )


def test_hsp04_canonical_json_and_journal_field_set_are_path_independent() -> None:
    left = {"z": [2, 1], "a": {"b": True, "a": "é"}}
    right = {"a": {"a": "é", "b": True}, "z": [2, 1]}
    assert canonical_json(left) == canonical_json(right)
    assert canonical_hash(left) == canonical_hash(right)

    envelope = _journal()
    assert set(envelope) == {
        "schema_version", "entry_id", "sequence", "appended_at", "producer",
        "artifact", "lineage", "source", "classification", "access", "policy_id", "dedupe", "usage",
    }
    assert set(envelope["artifact"]) == {"kind", "schema", "record_id", "hash", "authorized_uri"}
    assert set(envelope["lineage"]) == {"relation", "record_id", "lead_id"}
    assert set(envelope["source"]) == {"provider", "native_id", "canonical_url"}
    assert set(envelope["usage"]) == {"requests", "bytes"}
    assert validate_journal_envelope(envelope) == envelope


@pytest.mark.parametrize("kind", ["search", "extract", "capture", "transcription", "import", "refusal", "failure", "recovery"])
def test_hsp04_every_canonical_artifact_kind_uses_the_exact_envelope(kind: str) -> None:
    envelope = _journal(kind, "refused" if kind == "refusal" else "completed")
    assert validate_journal_envelope(envelope)["artifact"]["kind"] == kind


@pytest.mark.parametrize("field", ["summary", "priority", "status", "next_action", "approval", "crm", "wiki", "domain_tags"])
def test_hsp04_forbidden_canonical_fields_fail_closed(field: str) -> None:
    envelope = _journal()
    envelope[field] = "forbidden"
    with pytest.raises(ContractError):
        validate_journal_envelope(envelope)


def test_hsp04_request_contract_rejects_unknown_principal_and_unknown_fields() -> None:
    request = {
        "schema_version": "houndd.request.v1",
        "request_id": "request",
        "idempotency_key": "key",
        "producer": {"owner_id": "owner", "capability": "capture", "run_id": "run"},
        "requested_access": "restricted",
        "policy_id": "policy",
        "operation": {"name": "capture", "payload": {}},
    }
    assert validate_request(request) == request
    forged = {**request, "principal": "caller-controlled"}
    with pytest.raises(ContractError):
        validate_request(forged)
