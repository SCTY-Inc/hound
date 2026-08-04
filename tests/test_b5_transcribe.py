"""B5: ``transcribe`` bound to an authorized media capture (GOALIE D5, OpenAI Whisper).

``transcribe`` is an adapter operation with no SOURCE: its bytes are the media
capture the daemon resolves for itself.  Two VISION contracts shape everything
here.

Capture binding (VISION §"Slice 3C1 operation records"): the capture ID "must
resolve to an authorized ``kind=media`` capture under the effective scope with
that exact hash, type, and lineage before any model call".  The resolution runs
before acceptance, so an unresolvable ID creates no reservation, no attempt, no
record, no event, and never reaches the provider.

Transcript PHI (VISION §"Access, classification, retention"): "Transcription
records retain hashes and policy-safe provenance only, unless a separately
approved non-PHI representation is established."  No such representation is
approved, so a transcription record is hashes and provenance only and **no
transcript byte is ever staged**.  That also keeps the ``houndd.phi-text-scan.v1``
boundary exactly as VISION defines it (``application/json`` and
``text/markdown``): nothing is staged, so nothing needs scanning before staging.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path
import threading
import time
from typing import Any

import pytest

from houndd import HounddStore
from houndd.adapter_host import (
    ADAPTER_MEDIA_TYPES,
    ADAPTER_OPERATIONS,
    ADAPTER_PROVIDERS,
    AdapterAbstained,
    AdapterFailed,
    AdapterHost,
    AdapterResult,
    AdapterUnavailable,
)
from houndd.adapter_validation import (
    TRANSCRIPT_RECORD_SCHEMA,
    AdapterOutcomeError,
    validate_adapter_outcome,
    validate_adapter_record,
)
from houndd.access import AuthenticatedPrincipal, EventSelector, PrincipalScope, ProducerSelector
from houndd.commit import CommitContractError, normalize_source, parse_commit_request, resolve_route
from houndd.commit_runtime import (
    CommitIntegrityError,
    CommitRefusal,
    CommitRuntime,
)
from houndd.contracts import canonical_bytes, make_journal_envelope
from houndd.phi import PhiInputError, scan_text
from houndd.service import HounddService
from houndd.verify import verify_store
from hound_research import cli as research_cli
from hound_research.commit_client import exchange
from hound_web_adapters._http import AdapterError
from hound_web_adapters.whisper import MODEL, transcribe as whisper_transcribe


PRINCIPAL = f"linux-uid:{os.getuid()}"
AUDIO = b"\x00\x01authorized media capture bytes\x02\x03"
TRANSCRIPT = "Respite care exists. Ask the county."
SEGMENT_TEXTS = ("Respite care exists.", " Ask the county.")
CAPABILITIES = ("ingest.media", "transcribe")


def _policy() -> dict[str, object]:
    return {
        "schema_version": "houndd.policy.v1",
        "rules": [
            {
                "subject": PRINCIPAL,
                "claim_selector": {"owner_id": "writer", "capability": capability, "run_id": None},
                "policy_id": "write-policy",
                "event_producer_selectors": [{"owner_id": "writer", "capability": selector, "run_id": None} for selector in CAPABILITIES],
                "readable_tiers": ["public"],
                "allowed_output_tiers": ["public"],
            }
            for capability in CAPABILITIES
        ],
    }


def _state(tmp_path: Path, *, audio: bytes = AUDIO) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700, parents=True)
    HounddStore(root).close()
    service = root / "service"
    service.mkdir(mode=0o700)
    (service / "policy.json").write_bytes(canonical_bytes(_policy()))
    (service / "policy.json").chmod(0o600)
    (service / "phi-clear.json").write_bytes(canonical_bytes({
        "schema_version": "houndd.phi-clear.v1",
        "entries": [{"sha256": hashlib.sha256(audio).hexdigest(), "media_type": "application/octet-stream", "encoding": "identity"}],
    }))
    (service / "phi-clear.json").chmod(0o600)
    return root


def _scope(*, capabilities: tuple[str, ...] = CAPABILITIES) -> PrincipalScope:
    tiers = frozenset({"public"})
    return PrincipalScope(
        principal=AuthenticatedPrincipal(PRINCIPAL),
        readable_tiers=tiers,
        permitted_event_selectors=tuple(EventSelector("write-policy", ProducerSelector("writer", capability, None), tiers) for capability in capabilities),
    )


def _media_frame(*, data: bytes, key: str, request_id: str = "capture") -> dict[str, Any]:
    digest = hashlib.sha256(data).hexdigest()
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": "/v1/ingest/media",
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": key,
            "producer": {"owner_id": "writer", "capability": "ingest.media", "run_id": "run"},
            "requested_access": "public",
            "policy_id": "write-policy",
            "operation": {"name": "ingest.media", "payload": {
                "source": {"kind": "bytes", "body_base64": base64.b64encode(data).decode("ascii"), "sha256": digest, "byte_length": len(data)},
                "media_type": "application/octet-stream",
            }},
        },
    }


def _transcribe_frame(capture_id: str, *, key: str, request_id: str = "one", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "wire_version": "houndd.uds.v1",
        "method": "POST",
        "path": "/v1/transcribe",
        "body": {
            "schema_version": "houndd.commit-request.v1",
            "request_id": request_id,
            "idempotency_key": key,
            "producer": {"owner_id": "writer", "capability": "transcribe", "run_id": "run"},
            "requested_access": "public",
            "policy_id": "write-policy",
            "operation": {"name": "transcribe", "payload": {"capture_id": capture_id} if payload is None else payload},
        },
    }


def _capture(runtime: CommitRuntime, *, data: bytes = AUDIO, key: str = "capture-key") -> str:
    """Commit one media capture the way B4 does and return its record ID."""

    route = resolve_route("POST", "/v1/ingest/media", require_available=True)
    request = parse_commit_request(_media_frame(data=data, key=key)["body"], route)
    response = runtime.execute(
        request,
        route,
        principal=PRINCIPAL,
        access="public",
        source=normalize_source(request.source.to_wire()),
        scanner_clear=True,
        scope=_scope(),
    )
    assert response["outcome"] == "completed"
    return response["record_ids"][0]


def _request(capture_id: str, *, key: str, request_id: str = "one", payload: dict[str, Any] | None = None):
    route = resolve_route("POST", "/v1/transcribe", require_available=True)
    return parse_commit_request(_transcribe_frame(capture_id, key=key, request_id=request_id, payload=payload)["body"], route), route


def _segments(*, spans: tuple[tuple[int, int], ...] = ((0, 2_000), (2_000, 4_000))) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "index": index,
            "start_ms": start,
            "end_ms": end,
            "text_sha256": hashlib.sha256(SEGMENT_TEXTS[index].encode("utf-8")).hexdigest(),
        }
        for index, (start, end) in enumerate(spans)
    )


def _result(*, outcome: str = "completed", spans: tuple[tuple[int, int], ...] = ((0, 2_000), (2_000, 4_000))) -> AdapterResult:
    text = TRANSCRIPT.encode("utf-8")
    return AdapterResult(
        "transcribe",
        outcome,
        b"",
        "none",
        "2026-08-04T00:00:00Z",
        1,
        0,
        (),
        model=MODEL,
        model_version="whisper-1-2026-01",
        language="en",
        text_sha256=hashlib.sha256(text).hexdigest(),
        text_byte_length=len(text),
        segments=_segments(spans=spans),
    )


class _FauxHost(AdapterHost):
    """One faux transcription adapter that records every invocation."""

    def __init__(self, *, result: AdapterResult | None = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []

        def adapter(payload: Any) -> AdapterResult:
            self.calls.append(dict(payload))
            if len(self.calls) > 1:
                raise AssertionError("an accepted attempt invoked its adapter more than once")
            if error is not None:
                raise error
            return result if result is not None else _result()

        super().__init__({"transcribe": adapter})


def _whisper_body(*, text: str = TRANSCRIPT, duration: float = 4.0, model: str | None = "whisper-1-2026-01", segments: list[dict[str, Any]] | None = None) -> bytes:
    body: dict[str, Any] = {
        "text": text,
        "language": "english",
        "duration": duration,
        "segments": segments if segments is not None else [
            {"start": 0.0, "end": 2.0, "text": SEGMENT_TEXTS[0]},
            {"start": 2.0, "end": 4.0, "text": SEGMENT_TEXTS[1]},
        ],
    }
    if model is not None:
        body["model"] = model
    return json.dumps(body).encode("utf-8")


# ------------------------------------------------------------------- contract


def test_b5_route_and_payload_bind_only_a_capture_id() -> None:
    """VISION: ``transcribe`` is ``{capture_id}`` and no provider/model fields."""

    route = resolve_route("POST", "/v1/transcribe", require_available=True)
    assert route.operation == route.capability == "transcribe"
    assert "transcribe" in ADAPTER_OPERATIONS and ADAPTER_PROVIDERS["transcribe"] == "openai"

    capture_id = "a" * 64
    parsed = parse_commit_request(_transcribe_frame(capture_id, key="k")["body"], route)
    assert parsed.payload == {"capture_id": capture_id}
    assert parsed.source is None

    for payload in (
        {"capture_id": capture_id, "model": "whisper-1"},
        {"capture_id": capture_id, "provider": "openai"},
        {"capture_id": capture_id, "language": "en"},
        {"capture_id": "not-a-record-id"},
        {"capture_id": "A" * 64},
        {"capture_id": capture_id.upper()},
        {},
        {"capture_id": 1},
    ):
        with pytest.raises(CommitContractError):
            parse_commit_request(_transcribe_frame(capture_id, key="k", payload=payload)["body"], route)


def test_b5_transcript_stages_nothing_and_stays_outside_the_text_scanner_boundary() -> None:
    """The PHI text-scan boundary is unchanged: transcribe stages nothing."""

    assert "transcribe" not in ADAPTER_MEDIA_TYPES
    with pytest.raises(PhiInputError):
        scan_text(TRANSCRIPT.encode("utf-8"), "text/plain", "transcribe")
    with pytest.raises(PhiInputError):
        scan_text(TRANSCRIPT.encode("utf-8"), "application/json", "transcribe")


def test_b5_adapter_result_refuses_transcript_content_and_missing_provenance() -> None:
    with pytest.raises(TypeError):
        # A transcript byte may never ride the commit path.
        AdapterResult("transcribe", "completed", b"text", "text/plain", "2026-08-04T00:00:00Z", 1, 0)
    with pytest.raises(TypeError):
        AdapterResult("transcribe", "completed", b"", "none", "2026-08-04T00:00:00Z", 1, 0, (), model=MODEL, model_version="v", language="en", text_sha256="none", text_byte_length=0, segments=_segments())
    with pytest.raises(TypeError):
        AdapterResult("transcribe", "completed", b"", "none", "2026-08-04T00:00:00Z", 1, 0, (), model=MODEL, model_version="v", language="en", text_sha256=hashlib.sha256(b"x").hexdigest(), text_byte_length=1, segments=())
    with pytest.raises(TypeError):
        # Provenance belongs to transcription and to nothing else.
        AdapterResult("ingest.url", "completed", b"# md", "text/markdown", "2026-08-04T00:00:00Z", 1, 0, (), model="whisper-1")
    with pytest.raises(TypeError):
        AdapterResult("ingest.url", "completed", b"# md", "text/markdown", "2026-08-04T00:00:00Z", 1, 0, (), segments=_segments())
    with pytest.raises(TypeError):
        # Out-of-order segment timings are not provenance.
        AdapterResult("transcribe", "completed", b"", "none", "2026-08-04T00:00:00Z", 1, 0, (), model=MODEL, model_version="v", language="en", text_sha256=hashlib.sha256(b"x").hexdigest(), text_byte_length=1, segments=_segments(spans=((2_000, 4_000), (0, 2_000))))


# ------------------------------------------------------------ capture binding


def test_b5_completed_transcription_binds_its_capture_and_stages_no_transcript(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        capture_record = runtime.records.read_json(capture_id)  # type: ignore[union-attr]
        host = _FauxHost()
        request, route = _request(capture_id, key="transcribe-key")
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())

        assert response["outcome"] == "completed" and response["ok"] is True
        assert len(response["record_ids"]) == len(response["entry_ids"]) == 1
        # The provider saw the authorized capture's exact bytes and nothing else.
        assert host.calls == [{"capture_id": capture_id, "audio": AUDIO}]

        record_id = response["record_ids"][0]
        record = runtime.records.read_json(record_id)  # type: ignore[union-attr]
        assert record["schema_version"] == TRANSCRIPT_RECORD_SCHEMA
        assert record["operation"] == "transcribe" and record["provider"] == "openai"
        assert record["evidence_status"] == "clear"
        assert record["capture"] == {
            "record_id": capture_id,
            "source_sha256": capture_record["source"]["sha256"],
            "byte_length": capture_record["source"]["byte_length"],
            "media_type": "application/octet-stream",
        }
        assert record["lineage"] == {"relation": "media", "record_id": capture_id, "lead_id": "none"}
        assert record["model"] == MODEL and record["model_version"] == "whisper-1-2026-01" and record["language"] == "en"
        assert record["text_sha256"] == hashlib.sha256(TRANSCRIPT.encode("utf-8")).hexdigest()
        assert record["text_byte_length"] == len(TRANSCRIPT.encode("utf-8"))
        assert [segment["text_sha256"] for segment in record["segments"]] == [hashlib.sha256(text.encode("utf-8")).hexdigest() for text in SEGMENT_TEXTS]
        assert set(record) == {
            "schema_version", "attempt_id", "request_hash", "operation", "outcome", "evidence_status",
            "reason", "provider", "retrieved_at", "model", "model_version", "language", "capture",
            "text_sha256", "text_byte_length", "segments", "lineage",
        }

        event = runtime.journal.entries()[-1]  # type: ignore[union-attr]
        assert event["artifact"]["kind"] == "transcription"
        assert event["artifact"]["schema"] == TRANSCRIPT_RECORD_SCHEMA
        assert event["source"] == {"provider": "openai", "native_id": record_id, "canonical_url": "none"}
        assert event["lineage"] == record["lineage"]
        assert event["usage"] == {"requests": 1, "bytes": 0, "cost": 0}
        validate_adapter_outcome(record, event, record_id=record_id)

        # Only the capture's audio is a durable object: no transcript blob.
        assert [path.name for path in sorted((state / "blobs").iterdir())] == [capture_record["source"]["sha256"]]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


def test_b5_no_durable_byte_carries_the_transcript_text(tmp_path: Path) -> None:
    """No record, event, blob, or private marker may contain transcript text."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        request, route = _request(capture_id, key="phi-key")
        runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_FauxHost(), scope=_scope())
    finally:
        runtime.close()

    needles = [TRANSCRIPT.encode("utf-8"), *(text.encode("utf-8") for text in SEGMENT_TEXTS), b"respite", b"Respite"]
    for path in sorted(state.rglob("*")):
        if not path.is_file():
            continue
        raw = path.read_bytes()
        if raw == AUDIO:
            continue  # the capture's own source bytes
        for needle in needles:
            assert needle not in raw, f"{path} retains transcript text"


@pytest.mark.parametrize(
    "case",
    ("absent", "unauthorized", "wrong_kind", "wrong_hash"),
)
def test_b5_unresolvable_capture_refuses_before_any_attempt_or_model_call(tmp_path: Path, case: str) -> None:
    """Every unresolvable binding refuses identically and reaches no provider."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        scope = _scope()
        events = 1
        if case == "absent":
            target = hashlib.sha256(b"never committed").hexdigest()
        elif case == "unauthorized":
            # The capture exists, but this principal's scope cannot see the
            # media producer at all.
            target, scope = capture_id, _scope(capabilities=("transcribe",))
        elif case == "wrong_kind":
            # A real, authorized, in-scope record that is not a media capture:
            # a transcription cannot be transcribed.
            seed, seed_route = _request(capture_id, key="seed-transcript")
            target = runtime.execute_adapter(seed, seed_route, principal=PRINCIPAL, access="public", adapter_host=_FauxHost(), scope=scope)["record_ids"][0]
            events = 2
        else:
            target = capture_id[:-1] + ("0" if capture_id[-1] != "0" else "1")

        host = _FauxHost()
        request, route = _request(target, key=f"refuse-{case}")
        with pytest.raises(CommitRefusal):
            runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=scope)
        assert host.calls == []
        # The refusal created no attempt: no new event, reservation, or marker.
        assert len(runtime.journal.entries()) == events  # type: ignore[union-attr]
        assert len(list((state / "commit3c1" / "reservations").iterdir())) == events
        assert len(list((state / "commit3c1" / "open").iterdir())) == events
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


def test_b5_capture_record_that_no_longer_hashes_to_its_id_fails_closed(tmp_path: Path) -> None:
    """The exact record identity is re-proven before the capture is usable."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        record = runtime.records.read_json(capture_id)  # type: ignore[union-attr]
        path = state / "records" / f"{capture_id}.bin"
        path.chmod(0o600)
        path.write_bytes(canonical_bytes({**record, "outcome": "interrupted", "evidence_status": "interrupted"}))
        host = _FauxHost()
        request, route = _request(capture_id, key="rewritten-record")
        with pytest.raises(CommitIntegrityError, match="malformed"):
            runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert host.calls == []
    finally:
        runtime.close()


def test_b5_absent_and_unresolvable_captures_are_indistinguishable_over_the_socket(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
    finally:
        runtime.close()

    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    service = HounddService(state_root=state, socket_path=runtime_dir / "houndd.sock", adapter_host=_FauxHost())
    principal = AuthenticatedPrincipal(PRINCIPAL)
    try:
        absent = service._dispatch(principal, _transcribe_frame(hashlib.sha256(b"absent").hexdigest(), key="absent"))
        near_miss = service._dispatch(principal, _transcribe_frame(capture_id[:-1] + ("0" if capture_id[-1] != "0" else "1"), key="near-miss"))
        assert absent["status"] == near_miss["status"] == 400
        assert absent["body"]["error"] == near_miss["body"]["error"]
        assert absent["body"]["error"]["code"] == "invalid_request"
        assert capture_id not in json.dumps(absent["body"])
        # One marker: the capture's own, and no refused attempt beside it.
        assert len(list((state / "commit3c1" / "open").iterdir())) == 1
    finally:
        service.close()


def test_b5_capture_bytes_that_changed_under_the_record_fail_closed(tmp_path: Path) -> None:
    """The exact hash is re-proven against the stored bytes before the model call."""

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        digest = runtime.records.read_json(capture_id)["source"]["sha256"]  # type: ignore[union-attr]
        blob = state / "blobs" / digest
        blob.chmod(0o600)
        blob.write_bytes(b"substituted media bytes")
        host = _FauxHost()
        request, route = _request(capture_id, key="tampered-bytes")
        with pytest.raises(CommitIntegrityError, match="no verified source bytes"):
            runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert host.calls == []
    finally:
        runtime.close()


def test_b5_forged_transcript_record_fails_validation_and_verification(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        request, route = _request(capture_id, key="forge-key")
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_FauxHost(), scope=_scope())
        record_id = response["record_ids"][0]
        record = runtime.records.read_json(record_id)  # type: ignore[union-attr]
        event = runtime.journal.entries()[-1]  # type: ignore[union-attr]
    finally:
        runtime.close()

    for mutate in (
        lambda body: body.__setitem__("capture", {**body["capture"], "source_sha256": hashlib.sha256(b"other").hexdigest()}),
        lambda body: body.__setitem__("capture", {**body["capture"], "record_id": hashlib.sha256(b"other capture").hexdigest()}),
        lambda body: body.__setitem__("capture", {**body["capture"], "media_type": "audio/mpeg"}),
        lambda body: body.__setitem__("lineage", {"relation": "none", "record_id": "none", "lead_id": "none"}),
        lambda body: body.__setitem__("lineage", {"relation": "search", "record_id": body["capture"]["record_id"], "lead_id": "none"}),
        lambda body: body.__setitem__("text_sha256", hashlib.sha256(b"different transcript").hexdigest()),
        lambda body: body.__setitem__("segments", []),
        lambda body: body.__setitem__("model_version", "none"),
        lambda body: body.update({"text": TRANSCRIPT}),
    ):
        forged = deepcopy(record)
        mutate(forged)
        with pytest.raises(AdapterOutcomeError):
            validate_adapter_outcome(forged, event, record_id=record_id)

    # A transcript whose capture record does not exist fails verification.
    state_two = _state(tmp_path / "second")
    orphan = CommitRuntime(state_two)
    try:
        orphan_capture = _capture(orphan)
        orphan_request, orphan_route = _request(orphan_capture, key="orphan")
        orphan_response = orphan.execute_adapter(orphan_request, orphan_route, principal=PRINCIPAL, access="public", adapter_host=_FauxHost(), scope=_scope())
        orphan_record = orphan_response["record_ids"][0]
    finally:
        orphan.close()
    (state_two / "records" / f"{orphan_capture}.bin").unlink()
    report = verify_store(state_two, projection=False)
    assert report["valid"] is False
    assert any("capture" in failure or orphan_capture in failure for failure in report["failures"])
    assert orphan_record


def test_b5_verify_rejects_a_forged_duplicate_transcription_event(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        request, route = _request(capture_id, key="duplicate")
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_FauxHost(), scope=_scope())
        record_id = response["record_ids"][0]
        original = runtime.journal.entries()[-1]  # type: ignore[union-attr]
        forged = make_journal_envelope(
            sequence=original["sequence"] + 1,
            appended_at="2026-08-04T00:00:01Z",
            producer=original["producer"],
            artifact=original["artifact"],
            lineage=original["lineage"],
            source=original["source"],
            classification=original["classification"],
            access=original["access"],
            policy_id=original["policy_id"],
            dedupe=original["dedupe"],
            usage=original["usage"],
        )
        runtime.journal.append(forged)  # type: ignore[union-attr]
    finally:
        runtime.close()

    report = verify_store(state, projection=False)
    assert report["valid"] is False
    assert any(record_id in failure for failure in report["failures"])


# ------------------------------------------------------------------- outcomes


def test_b5_partial_coverage_stays_partial_and_never_reads_as_complete(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        request, route = _request(capture_id, key="partial-key")
        response = runtime.execute_adapter(
            request,
            route,
            principal=PRINCIPAL,
            access="public",
            adapter_host=_FauxHost(result=_result(outcome="partial")),
            scope=_scope(),
        )
        assert response["outcome"] == "partial" and response["ok"] is False
        record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
        assert record["outcome"] == "partial" and record["evidence_status"] == "partial"
        assert record["capture"]["record_id"] == capture_id
        assert record["segments"] and record["text_sha256"] != "none"
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


@pytest.mark.parametrize(
    ("error", "outcome", "evidence", "reason", "requests"),
    (
        (AdapterFailed("provider exchange failed", requests=1), "failed", "failure", "provider_failed", 1),
        (AdapterAbstained("provider returned no transcript", requests=1), "refused", "refused", "provider_abstained", 1),
        (AdapterUnavailable("no adapter is bound"), "degraded", "degraded", "adapter_absent", 0),
    ),
)
def test_b5_non_transcribed_outcomes_are_durable_and_claim_no_provenance(
    tmp_path: Path, error: Exception, outcome: str, evidence: str, reason: str, requests: int
) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        request, route = _request(capture_id, key=f"outcome-{outcome}")
        response = runtime.execute_adapter(
            request,
            route,
            principal=PRINCIPAL,
            access="public",
            adapter_host=_FauxHost(error=error),
            scope=_scope(),
        )
        assert response["outcome"] == outcome and response["ok"] is False
        assert response["usage"] == {"requests": requests, "bytes": 0, "cost": 0}
        record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
        assert record["evidence_status"] == evidence and record["reason"] == reason
        # A non-transcribed outcome can never read as thin evidence.
        assert (record["model"], record["model_version"], record["language"]) == ("none", "none", "none")
        assert record["text_sha256"] == "none" and record["text_byte_length"] == 0 and record["segments"] == []
        # It still names the capture it was authorized against.
        assert record["capture"]["record_id"] == capture_id
        assert record["lineage"] == {"relation": "media", "record_id": capture_id, "lead_id": "none"}
        assert [path.name for path in (state / "blobs").iterdir()] == [record["capture"]["source_sha256"]]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


def test_b5_degraded_when_no_openai_key_is_bound(tmp_path: Path) -> None:
    """No ``OPENAI_API_KEY`` means no bound adapter: one durable degraded outcome."""

    def transport(**_call: object) -> tuple[int, bytes]:
        pytest.fail("an unbound adapter must not open a provider connection")

    host = AdapterHost.from_env({"EXA_API_KEY": "k"}, transport=transport)
    assert "transcribe" not in host.operations

    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        request, route = _request(capture_id, key="degraded-key")
        response = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert response["outcome"] == "degraded" and response["ok"] is False
        record = runtime.records.read_json(response["record_ids"][0])  # type: ignore[union-attr]
        assert record["reason"] == "adapter_absent" and record["model"] == "none"
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        runtime.close()


def test_b5_exact_replay_returns_the_original_outcome_without_a_second_exchange(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
        host = _FauxHost()
        request, route = _request(capture_id, key="replay-key")
        first = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        replay = runtime.probe(request, route, principal=PRINCIPAL)
        assert replay.response_template is not None
        assert replay.response_template["record_ids"] == first["record_ids"]
        assert replay.response_template["entry_ids"] == first["entry_ids"]
        again = runtime.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
        assert again["record_ids"] == first["record_ids"]
        assert len(host.calls) == 1
        assert len(runtime.journal.entries()) == 2  # type: ignore[union-attr]
    finally:
        runtime.close()


# --------------------------------------------------------------- crash matrix


def test_b5_crash_after_reservation_is_an_unrecoverable_integrity_failure(tmp_path: Path) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
    finally:
        runtime.close()

    def crash(phase: str) -> None:
        if phase == "after_reservation":
            raise RuntimeError("simulated death at after_reservation")

    crashed = CommitRuntime(state, fault_hook=crash)
    request, route = _request(capture_id, key="crash-after_reservation")
    try:
        with pytest.raises(RuntimeError):
            crashed.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=_FauxHost(), scope=_scope())
    finally:
        crashed.close()

    with pytest.raises(CommitIntegrityError):
        CommitRuntime(state)


@pytest.mark.parametrize("crash_phase", ("after_open", "after_adapter", "after_plan", "after_record", "after_journal"))
def test_b5_crash_matrix_recovers_at_every_commit_point(tmp_path: Path, crash_phase: str) -> None:
    state = _state(tmp_path)
    runtime = CommitRuntime(state)
    try:
        capture_id = _capture(runtime)
    finally:
        runtime.close()

    def crash(phase: str) -> None:
        if phase == crash_phase:
            raise RuntimeError(f"simulated death at {crash_phase}")

    host = _FauxHost()
    request, route = _request(capture_id, key=f"crash-{crash_phase}")
    crashed = CommitRuntime(state, fault_hook=crash)
    try:
        with pytest.raises(RuntimeError):
            crashed.execute_adapter(request, route, principal=PRINCIPAL, access="public", adapter_host=host, scope=_scope())
    finally:
        crashed.close()

    recovered = CommitRuntime(state)
    try:
        recovered.reconcile()
        replay = recovered.probe(request, route, principal=PRINCIPAL)
        assert replay.response_template is not None
        assert len(replay.response_template["record_ids"]) == len(replay.response_template["entry_ids"]) == 1
        record = recovered.records.read_json(replay.response_template["record_ids"][0])  # type: ignore[union-attr]
        if crash_phase in {"after_open", "after_adapter"}:
            # Nothing durable was written for the exchange, so recovery reports
            # interrupted rather than promoting an unwritten answer.
            assert replay.response_template["outcome"] == "interrupted"
            assert record["model"] == "none" and record["segments"] == []
        else:
            assert replay.response_template["outcome"] == "completed"
            assert record["model_version"] == "whisper-1-2026-01"
        assert record["capture"]["record_id"] == capture_id
        # Recovery never re-invokes the provider.
        assert len(host.calls) == (0 if crash_phase == "after_open" else 1)
        assert len(recovered.journal.entries()) == 2  # type: ignore[union-attr]
        assert [path.name for path in (state / "blobs").iterdir()] == [record["capture"]["source_sha256"]]
        assert verify_store(state, projection=False)["valid"] is True
    finally:
        recovered.close()


# --------------------------------------------------------- service and client


def test_b5_real_uds_transcribe_round_trip_and_cli_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    state = _state(tmp_path)
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir(mode=0o700)
    socket_path = runtime_dir / "houndd.sock"
    source_path = tmp_path / "media.bin"
    source_path.write_bytes(AUDIO)
    host = _FauxHost()
    service = HounddService(state_root=state, socket_path=socket_path, adapter_host=host)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.01)
        captured = exchange(socket_path, _media_frame(data=AUDIO, key="socket-capture"))
        assert captured["status"] == 200 and captured["body"]["outcome"] == "completed"
        capture_id = captured["body"]["record_ids"][0]

        code = research_cli.main([
            "transcribe",
            "--socket", os.fspath(socket_path),
            "--owner-id", "writer", "--run-id", "run", "--policy-id", "write-policy", "--requested-access", "public",
            "--idempotency-key", "cli-transcribe-key", "--request-id", "cli-transcribe-request",
            "--capture-id", capture_id,
        ])
        assert code == 0
        body = json.loads(capsys.readouterr().out)
        assert body["outcome"] == "completed" and len(body["record_ids"]) == 1
        assert host.calls == [{"capture_id": capture_id, "audio": AUDIO}]

        # A malformed capture ID never reaches the socket.
        assert research_cli.main([
            "transcribe",
            "--socket", os.fspath(socket_path),
            "--owner-id", "writer", "--run-id", "run", "--policy-id", "write-policy",
            "--idempotency-key", "cli-bad-key", "--request-id", "cli-bad-request",
            "--capture-id", "not-a-capture",
        ]) == 2
        capsys.readouterr()
    finally:
        service.close()
        thread.join(timeout=2)

    assert verify_store(state, projection=False)["valid"] is True


def test_b5_cli_still_carries_the_neighbouring_journal_and_search_options(capsys: pytest.CaptureFixture[str]) -> None:
    """B13's --options-json and B14's --order share this file; both survive."""

    parser = research_cli.build_parser()
    transcribe_args = parser.parse_args([
        "transcribe", "--socket", "/tmp/x.sock", "--owner-id", "w", "--run-id", "r",
        "--policy-id", "p", "--idempotency-key", "k", "--request-id", "i", "--capture-id", "a" * 64,
    ])
    assert transcribe_args.capture_id == "a" * 64
    search_args = parser.parse_args([
        "ingest", "search", "--socket", "/tmp/x.sock", "--owner-id", "w", "--run-id", "r",
        "--policy-id", "p", "--idempotency-key", "k", "--request-id", "i", "--query", "q",
        "--options-json", '{"category": "news"}',
    ])
    assert search_args.options_json == '{"category": "news"}'
    query_args = parser.parse_args(["journal", "query", "--socket", "/tmp/x.sock", "--owner-id", "w", "--run-id", "r", "--policy-id", "p", "--order", "descending"])
    assert query_args.order == "descending"


# ------------------------------------------------------------ whisper adapter


def test_b5_whisper_derives_daemon_provenance_from_one_injected_exchange() -> None:
    calls: list[dict[str, Any]] = []

    def transport(**call: object) -> tuple[int, bytes]:
        calls.append(dict(call))
        return 200, _whisper_body()

    result = whisper_transcribe(
        {"capture_id": "b" * 64, "audio": AUDIO},
        env={"OPENAI_API_KEY": "test-key"},
        transport=transport,
        retrieved_at="2026-08-04T00:00:00Z",
    )
    assert len(calls) == 1 and calls[0]["method"] == "POST"
    assert calls[0]["headers"]["Authorization"] == "Bearer test-key"
    assert b'name="model"' in calls[0]["body"] and AUDIO in calls[0]["body"]
    output = result["output"]
    # The provider names the model that answered; the request's model is not
    # substituted for it.
    assert output["model"] == MODEL and output["model_version"] == "whisper-1-2026-01"
    assert output["language"] == "english" and output["duration_ms"] == 4_000
    assert [segment["start_ms"] for segment in output["segments"]] == [0, 2_000]
    assert result["usage"]["requests"] == 1


@pytest.mark.parametrize(
    "body",
    (
        _whisper_body(segments=[{"start": 0.0, "end": 2.0, "text": "does not reconstruct"}]),
        _whisper_body(segments=[{"start": 2.0, "end": 0.0, "text": SEGMENT_TEXTS[0]}]),
        _whisper_body(segments=[]),
        b"{not json",
        canonical_bytes({"language": "en"}),
    ),
)
def test_b5_whisper_refuses_a_provider_answer_it_cannot_verify(body: bytes) -> None:
    def transport(**_call: object) -> tuple[int, bytes]:
        return 200, body

    with pytest.raises(AdapterError):
        whisper_transcribe({"capture_id": "b" * 64, "audio": AUDIO}, env={"OPENAI_API_KEY": "k"}, transport=transport)


def test_b5_whisper_requires_a_credential_and_bounded_capture_bytes() -> None:
    def transport(**_call: object) -> tuple[int, bytes]:
        pytest.fail("a refused transcription must not open a provider connection")

    for payload in (
        {"capture_id": "b" * 64, "audio": b""},
        {"capture_id": "short", "audio": AUDIO},
        {"capture_id": "b" * 64, "audio": "not bytes"},
    ):
        with pytest.raises(AdapterError):
            whisper_transcribe(payload, env={"OPENAI_API_KEY": "k"}, transport=transport)
    with pytest.raises(AdapterError):
        whisper_transcribe({"capture_id": "b" * 64, "audio": AUDIO}, env={}, transport=transport)


def test_b5_whisper_provider_error_status_is_one_failed_exchange() -> None:
    def transport(**_call: object) -> tuple[int, bytes]:
        return 429, b'{"error": {"message": "rate limited"}}'

    with pytest.raises(AdapterError) as failure:
        whisper_transcribe({"capture_id": "b" * 64, "audio": AUDIO}, env={"OPENAI_API_KEY": "k"}, transport=transport)
    assert failure.value.requests == 1


def test_b5_host_reports_an_unbound_capture_payload_as_zero_exchanges() -> None:
    """The daemon binds the bytes; a payload without them made no request."""

    def transport(**_call: object) -> tuple[int, bytes]:
        pytest.fail("an unbound transcribe payload must not reach the provider")

    host = AdapterHost.from_env({"OPENAI_API_KEY": "k"}, transport=transport)
    with pytest.raises(AdapterFailed) as failure:
        host.invoke("transcribe", {"capture_id": "b" * 64})
    assert failure.value.requests == 0


def test_b5_host_reduces_an_injected_exchange_to_a_hashes_only_result() -> None:
    def transport(**_call: object) -> tuple[int, bytes]:
        return 200, _whisper_body()

    host = AdapterHost.from_env({"OPENAI_API_KEY": "k"}, transport=transport)
    result = host.invoke("transcribe", {"capture_id": "b" * 64, "audio": AUDIO})
    assert result.operation == "transcribe" and result.outcome == "completed"
    assert result.content == b"" and result.media_type == "none"
    assert result.text_sha256 == hashlib.sha256(TRANSCRIPT.encode("utf-8")).hexdigest()
    assert [segment["text_sha256"] for segment in result.segments] == [hashlib.sha256(text.encode("utf-8")).hexdigest() for text in SEGMENT_TEXTS]

    def short(**_call: object) -> tuple[int, bytes]:
        # The provider's own timings leave most of the media unaccounted for.
        return 200, _whisper_body(duration=60.0)

    partial = AdapterHost.from_env({"OPENAI_API_KEY": "k"}, transport=short).invoke("transcribe", {"capture_id": "b" * 64, "audio": AUDIO})
    assert partial.outcome == "partial"

    def silent(**_call: object) -> tuple[int, bytes]:
        return 200, _whisper_body(text="", segments=[])

    with pytest.raises(AdapterAbstained):
        AdapterHost.from_env({"OPENAI_API_KEY": "k"}, transport=silent).invoke("transcribe", {"capture_id": "b" * 64, "audio": AUDIO})


def test_b5_transcript_record_validator_requires_its_capture_and_hashes() -> None:
    """The record shape is closed: no transcript text field can be added."""

    capture_id = hashlib.sha256(b"capture").hexdigest()
    body = {
        "schema_version": TRANSCRIPT_RECORD_SCHEMA,
        "attempt_id": hashlib.sha256(b"attempt").hexdigest(),
        "request_hash": hashlib.sha256(b"request").hexdigest(),
        "operation": "transcribe",
        "outcome": "completed",
        "evidence_status": "clear",
        "reason": "none",
        "provider": "openai",
        "retrieved_at": "2026-08-04T00:00:00Z",
        "model": MODEL,
        "model_version": "whisper-1-2026-01",
        "language": "en",
        "capture": {"record_id": capture_id, "source_sha256": hashlib.sha256(AUDIO).hexdigest(), "byte_length": len(AUDIO), "media_type": "application/octet-stream"},
        "text_sha256": hashlib.sha256(TRANSCRIPT.encode("utf-8")).hexdigest(),
        "text_byte_length": len(TRANSCRIPT.encode("utf-8")),
        "segments": [dict(segment) for segment in _segments()],
        "lineage": {"relation": "media", "record_id": capture_id, "lead_id": "none"},
    }
    outcome = validate_adapter_record(body, expected_payload={"capture_id": capture_id})
    assert outcome.kind == "transcription" and outcome.staged is False

    with pytest.raises(AdapterOutcomeError):
        validate_adapter_record(body, expected_payload={"capture_id": hashlib.sha256(b"other").hexdigest()})
    with pytest.raises(AdapterOutcomeError):
        # A transcript may never claim a staged object.
        validate_adapter_record(body, content_identity={"sha256": hashlib.sha256(b"text").hexdigest(), "byte_length": 4})
    for extra in ("text", "provider_response", "content_sha256"):
        with pytest.raises(AdapterOutcomeError):
            validate_adapter_record({**body, extra: "x"})
