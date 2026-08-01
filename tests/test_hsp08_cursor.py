from __future__ import annotations

import base64
import hashlib
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from houndd.cursor import (
    CursorBindings,
    CursorCodec,
    CursorKeyring,
    CursorRecoverySnapshot,
    CursorRejected,
    JournalCursorCandidate,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class _EqualitySpoofingDatetime(datetime):
    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False

    def isoformat(self, sep: str = "T", timespec: str = "auto") -> str:
        return "2026-07-31T00:00:00+00:00"


def _candidate(
    sequence: int,
    *,
    appended_at: str | None = None,
    entry_label: str | None = None,
    chain_label: str | None = None,
) -> JournalCursorCandidate:
    return JournalCursorCandidate(
        sequence=sequence,
        appended_at=appended_at or f"2026-07-31T00:00:{sequence:02d}Z",
        entry_id=_digest(entry_label or f"entry-{sequence}"),
        chain_sha256=_digest(chain_label or f"chain-{sequence}"),
    )


@pytest.fixture
def bindings() -> CursorBindings:
    return CursorBindings(
        service_generation="generation/protected/alpha",
        filter_hash=_digest("normalized protected filter"),
        authenticated_principal="uid:12345/protected-principal",
        query_context_hash=_digest("policy bundle plus annotation generation"),
    )


@pytest.fixture
def keyring() -> CursorKeyring:
    return CursorKeyring(active_kid="active-2026", keys={"active-2026": b"A" * 32})


@pytest.fixture
def codec(keyring: CursorKeyring) -> CursorCodec:
    return CursorCodec(keyring, nonce_source=lambda size: b"N" * size)


def _token(
    codec: CursorCodec,
    bindings: CursorBindings,
    *,
    last: JournalCursorCandidate | None = None,
    high_watermark: JournalCursorCandidate | None = None,
) -> tuple[str, tuple[JournalCursorCandidate, ...]]:
    candidates = tuple(_candidate(sequence) for sequence in range(5))
    last = candidates[1] if last is None else last
    high_watermark = candidates[3] if high_watermark is None else high_watermark
    return codec.issue(bindings, last=last, high_watermark=high_watermark), candidates


def _assert_generic_rejection(call) -> None:
    with pytest.raises(CursorRejected) as raised:
        call()
    assert type(raised.value) is CursorRejected
    assert str(raised.value) == "cursor rejected"
    assert raised.value.args == ("cursor rejected",)
    assert not vars(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_hsp08_cursor_round_trip_is_stateless_and_immutable(
    tmp_path, codec: CursorCodec, keyring: CursorKeyring, bindings: CursorBindings
) -> None:
    before = tuple(tmp_path.iterdir())
    token, candidates = _token(codec, bindings)
    raw = base64.urlsafe_b64decode(token)

    recovered = codec.recover(token, bindings, CursorRecoverySnapshot(candidates))

    assert len(token) == 416
    assert len(raw) == 310
    assert raw[:6] == b"HCUR\x01\x0b"
    assert recovered.last == candidates[1]
    assert recovered.high_watermark == candidates[3]
    assert recovered.last_sequence == 1
    assert recovered.high_watermark_sequence == 3
    assert recovered.resume_after == candidates[1].chronological_order
    assert tuple(tmp_path.iterdir()) == before
    with pytest.raises(FrozenInstanceError):
        bindings.service_generation = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        candidates[0].sequence = 9  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        recovered.last = candidates[0]  # type: ignore[misc]
    with pytest.raises(TypeError):
        keyring.keys["other"] = b"B" * 32  # type: ignore[index]
    assert (b"A" * 32).decode("ascii") not in repr(keyring)


def test_hsp08_decoded_cursor_contains_no_sensitive_claim_literals(
    codec: CursorCodec, bindings: CursorBindings
) -> None:
    last = _candidate(
        7_654_321,
        appended_at="2026-07-31T12:34:56.123456+05:45",
        entry_label="protected-entry-identifier",
        chain_label="protected-last-chain",
    )
    high_watermark = _candidate(
        7_654_399,
        appended_at="2026-07-31T12:35:01.654321+05:45",
        entry_label="protected-watermark-entry",
        chain_label="protected-watermark-chain",
    )

    raw = base64.urlsafe_b64decode(codec.issue(bindings, last=last, high_watermark=high_watermark))

    protected_literals = (
        bindings.service_generation,
        bindings.filter_hash,
        bindings.authenticated_principal,
        bindings.query_context_hash,
        str(last.sequence),
        str(high_watermark.sequence),
        last.entry_id,
        high_watermark.entry_id,
        last.chain_sha256,
        high_watermark.chain_sha256,
        "2026-07-31",
        "12:34:56",
    )
    assert all(value.encode("utf-8") not in raw for value in protected_literals)


def test_hsp08_nonce_and_binding_context_decorrelate_every_field_commitment(
    keyring: CursorKeyring, bindings: CursorBindings
) -> None:
    first_codec = CursorCodec(keyring, nonce_source=lambda size: b"1" * size)
    second_codec = CursorCodec(keyring, nonce_source=lambda size: b"2" * size)
    first, _ = _token(first_codec, bindings)
    second, _ = _token(second_codec, bindings)
    changed_context = CursorBindings(
        bindings.service_generation,
        bindings.filter_hash,
        bindings.authenticated_principal,
        _digest("changed query context"),
    )
    third, _ = _token(first_codec, changed_context)

    def commitments(token: str) -> tuple[bytes, ...]:
        raw = base64.urlsafe_b64decode(token)
        start = 4 + 1 + 1 + 32 + 16
        return tuple(raw[offset : offset + 32] for offset in range(start, start + 7 * 32, 32))

    first_commitments = commitments(first)
    assert all(left != right for left, right in zip(first_commitments, commitments(second), strict=True))
    assert all(left != right for left, right in zip(first_commitments, commitments(third), strict=True))


def test_hsp08_equal_instants_with_different_offsets_commit_identically(
    codec: CursorCodec, bindings: CursorBindings
) -> None:
    offset_last = _candidate(0, appended_at="2026-07-31T05:45:00+05:45")
    utc_last = _candidate(0, appended_at="2026-07-31T00:00:00Z")
    offset_hwm = _candidate(1, appended_at="2026-07-31T06:45:00+05:45")
    utc_hwm = _candidate(1, appended_at="2026-07-31T01:00:00+00:00")

    first = codec.issue(bindings, last=offset_last, high_watermark=offset_hwm)
    second = codec.issue(bindings, last=utc_last, high_watermark=utc_hwm)
    datetime_candidate = JournalCursorCandidate(
        0,
        _digest("base-datetime-entry"),
        datetime(
            2026,
            7,
            31,
            5,
            45,
            tzinfo=timezone(timedelta(hours=5, minutes=45)),
        ),
        _digest("base-datetime-chain"),
    )

    assert first == second
    assert offset_last.appended_at == datetime(2026, 7, 31, tzinfo=timezone.utc)
    assert type(datetime_candidate.sequence) is int
    assert type(datetime_candidate.entry_id) is str
    assert type(datetime_candidate.appended_at) is datetime
    assert datetime_candidate.appended_at == datetime(2026, 7, 31, tzinfo=timezone.utc)
    assert datetime_candidate.appended_at.tzinfo is timezone.utc
    assert type(datetime_candidate.chain_sha256) is str


def test_hsp08_recovery_uses_full_chronological_tuple_not_sequence_order(
    codec: CursorCodec, bindings: CursorBindings
) -> None:
    candidates = (
        _candidate(0, appended_at="2026-07-31T03:00:00Z"),
        _candidate(1, appended_at="2026-07-31T00:30:00-01:00"),
        _candidate(2, appended_at="2026-07-31T02:00:00Z"),
        _candidate(3, appended_at="2026-07-31T04:00:00Z"),
    )
    token = codec.issue(bindings, last=candidates[1], high_watermark=candidates[2])

    recovered = codec.recover(token, bindings, CursorRecoverySnapshot(candidates))

    assert recovered.last_sequence == 1
    assert recovered.resume_after == (
        datetime(2026, 7, 31, 1, 30, tzinfo=timezone.utc),
        1,
        candidates[1].entry_id,
    )
    assert recovered.high_watermark_sequence == 2


def test_hsp08_watermark_binds_entry_and_chain_not_only_sequence(
    codec: CursorCodec, bindings: CursorBindings
) -> None:
    token, candidates = _token(codec, bindings)
    divergent = list(candidates)
    divergent[3] = _candidate(
        3,
        appended_at=candidates[3].appended_at.isoformat(),
        entry_label="divergent-entry-at-same-sequence",
        chain_label="divergent-chain-at-same-sequence",
    )

    _assert_generic_rejection(
        lambda: codec.recover(token, bindings, CursorRecoverySnapshot(tuple(divergent)))
    )

    chain_only = list(candidates)
    chain_only[3] = JournalCursorCandidate(
        sequence=3,
        appended_at=candidates[3].appended_at,
        entry_id=candidates[3].entry_id,
        chain_sha256=_digest("same-event-divergent-journal-chain"),
    )
    _assert_generic_rejection(
        lambda: codec.recover(token, bindings, CursorRecoverySnapshot(tuple(chain_only)))
    )


def test_hsp08_valid_outer_token_scans_every_candidate_exactly_once(
    codec: CursorCodec, bindings: CursorBindings
) -> None:
    token, candidates = _token(codec, bindings)
    visited: list[int] = []

    codec.recover(
        token,
        bindings,
        CursorRecoverySnapshot(candidates),
        scan_observer=lambda candidate: visited.append(candidate.sequence),
    )

    assert visited == [0, 1, 2, 3, 4]


def test_hsp08_outer_mac_rejection_happens_before_snapshot_scan(
    codec: CursorCodec, bindings: CursorBindings
) -> None:
    token, candidates = _token(codec, bindings)
    raw = bytearray(base64.urlsafe_b64decode(token))
    raw[-1] ^= 1
    tampered = base64.urlsafe_b64encode(raw).decode("ascii")
    visited: list[int] = []

    _assert_generic_rejection(
        lambda: codec.recover(
            tampered,
            bindings,
            CursorRecoverySnapshot(candidates),
            scan_observer=lambda candidate: visited.append(candidate.sequence),
        )
    )
    assert visited == []


def test_hsp08_all_binding_and_wire_failures_are_generic(
    codec: CursorCodec, bindings: CursorBindings
) -> None:
    token, candidates = _token(codec, bindings)
    snapshot = CursorRecoverySnapshot(candidates)
    altered = (
        CursorBindings(
            "other-generation",
            bindings.filter_hash,
            bindings.authenticated_principal,
            bindings.query_context_hash,
        ),
        CursorBindings(
            bindings.service_generation,
            _digest("other-filter"),
            bindings.authenticated_principal,
            bindings.query_context_hash,
        ),
        CursorBindings(bindings.service_generation, bindings.filter_hash, "uid:forged", bindings.query_context_hash),
        CursorBindings(
            bindings.service_generation,
            bindings.filter_hash,
            bindings.authenticated_principal,
            _digest("other-context"),
        ),
    )
    failures = [lambda value=value: codec.recover(token, value, snapshot) for value in altered]

    raw = bytearray(base64.urlsafe_b64decode(token))
    raw[0] ^= 1
    failures.append(lambda: codec.recover(base64.urlsafe_b64encode(raw).decode("ascii"), bindings, snapshot))
    for offset, replacement in ((4, 2), (5, 0), (6 + 31, 1)):
        malformed = bytearray(base64.urlsafe_b64decode(token))
        malformed[offset] = replacement
        encoded_malformed = base64.urlsafe_b64encode(malformed).decode("ascii")
        failures.append(
            lambda value=encoded_malformed: codec.recover(value, bindings, snapshot)
        )
    failures.extend(
        (
            lambda: codec.recover(token[:-1], bindings, snapshot),
            lambda: codec.recover(token + "A", bindings, snapshot),
            lambda: codec.recover("!" * len(token), bindings, snapshot),
            lambda: codec.recover(b"not-a-string", bindings, snapshot),  # type: ignore[arg-type]
        )
    )

    for failure in failures:
        _assert_generic_rejection(failure)


def test_hsp08_outer_tag_rejects_fields_mixed_from_valid_tokens(
    keyring: CursorKeyring, bindings: CursorBindings
) -> None:
    codec_one = CursorCodec(keyring, nonce_source=lambda size: b"1" * size)
    codec_two = CursorCodec(keyring, nonce_source=lambda size: b"2" * size)
    first, candidates = _token(codec_one, bindings)
    second, _ = _token(codec_two, bindings)
    first_raw = base64.urlsafe_b64decode(first)
    second_raw = base64.urlsafe_b64decode(second)
    midpoint = len(first_raw) // 2
    mixed = base64.urlsafe_b64encode(first_raw[:midpoint] + second_raw[midpoint:]).decode("ascii")

    _assert_generic_rejection(
        lambda: codec_one.recover(mixed, bindings, CursorRecoverySnapshot(candidates))
    )


def test_hsp08_restart_rotation_overlap_and_retirement(bindings: CursorBindings) -> None:
    old = CursorKeyring(active_kid="old", keys={"old": b"O" * 32})
    old_codec = CursorCodec(old, nonce_source=lambda size: b"R" * size)
    token, candidates = _token(old_codec, bindings)
    snapshot = CursorRecoverySnapshot(candidates)

    restarted = CursorCodec(CursorKeyring(active_kid="old", keys={"old": b"O" * 32}))
    assert restarted.recover(token, bindings, snapshot).last_sequence == 1

    overlap = CursorKeyring(active_kid="new", keys={"new": b"X" * 32, "old": b"O" * 32})
    overlap_codec = CursorCodec(overlap, nonce_source=lambda size: b"S" * size)
    assert overlap_codec.recover(token, bindings, snapshot).last_sequence == 1
    new_token, _ = _token(overlap_codec, bindings)
    decoded_new = base64.urlsafe_b64decode(new_token)
    assert b"new" in decoded_new

    retired = CursorCodec(CursorKeyring(active_kid="new", keys={"new": b"X" * 32}))
    _assert_generic_rejection(lambda: retired.recover(token, bindings, snapshot))

    unknown = CursorCodec(CursorKeyring(active_kid="other", keys={"other": b"Y" * 32}))
    _assert_generic_rejection(lambda: unknown.recover(new_token, bindings, snapshot))


@pytest.mark.parametrize(
    "candidates",
    [
        (_candidate(1),),
        (_candidate(0), _candidate(2)),
        (_candidate(0), _candidate(1, entry_label="entry-0")),
    ],
)
def test_hsp08_snapshot_sequences_must_be_contiguous_from_zero_and_entry_ids_unique(
    codec: CursorCodec,
    bindings: CursorBindings,
    candidates: tuple[JournalCursorCandidate, ...],
) -> None:
    valid = tuple(_candidate(sequence) for sequence in range(3))
    token = codec.issue(bindings, last=valid[0], high_watermark=valid[1])
    visited: list[int] = []

    _assert_generic_rejection(
        lambda: codec.recover(
            token,
            bindings,
            CursorRecoverySnapshot(candidates),
            scan_observer=lambda candidate: visited.append(candidate.sequence),
        )
    )
    assert len(visited) == len(candidates)


def test_hsp08_cursor_rejects_missing_positions_or_invalid_bounds(
    codec: CursorCodec, bindings: CursorBindings
) -> None:
    candidates = tuple(_candidate(sequence) for sequence in range(5))
    snapshot = CursorRecoverySnapshot(candidates)

    with pytest.raises(ValueError):
        codec.issue(bindings, last=None, high_watermark=candidates[3])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        codec.issue(bindings, last=candidates[4], high_watermark=candidates[3])

    token = codec.issue(bindings, last=candidates[1], high_watermark=candidates[3])
    _assert_generic_rejection(
        lambda: codec.recover(token, bindings, CursorRecoverySnapshot(candidates[:3]))
    )
    _assert_generic_rejection(
        lambda: codec.recover(token, bindings, CursorRecoverySnapshot(()))
    )
    assert codec.recover(token, bindings, snapshot).high_watermark_sequence == 3


@pytest.mark.parametrize(
    ("active_kid", "keys"),
    [
        ("missing", {"present": b"P" * 32}),
        ("", {"": b"P" * 32}),
        ("has space", {"has space": b"P" * 32}),
        ("x" * 33, {"x" * 33: b"P" * 32}),
        ("short", {"short": b"S" * 31}),
    ],
)
def test_hsp08_keyring_is_strict_and_secrets_are_at_least_32_bytes(active_kid, keys) -> None:
    with pytest.raises(ValueError):
        CursorKeyring(active_kid=active_kid, keys=keys)


def test_hsp08_nonce_source_must_return_exactly_16_bytes(
    keyring: CursorKeyring, bindings: CursorBindings
) -> None:
    last = _candidate(0)
    hwm = _candidate(1)
    for nonce in (b"short", b"L" * 17, "N" * 16):
        codec = CursorCodec(keyring, nonce_source=lambda _size, nonce=nonce: nonce)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="nonce source"):
            codec.issue(bindings, last=last, high_watermark=hwm)


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "sequence": -1,
            "appended_at": "2026-07-31T00:00:00Z",
            "entry_id": _digest("entry"),
            "chain_sha256": _digest("chain"),
        },
        {
            "sequence": True,
            "appended_at": "2026-07-31T00:00:00Z",
            "entry_id": _digest("entry"),
            "chain_sha256": _digest("chain"),
        },
        {
            "sequence": 0,
            "appended_at": "2026-07-31T00:00:00",
            "entry_id": _digest("entry"),
            "chain_sha256": _digest("chain"),
        },
        {
            "sequence": 0,
            "appended_at": "not-a-time",
            "entry_id": _digest("entry"),
            "chain_sha256": _digest("chain"),
        },
        {
            "sequence": 0,
            "appended_at": "2026-07-31/00:00:00Z",
            "entry_id": _digest("entry"),
            "chain_sha256": _digest("chain"),
        },
        {
            "sequence": 0,
            "appended_at": "2026-07-31T00:00:00.0000001Z",
            "entry_id": _digest("entry"),
            "chain_sha256": _digest("chain"),
        },
        {
            "sequence": 0,
            "appended_at": "2026-07-31T00:00:00Z",
            "entry_id": "",
            "chain_sha256": _digest("chain"),
        },
        {
            "sequence": 0,
            "appended_at": "2026-07-31T00:00:00Z",
            "entry_id": _digest("entry"),
            "chain_sha256": "not-a-hash",
        },
    ],
)
def test_hsp08_candidate_contract_is_strict(kwargs) -> None:
    with pytest.raises(ValueError):
        JournalCursorCandidate(**kwargs)


def test_hsp08_candidate_rejects_scalar_subclasses() -> None:
    valid = {
        "sequence": 0,
        "appended_at": "2026-07-31T00:00:00Z",
        "entry_id": _digest("entry"),
        "chain_sha256": _digest("chain"),
    }
    hostile_values = (
        ("sequence", _IntSubclass(0)),
        ("appended_at", _StringSubclass("2026-07-31T00:00:00Z")),
        ("entry_id", _StringSubclass(_digest("entry"))),
        ("chain_sha256", _StringSubclass(_digest("chain"))),
        ("appended_at", _EqualitySpoofingDatetime(2035, 1, 1, tzinfo=timezone.utc)),
    )

    for field, value in hostile_values:
        with pytest.raises(ValueError):
            JournalCursorCandidate(**(valid | {field: value}))
