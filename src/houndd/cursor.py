"""HSP-08: opaque, stateless journal cursor commitments."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType

from .query_contracts import parse_utc_instant


class CursorRejected(ValueError):
    """A cursor cannot be safely recovered."""

    def __init__(self) -> None:
        super().__init__("cursor rejected")


_MAGIC = b"HCUR"
_VERSION = 1
_KID_SIZE = 32
_NONCE_SIZE = 16
_COMMITMENT_SIZE = hashlib.sha256().digest_size
_COMMITMENT_DOMAINS = (
    b"service-generation",
    b"filter-hash",
    b"authenticated-principal",
    b"query-context-hash",
    b"last-sequence",
    b"last-chronological-tuple",
    b"high-watermark-anchor",
)
_HEADER_SIZE = len(_MAGIC) + 1 + 1 + _KID_SIZE + _NONCE_SIZE
_RAW_TOKEN_SIZE = _HEADER_SIZE + len(_COMMITMENT_DOMAINS) * _COMMITMENT_SIZE + _COMMITMENT_SIZE
_ENCODED_TOKEN_SIZE = len(base64.urlsafe_b64encode(b"\0" * _RAW_TOKEN_SIZE))
_KID_PATTERN = re.compile(r"[A-Za-z0-9._-]+", re.ASCII)
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
_COMMITMENT_PREFIX = b"hound/cursor/commitment/v1"
_OUTER_TAG_PREFIX = b"hound/cursor/outer-tag/v1"
_LEDGER_HWM_PREFIX = b"hound/intake-ledger/high-watermark/v1"


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"{label} must be valid UTF-8") from error
    return value


def _hash(value: object, label: str) -> str:
    value = _text(value, label)
    if _HASH_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _kid(value: object) -> str:
    value = _text(value, "key ID")
    try:
        encoded = value.encode("ascii")
    except UnicodeError as error:
        raise ValueError("key ID must be ASCII") from error
    if len(encoded) > _KID_SIZE or _KID_PATTERN.fullmatch(value) is None:
        raise ValueError("key ID must contain 1..32 safe ASCII characters")
    return value


def _sequence(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _utc_instant(value: object) -> datetime:
    if type(value) is str:
        try:
            return parse_utc_instant(value, "appended_at")
        except ValueError as error:
            raise ValueError("appended_at must be an aware ISO-8601 timestamp") from error
    if type(value) is not datetime:
        raise ValueError("appended_at must be an ISO-8601 timestamp")
    try:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("appended_at must include a timezone")
        return value.astimezone(timezone.utc)
    except (OverflowError, TypeError) as error:
        raise ValueError("appended_at must be a valid aware timestamp") from error


def _frame(*values: bytes) -> bytes:
    framed = bytearray()
    for value in values:
        framed.extend(len(value).to_bytes(8, "big"))
        framed.extend(value)
    return bytes(framed)


def _instant_bytes(value: datetime) -> bytes:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z").encode("ascii")


def _sequence_bytes(value: int) -> bytes:
    return str(value).encode("ascii")


@dataclass(frozen=True)
class CursorKeyring:
    """An immutable active signing key and zero or more verification keys."""

    active_kid: str
    keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        active_kid = _kid(self.active_kid)
        if not isinstance(self.keys, Mapping):
            raise ValueError("cursor keys must be a mapping")
        copied: dict[str, bytes] = {}
        for kid, secret in self.keys.items():
            normalized_kid = _kid(kid)
            if not isinstance(secret, bytes) or len(secret) < 32:
                raise ValueError("each cursor secret must be immutable bytes of at least 32 bytes")
            copied[normalized_kid] = secret
        if active_kid not in copied:
            raise ValueError("the active cursor key must exist")
        object.__setattr__(self, "active_kid", active_kid)
        object.__setattr__(self, "keys", MappingProxyType(copied))


@dataclass(frozen=True)
class CursorBindings:
    """Known query context to which a cursor is cryptographically bound."""

    service_generation: str
    filter_hash: str
    authenticated_principal: str
    query_context_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_generation", _text(self.service_generation, "service generation"))
        object.__setattr__(self, "filter_hash", _hash(self.filter_hash, "filter hash"))
        object.__setattr__(
            self,
            "authenticated_principal",
            _text(self.authenticated_principal, "authenticated principal"),
        )
        object.__setattr__(self, "query_context_hash", _hash(self.query_context_hash, "query-context hash"))


@dataclass(frozen=True)
class JournalCursorCandidate:
    """One event and its chain anchor from an already verified journal snapshot."""

    sequence: int
    entry_id: str
    appended_at: datetime | str
    chain_sha256: str

    def __post_init__(self) -> None:
        if type(self.entry_id) is not str or type(self.chain_sha256) is not str:
            raise ValueError("candidate entry ID and chain hash must be exact strings")
        object.__setattr__(self, "sequence", _sequence(self.sequence, "candidate sequence"))
        object.__setattr__(self, "entry_id", _hash(self.entry_id, "candidate entry ID"))
        object.__setattr__(self, "appended_at", _utc_instant(self.appended_at))
        object.__setattr__(self, "chain_sha256", _hash(self.chain_sha256, "candidate chain hash"))

    @property
    def chronological_order(self) -> tuple[datetime, int, str]:
        return (self.appended_at, self.sequence, self.entry_id)  # type: ignore[return-value]


@dataclass(frozen=True)
class CursorRecoverySnapshot:
    """In-memory candidates from the verified journal snapshot used for recovery."""

    candidates: tuple[JournalCursorCandidate, ...]

    def __init__(self, candidates: Iterable[JournalCursorCandidate]) -> None:
        try:
            copied = tuple(candidates)
        except TypeError as error:
            raise ValueError("cursor recovery candidates must be iterable") from error
        if any(not isinstance(candidate, JournalCursorCandidate) for candidate in copied):
            raise ValueError("cursor recovery candidates must be journal candidates")
        object.__setattr__(self, "candidates", copied)

    @property
    def current_head(self) -> int:
        return self.candidates[-1].sequence if self.candidates else -1


@dataclass(frozen=True)
class CursorRecovery:
    """Recovered positions needed for chronological resume within the old HWM."""

    last: JournalCursorCandidate
    high_watermark: JournalCursorCandidate

    @property
    def last_sequence(self) -> int:
        return self.last.sequence

    @property
    def high_watermark_sequence(self) -> int:
        return self.high_watermark.sequence

    @property
    def resume_after(self) -> tuple[datetime, int, str]:
        return self.last.chronological_order


@dataclass(frozen=True)
class _DecodedToken:
    kid: str
    nonce: bytes
    commitments: tuple[bytes, ...]
    tag: bytes
    authenticated_bytes: bytes


def _binding_context(bindings: CursorBindings) -> bytes:
    return _frame(
        bindings.service_generation.encode("utf-8"),
        bindings.filter_hash.encode("ascii"),
        bindings.authenticated_principal.encode("utf-8"),
        bindings.query_context_hash.encode("ascii"),
    )


def _commitment(
    secret: bytes,
    *,
    kid: str,
    nonce: bytes,
    bindings: CursorBindings,
    domain: bytes,
    value: bytes,
) -> bytes:
    message = _frame(
        _COMMITMENT_PREFIX,
        bytes((_VERSION,)),
        kid.encode("ascii"),
        nonce,
        _binding_context(bindings),
        domain,
        value,
    )
    return hmac.new(secret, message, hashlib.sha256).digest()


def _known_values(bindings: CursorBindings) -> tuple[bytes, ...]:
    return (
        bindings.service_generation.encode("utf-8"),
        bindings.filter_hash.encode("ascii"),
        bindings.authenticated_principal.encode("utf-8"),
        bindings.query_context_hash.encode("ascii"),
    )


def _tuple_value(candidate: JournalCursorCandidate) -> bytes:
    return _frame(
        _instant_bytes(candidate.appended_at),  # type: ignore[arg-type]
        _sequence_bytes(candidate.sequence),
        candidate.entry_id.encode("ascii"),
    )


def _anchor_value(candidate: JournalCursorCandidate) -> bytes:
    return _frame(
        _sequence_bytes(candidate.sequence),
        candidate.entry_id.encode("ascii"),
        candidate.chain_sha256.encode("ascii"),
    )


def _header(kid: str, nonce: bytes) -> bytes:
    encoded_kid = kid.encode("ascii")
    return (
        _MAGIC
        + bytes((_VERSION, len(encoded_kid)))
        + encoded_kid.ljust(_KID_SIZE, b"\0")
        + nonce
    )


def _outer_tag(secret: bytes, authenticated_bytes: bytes) -> bytes:
    return hmac.new(secret, _frame(_OUTER_TAG_PREFIX, authenticated_bytes), hashlib.sha256).digest()


def _decode_token(token: object) -> _DecodedToken:
    if not isinstance(token, str) or len(token) != _ENCODED_TOKEN_SIZE:
        raise CursorRejected()
    raw: bytes | None
    try:
        encoded = token.encode("ascii")
        raw = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        raw = None
    if raw is None:
        raise CursorRejected()
    if len(raw) != _RAW_TOKEN_SIZE or base64.urlsafe_b64encode(raw) != encoded:
        raise CursorRejected()
    if raw[: len(_MAGIC)] != _MAGIC or raw[len(_MAGIC)] != _VERSION:
        raise CursorRejected()
    kid_length_offset = len(_MAGIC) + 1
    kid_length = raw[kid_length_offset]
    kid_offset = kid_length_offset + 1
    kid_slot = raw[kid_offset : kid_offset + _KID_SIZE]
    if not 1 <= kid_length <= _KID_SIZE or any(kid_slot[kid_length:]):
        raise CursorRejected()
    try:
        decoded_kid = kid_slot[:kid_length].decode("ascii")
    except (UnicodeError, ValueError):
        decoded_kid = None
    if decoded_kid is None:
        raise CursorRejected()
    try:
        kid = _kid(decoded_kid)
    except ValueError:
        kid = None
    if kid is None:
        raise CursorRejected()
    nonce_offset = kid_offset + _KID_SIZE
    nonce = raw[nonce_offset : nonce_offset + _NONCE_SIZE]
    commitments_offset = nonce_offset + _NONCE_SIZE
    commitments_end = commitments_offset + len(_COMMITMENT_DOMAINS) * _COMMITMENT_SIZE
    commitments = tuple(
        raw[offset : offset + _COMMITMENT_SIZE]
        for offset in range(commitments_offset, commitments_end, _COMMITMENT_SIZE)
    )
    return _DecodedToken(
        kid=kid,
        nonce=nonce,
        commitments=commitments,
        tag=raw[commitments_end:],
        authenticated_bytes=raw[:commitments_end],
    )


class CursorCodec:
    """Issue and recover fixed-schema cursor commitment tokens without state."""

    def __init__(
        self,
        keyring: CursorKeyring,
        *,
        nonce_source: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if not isinstance(keyring, CursorKeyring):
            raise ValueError("cursor codec requires a keyring")
        if not callable(nonce_source):
            raise ValueError("cursor nonce source must be callable")
        self._keyring = keyring
        self._nonce_source = nonce_source

    @property
    def keyring(self) -> CursorKeyring:
        return self._keyring

    def _authenticated_token(self, token: str) -> tuple[_DecodedToken, bytes]:
        decoded = _decode_token(token)
        secret = self._keyring.keys.get(decoded.kid)
        if secret is None:
            raise CursorRejected()
        if not hmac.compare_digest(decoded.tag, _outer_tag(secret, decoded.authenticated_bytes)):
            raise CursorRejected()
        return decoded, secret

    def authenticate(self, token: str) -> None:
        """Reject malformed, unknown-key, or forged tokens before context work."""

        self._authenticated_token(token)

    def intake_high_watermark_commitment(
        self,
        bindings: CursorBindings,
        high_watermark: JournalCursorCandidate | None,
        *,
        cursor: str | None = None,
    ) -> str:
        """Return an opaque ledger HWM commitment without disclosing its anchor.

        Continuations use the cursor's authenticated (possibly retired-active)
        signing key.  This leaves the visible commitment stable through a key
        rotation while that cursor remains recoverable, without carrying the
        key ID, sequence, entry ID, or chain digest on the wire.
        """

        if type(bindings) is not CursorBindings:
            raise ValueError("ledger commitment requires validated bindings")
        if high_watermark is not None and type(high_watermark) is not JournalCursorCandidate:
            raise ValueError("ledger commitment requires a canonical high-watermark")
        if cursor is None:
            secret = self._keyring.keys[self._keyring.active_kid]
        else:
            _decoded, secret = self._authenticated_token(cursor)
        anchor = b"" if high_watermark is None else _anchor_value(high_watermark)
        value = hmac.new(
            secret,
            _frame(_LEDGER_HWM_PREFIX, _binding_context(bindings), anchor),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(value).decode("ascii")

    def issue(
        self,
        bindings: CursorBindings,
        *,
        last: JournalCursorCandidate,
        high_watermark: JournalCursorCandidate,
    ) -> str:
        if not isinstance(bindings, CursorBindings):
            raise ValueError("cursor issue requires validated bindings")
        if not isinstance(last, JournalCursorCandidate):
            raise ValueError("cursor issue requires a last authorized result")
        if not isinstance(high_watermark, JournalCursorCandidate):
            raise ValueError("cursor issue requires a journal high-watermark anchor")
        if last.sequence > high_watermark.sequence:
            raise ValueError("the last result cannot exceed the high-watermark")
        nonce = self._nonce_source(_NONCE_SIZE)
        if not isinstance(nonce, bytes) or len(nonce) != _NONCE_SIZE:
            raise ValueError("cursor nonce source must return exactly 16 immutable bytes")
        kid = self._keyring.active_kid
        secret = self._keyring.keys[kid]
        values = (
            *_known_values(bindings),
            _sequence_bytes(last.sequence),
            _tuple_value(last),
            _anchor_value(high_watermark),
        )
        commitments = b"".join(
            _commitment(
                secret,
                kid=kid,
                nonce=nonce,
                bindings=bindings,
                domain=domain,
                value=value,
            )
            for domain, value in zip(_COMMITMENT_DOMAINS, values, strict=True)
        )
        authenticated_bytes = _header(kid, nonce) + commitments
        raw = authenticated_bytes + _outer_tag(secret, authenticated_bytes)
        return base64.urlsafe_b64encode(raw).decode("ascii")

    def recover(
        self,
        token: str,
        bindings: CursorBindings,
        snapshot: CursorRecoverySnapshot,
        *,
        scan_observer: Callable[[JournalCursorCandidate], None] | None = None,
    ) -> CursorRecovery:
        decoded, secret = self._authenticated_token(token)
        if not isinstance(bindings, CursorBindings) or not isinstance(snapshot, CursorRecoverySnapshot):
            raise CursorRejected()
        known_match = True
        for domain, value, supplied in zip(
            _COMMITMENT_DOMAINS[:4],
            _known_values(bindings),
            decoded.commitments[:4],
            strict=True,
        ):
            expected = _commitment(
                secret,
                kid=decoded.kid,
                nonce=decoded.nonce,
                bindings=bindings,
                domain=domain,
                value=value,
            )
            known_match &= hmac.compare_digest(supplied, expected)
        if not known_match:
            raise CursorRejected()
        return self._recover_positions(
            decoded,
            secret,
            bindings,
            snapshot,
            scan_observer=scan_observer,
        )

    @staticmethod
    def _recover_positions(
        decoded: _DecodedToken,
        secret: bytes,
        bindings: CursorBindings,
        snapshot: CursorRecoverySnapshot,
        *,
        scan_observer: Callable[[JournalCursorCandidate], None] | None,
    ) -> CursorRecovery:
        last_sequence_candidate: JournalCursorCandidate | None = None
        last_tuple_candidate: JournalCursorCandidate | None = None
        high_watermark_candidate: JournalCursorCandidate | None = None
        last_sequence_matches = 0
        last_tuple_matches = 0
        high_watermark_matches = 0
        invalid_snapshot = False
        seen_entry_ids: set[str] = set()
        seen_chain_hashes: set[str] = set()

        for expected_sequence, candidate in enumerate(snapshot.candidates):
            if scan_observer is not None:
                scan_observer(candidate)
            if candidate.sequence != expected_sequence:
                invalid_snapshot = True
            if candidate.entry_id in seen_entry_ids or candidate.chain_sha256 in seen_chain_hashes:
                invalid_snapshot = True
            seen_entry_ids.add(candidate.entry_id)
            seen_chain_hashes.add(candidate.chain_sha256)

            sequence_commitment = _commitment(
                secret,
                kid=decoded.kid,
                nonce=decoded.nonce,
                bindings=bindings,
                domain=_COMMITMENT_DOMAINS[4],
                value=_sequence_bytes(candidate.sequence),
            )
            tuple_commitment = _commitment(
                secret,
                kid=decoded.kid,
                nonce=decoded.nonce,
                bindings=bindings,
                domain=_COMMITMENT_DOMAINS[5],
                value=_tuple_value(candidate),
            )
            anchor_commitment = _commitment(
                secret,
                kid=decoded.kid,
                nonce=decoded.nonce,
                bindings=bindings,
                domain=_COMMITMENT_DOMAINS[6],
                value=_anchor_value(candidate),
            )
            if hmac.compare_digest(decoded.commitments[4], sequence_commitment):
                last_sequence_candidate = candidate
                last_sequence_matches += 1
            if hmac.compare_digest(decoded.commitments[5], tuple_commitment):
                last_tuple_candidate = candidate
                last_tuple_matches += 1
            if hmac.compare_digest(decoded.commitments[6], anchor_commitment):
                high_watermark_candidate = candidate
                high_watermark_matches += 1

        positions_valid = (
            not invalid_snapshot
            and last_sequence_matches == 1
            and last_tuple_matches == 1
            and high_watermark_matches == 1
            and last_sequence_candidate is last_tuple_candidate
            and last_sequence_candidate is not None
            and high_watermark_candidate is not None
        )
        if not positions_valid:
            raise CursorRejected()
        current_head = len(snapshot.candidates) - 1
        if not 0 <= last_sequence_candidate.sequence <= high_watermark_candidate.sequence <= current_head:
            raise CursorRejected()
        return CursorRecovery(last_sequence_candidate, high_watermark_candidate)


__all__ = [
    "CursorBindings",
    "CursorCodec",
    "CursorKeyring",
    "CursorRecovery",
    "CursorRecoverySnapshot",
    "CursorRejected",
    "JournalCursorCandidate",
]
