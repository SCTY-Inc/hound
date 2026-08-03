"""Slice 3B's intentionally small local Unix-socket read boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import ctypes
import errno
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .access import AccessRefusal, AuthenticatedPrincipal, EventSelector, PolicyBundle, PolicyRule, PrincipalScope, ProducerClaim, ProducerSelector, resolve_commit_access, resolve_scope
from .adapter_host import ADAPTER_ENV_KEYS, AdapterHost, AdapterHostError
from .commit import ADAPTER_OPERATIONS, CommitContractError, CommitRequest, SourceError, make_commit_response, normalize_source, parse_commit_request, resolve_route
from .commit_runtime import CommitCollision, CommitIntegrityError, CommitRefusal, CommitRuntime, CommitRuntimeError, CommitUnavailable
from .phi import PhiInputError, PhiManifestError, PhiScanner, phi_manifest_path
from .contracts import canonical_bytes
from .query_contracts import QueryContractError, parse_query_request
from .query_engine import QuerySnapshotError
from .reads import ReadContractError, parse_entry_request, parse_record_request, read_record, select_entry, select_record, verified_events
from .snapshot import DurableJournalQueryAdapter, DurableQueryError, QueryFilterNotAvailable
from .intake_projection import IntakeProjectionError, project_intake_ledger_page
from .service_identity import ServiceIdentity, ServiceIdentityError
from . import HounddStore
from ._safety import AnchoredRoot
from .journal import JournalError
from .store import StoreError
from .verify import verify_store


WIRE_VERSION = "houndd.uds.v1"
MAX_FRAME_BYTES = 1_048_576
MAX_WIRE_FRAME_BYTES = MAX_FRAME_BYTES + 2_048
CONNECTION_TIMEOUT_SECONDS = 0.2
ACCEPT_TIMEOUT_SECONDS = 0.2
REQUEST_SCHEMA = "houndd.read-request.v1"
RESPONSE_SCHEMA = "houndd.read-response.v1"
_REQUEST_FIELDS = frozenset({"schema_version", "request_id", "producer", "requested_access", "policy_id", "operation"})
_RESPONSE_REQUIRED = frozenset({"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage"})
_RESPONSE_OPTIONAL = frozenset({"result", "cursor", "projection", "error"})
_FRAME_FIELDS = frozenset({"wire_version", "method", "path", "body"})
_READ_OPERATIONS = frozenset({"service.health", "service.ready", "journal.query", "journal.get", "record.get"})
_ACCESS_CEILINGS = {
    "public": frozenset({"public"}),
    "workspace": frozenset({"public", "workspace"}),
    "restricted": frozenset({"public", "workspace", "restricted"}),
}
_RENAME_NOREPLACE = 1


def _rename_noreplace(source: str, destination: str, *, directory_fd: int) -> None:
    """Atomically publish a privately-bound socket name without replacement."""

    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:  # pragma: no cover - certified Linux exposes it
        raise ServiceError("atomic socket publication is unavailable") from error
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(directory_fd, os.fsencode(source), directory_fd, os.fsencode(destination), _RENAME_NOREPLACE) != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise ServiceError("socket path is already occupied")
        raise ServiceError("atomic socket publication failed") from OSError(number, os.strerror(number))


class ServiceError(RuntimeError):
    """A service startup or protocol condition that must fail closed."""


class FrameError(ServiceError):
    """The peer did not send exactly one bounded canonical frame.

    A framing failure is normally deliberately silent.  ``request_id`` is set
    only when a complete UTF-8 JSON frame contains exactly one safely bounded
    body request ID; this permits the one recoverable logical 400 required by
    the wire contract without manufacturing an identifier from damaged bytes.
    """

    def __init__(self, message: str, *, request_id: str | None = None, commit: bool = False) -> None:
        super().__init__(message)
        self.request_id = request_id
        self.commit = commit


class RequestError(ServiceError):
    """The authenticated request does not meet the Slice 3B contract."""


class PolicyError(ServiceError):
    """The operator-provisioned policy is absent, unsafe, or ambiguous."""


class ResponseTooLarge(ServiceError):
    """An otherwise valid response exceeds the fixed wire bound."""


class EncodedResponse(dict[str, Any]):
    """A response with its one canonical wire encoding retained for send."""

    def __init__(self, value: dict[str, Any], wire: bytes) -> None:
        super().__init__(value)
        self.wire = wire


@dataclass(frozen=True, slots=True)
class FrozenPolicy:
    bundle: PolicyBundle
    fingerprint: tuple[int, int, int, int, int, int, str]
    service_root: AnchoredRoot
    policy_fd: int


def _canonical_load(raw: bytes, label: str, error_type: type[ServiceError] = PolicyError) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeError, ValueError) as error:
        raise error_type(f"{label} is not canonical UTF-8 JSON") from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise error_type(f"{label} is not canonical JSON")
    return value


def _private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise ServiceError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ServiceError(f"{label} must be current-user 0700 directory")


def _policy_fingerprint(service_root: AnchoredRoot, descriptor: int) -> tuple[bytes, tuple[int, int, int, int, int, int, str]]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1:
            raise PolicyError("policy file must be current-user 0600 regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            if sum(map(len, chunks)) + len(chunk) > MAX_FRAME_BYTES:
                raise PolicyError("policy file exceeds the bounded policy size")
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as error:
        raise PolicyError("policy file cannot be read") from error
    try:
        # The service directory and policy leaf must still be the objects
        # opened at startup.  All lookup is relative to the held descriptor.
        with service_root.operation():
            visible = os.stat("policy.json", dir_fd=service_root.fd, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (before.st_dev, before.st_ino) != (visible.st_dev, visible.st_ino):
                raise PolicyError("policy file changed while read")
    except OSError as error:
        raise PolicyError("policy file disappeared") from error
    if not stat.S_ISREG(visible.st_mode):
        raise PolicyError("policy file changed while read")
    return raw, (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_size, after.st_mtime_ns, hashlib.sha256(raw).hexdigest())


def _selector(value: object, label: str) -> ProducerSelector:
    if type(value) is not dict or set(value) != {"owner_id", "capability", "run_id"}:
        raise PolicyError(f"{label} must have exact producer selector fields")
    try:
        return ProducerSelector(value["owner_id"], value["capability"], value["run_id"])
    except (TypeError, ValueError) as error:
        raise PolicyError(f"{label} is invalid") from error


def _rule(value: object) -> PolicyRule:
    fields = {"subject", "claim_selector", "policy_id", "event_producer_selectors", "readable_tiers", "allowed_output_tiers"}
    if type(value) is not dict or set(value) != fields:
        raise PolicyError("policy rule has missing or unknown fields")
    selectors = value["event_producer_selectors"]
    if type(selectors) is not list or not selectors:
        raise PolicyError("policy rule event selectors must be a nonempty array")
    for key in ("readable_tiers", "allowed_output_tiers"):
        if type(value[key]) is not list or not value[key]:
            raise PolicyError(f"policy rule {key} must be a nonempty array")
    try:
        return PolicyRule(
            subject=value["subject"],
            claim_selector=_selector(value["claim_selector"], "claim_selector"),
            policy_id=value["policy_id"],
            event_producer_selectors=tuple(_selector(item, "event_producer_selectors[]") for item in selectors),
            readable_tiers=frozenset(value["readable_tiers"]),
            allowed_output_tiers=frozenset(value["allowed_output_tiers"]),
        )
    except (TypeError, ValueError) as error:
        raise PolicyError("policy rule is invalid") from error


def load_frozen_policy(state_root: Path) -> FrozenPolicy:
    _private_directory(state_root, "state directory")
    service = state_root / "service"
    _private_directory(service, "service directory")
    service_root: AnchoredRoot | None = None
    descriptor: int | None = None
    try:
        service_root = AnchoredRoot(service, error_type=PolicyError)
        descriptor = service_root.open_file("policy.json", flags=os.O_RDONLY)
        raw, fingerprint = _policy_fingerprint(service_root, descriptor)
        value = _canonical_load(raw, "policy file")
        if set(value) != {"schema_version", "rules"} or value["schema_version"] != "houndd.policy.v1" or type(value["rules"]) is not list or not value["rules"]:
            raise PolicyError("policy file has unsupported schema or fields")
        rules = tuple(_rule(item) for item in value["rules"])
        bundle = PolicyBundle(rules)
        if len(bundle.rules) != len(rules):
            raise PolicyError("policy file must not duplicate rules")
        return FrozenPolicy(bundle, fingerprint, service_root, descriptor)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if service_root is not None:
            service_root.close()
        raise


def _assert_frozen(policy: FrozenPolicy, state_root: Path) -> None:
    # ``state_root`` is retained in this signature to make the service's
    # policy boundary explicit; it is never used for a second pathname lookup.
    del state_root
    _raw, fingerprint = _policy_fingerprint(policy.service_root, policy.policy_fd)
    if fingerprint != policy.fingerprint:
        raise PolicyError("policy changed after service startup")


def _phi_fingerprint(path: Path) -> tuple[int, int, int, int, int, int, int]:
    """Bind write readiness to the exact operator-provisioned manifest leaf."""

    try:
        info = path.lstat()
    except OSError as error:
        raise PhiManifestError("clear manifest is unavailable") from error
    if not stat.S_ISREG(info.st_mode):
        raise PhiManifestError("clear manifest is unsafe")
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns)


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise FrameError("truncated frame")
        data.extend(part)
    return bytes(data)


def _recover_frame_context(raw: bytes) -> tuple[str | None, bool]:
    """Extract one body request ID and an exact POST hint without accepting."""

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=lambda pairs: pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeError, ValueError):
        return None, False
    if type(value) is not list:
        return None, False
    methods = [item for key, item in value if type(key) is str and key == "method"]
    is_commit = len(methods) == 1 and type(methods[0]) is str and methods[0] == "POST"
    bodies = [item for key, item in value if type(key) is str and key == "body"]
    if len(bodies) != 1 or type(bodies[0]) is not list:
        return None, is_commit
    ids = [item for key, item in bodies[0] if type(key) is str and key == "request_id"]
    if len(ids) != 1:
        return None, is_commit
    try:
        return _text(ids[0], "request_id"), is_commit
    except RequestError:
        return None, is_commit


def read_frame(connection: socket.socket) -> dict[str, Any]:
    header = _read_exact(connection, 4)
    size = int.from_bytes(header, "big")
    if not 0 < size <= MAX_WIRE_FRAME_BYTES:
        raise FrameError("frame size is invalid")
    raw = _read_exact(connection, size)
    request_id, is_commit = _recover_frame_context(raw)
    if connection.recv(1):
        raise FrameError("connection contains trailing or second frame bytes", request_id=request_id, commit=is_commit)
    try:
        value = _canonical_load(raw, "wire frame", FrameError)
    except FrameError as error:
        raise FrameError(str(error), request_id=request_id, commit=is_commit) from error
    if set(value) != _FRAME_FIELDS or value.get("wire_version") != WIRE_VERSION or value.get("method") not in {"GET", "POST"} or type(value.get("path")) is not str or type(value.get("body")) is not dict:
        raise FrameError("wire frame fields are invalid", request_id=request_id, commit=is_commit)
    if len(canonical_bytes(value["body"])) > MAX_FRAME_BYTES:
        raise FrameError("read envelope body exceeds 1048576 bytes", request_id=request_id, commit=is_commit)
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or len(value) > 512:
        raise RequestError(f"{label} must be a bounded nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise RequestError(f"{label} is not valid Unicode") from error
    return value


def _request_id(body: object) -> str | None:
    if type(body) is not dict:
        return None
    value = body.get("request_id")
    try:
        return _text(value, "request_id")
    except RequestError:
        return None


@dataclass(frozen=True, slots=True)
class ReadRequest:
    request_id: str
    claim: ProducerClaim
    requested_access: str
    policy_id: str
    operation: str
    payload: dict[str, Any]


def parse_read_request(value: object) -> ReadRequest:
    if type(value) is not dict or set(value) != _REQUEST_FIELDS or value.get("schema_version") != REQUEST_SCHEMA:
        raise RequestError("read envelope has missing or unknown fields")
    producer = value["producer"]
    operation = value["operation"]
    if type(producer) is not dict or set(producer) != {"owner_id", "capability", "run_id"} or type(operation) is not dict or set(operation) != {"name", "payload"} or type(operation["payload"]) is not dict:
        raise RequestError("read envelope producer or operation is invalid")
    requested_access = value["requested_access"]
    if requested_access not in _ACCESS_CEILINGS:
        raise RequestError("requested_access is invalid")
    if operation["name"] not in _READ_OPERATIONS:
        raise RequestError("operation.name is not a read operation")
    try:
        return ReadRequest(
            _text(value["request_id"], "request_id"),
            ProducerClaim(producer["owner_id"], producer["capability"], producer["run_id"]),
            requested_access,
            _text(value["policy_id"], "policy_id"),
            _text(operation["name"], "operation.name"),
            operation["payload"],
        )
    except (TypeError, ValueError) as error:
        raise RequestError("read envelope values are invalid") from error


def _encode_response(value: dict[str, Any]) -> bytes:
    raw = canonical_bytes(value)
    if len(raw) > MAX_FRAME_BYTES:
        raise ResponseTooLarge("encoded response exceeds 1048576 bytes")
    return len(raw).to_bytes(4, "big") + raw


def _response(request_id: str, status: int, *, outcome: str, result: list[dict[str, Any]] | None = None, entry_ids: list[str] | None = None, record_ids: list[str] | None = None, cursor: str | None = None, projection: dict[str, str] | None = None, error: tuple[str, bool, str] | None = None) -> EncodedResponse:
    body: dict[str, Any] = {"schema_version": RESPONSE_SCHEMA, "request_id": request_id, "ok": status == 200, "outcome": outcome, "record_ids": [], "entry_ids": [], "usage": {"requests": 0, "bytes": 0, "cost": 0}}
    if result is not None:
        # Canonical-event results derive their aligned IDs; a record result is
        # not a journal event and must state the IDs it aligns with instead.
        body["result"] = result
        body["entry_ids"] = [event["entry_id"] for event in result] if entry_ids is None else entry_ids
        body["record_ids"] = [event["artifact"]["record_id"] for event in result] if record_ids is None else record_ids
    if cursor is not None:
        body["cursor"] = cursor
    if projection is not None:
        if status != 200 or type(projection) is not dict or set(projection) != {"schema_version", "integrity", "high_watermark"} or projection.get("schema_version") != "houndd.intake-ledger.v1" or projection.get("integrity") != "verified" or type(projection.get("high_watermark")) is not str or not projection["high_watermark"]:
            raise ResponseTooLarge("ledger projection is invalid")
        body["projection"] = projection
    if error is not None:
        body["error"] = {"code": error[0], "retryable": error[1], "message": error[2]}
    value = {"wire_version": WIRE_VERSION, "status": status, "body": body}
    return EncodedResponse(value, _encode_response(value))


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


def _generic_response(request_id: str, *, ready: bool) -> dict[str, Any]:
    return _response(request_id, 200 if ready else 503, outcome="completed" if ready else "unavailable", error=None if ready else ("service_unavailable", True, "service is not ready"))


def _commit_response(
    request_id: str,
    status: int,
    *,
    ok: bool,
    outcome: str,
    record_ids: list[str] | None = None,
    entry_ids: list[str] | None = None,
    usage: dict[str, int] | None = None,
    error_code: str | None = None,
) -> EncodedResponse:
    """Encode the strict Slice 3C1 response without borrowing read fields."""

    error = None
    if error_code is not None:
        safe = {
            "source_refused": {"code": "source_refused", "retryable": False, "message": "source refused"},
            "invalid_request": {"code": "invalid_request", "retryable": False, "message": "invalid request"},
            "request_conflict": {"code": "request_conflict", "retryable": False, "message": "request conflict"},
            "unavailable": {"code": "unavailable", "retryable": True, "message": "service unavailable"},
        }
        error = safe[error_code]
    body = make_commit_response(
        request_id,
        ok=ok,
        outcome=outcome,
        record_ids=[] if record_ids is None else record_ids,
        entry_ids=[] if entry_ids is None else entry_ids,
        usage={"requests": 0, "bytes": 0, "cost": 0} if usage is None else usage,
        error=error,
    )
    value = {"wire_version": WIRE_VERSION, "status": status, "body": body}
    return EncodedResponse(value, _encode_response(value))


class HounddService:
    """Foreground-only local service; it owns no scheduler or request cache."""

    def __init__(self, *, state_root: str | Path, socket_path: str | Path, adapter_host: AdapterHost | None = None) -> None:
        self._owner_pid = os.getpid()
        self.state_root = Path(state_root)
        self.socket_path = Path(socket_path)
        if not self.state_root.is_absolute() or not self.socket_path.is_absolute():
            raise ServiceError("state and socket paths must be absolute")
        # Provider credentials are captured once, here, and never re-read from
        # the process environment on a request path.
        try:
            self.adapter_host = adapter_host if adapter_host is not None else AdapterHost.from_env({key: os.environ[key] for key in ADAPTER_ENV_KEYS if key in os.environ})
        except AdapterHostError as error:
            raise ServiceError("adapter host cannot be frozen at startup") from error
        self._listener: socket.socket | None = None
        self._closed = False
        self.store: HounddStore | None = None
        self.identity: ServiceIdentity | None = None
        self.policy: FrozenPolicy | None = None
        self.phi_scanner: PhiScanner | None = None
        self._phi_fingerprint: tuple[int, int, int, int, int, int, int] | None = None
        self.commit_runtime: CommitRuntime | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._runtime_root: AnchoredRoot | None = None
        try:
            self.store = HounddStore(self.state_root)
            self.store.recover()
            if not self.store.verify()["valid"]:
                raise ServiceError("startup recovery verification failed")
            self.policy = load_frozen_policy(self.state_root)
            # Slice 3B reads remain available without a 3C1 scanner.  The
            # scanner is nevertheless frozen at startup when provisioned, and
            # commits fail unavailable rather than loading it lazily.
            try:
                self.phi_scanner = PhiScanner.from_path(phi_manifest_path(self.state_root))
                self._phi_fingerprint = _phi_fingerprint(phi_manifest_path(self.state_root))
            except PhiManifestError:
                self.phi_scanner = None
                self._phi_fingerprint = None
            self.commit_runtime = CommitRuntime(self.state_root)
            self.commit_runtime.reconcile()
            self.store.rebuild_index()
            if not verify_store(self.state_root)["valid"]:
                raise ServiceError("commit recovery verification failed")
            self.identity = ServiceIdentity(self.state_root, create=True)
            self._bind()
        except Exception:
            self.close()
            raise

    def _bind(self) -> None:
        parent = self.socket_path.parent
        runtime_root = AnchoredRoot(parent, error_type=ServiceError, create=True)
        self._runtime_root = runtime_root
        _private_directory(parent, "runtime directory")
        name = self.socket_path.name
        temporary = f".{name}.houndd.{self._owner_pid}.{secrets.token_hex(16)}"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # This spelling remains tied to the held runtime directory FD;
            # publication below is an atomic no-replace rename through it.
            listener.bind(f"/proc/self/fd/{runtime_root.fd}/{temporary}")
            # The private temporary name is addressed through the held parent
            # descriptor, so its mode can be set before publication without a
            # caller-controlled pathname race.
            os.chmod(f"/proc/self/fd/{runtime_root.fd}/{temporary}", 0o600)
            with runtime_root.operation():
                _rename_noreplace(temporary, name, directory_fd=runtime_root.fd)
                info = os.stat(name, dir_fd=runtime_root.fd, follow_symlinks=False)
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise ServiceError("socket permissions are unsafe")
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
                raise ServiceError("socket ownership is unsafe")
            listener.listen(32)
            # A bounded accept is the close linearization point: closing a
            # listening AF_UNIX descriptor in another thread is not a
            # portable wakeup guarantee on its own.
            listener.settimeout(ACCEPT_TIMEOUT_SECONDS)
            self._socket_identity = (info.st_dev, info.st_ino)
            self._listener = listener
            # A self-connect must arrive at this listener before it becomes
            # public.  It detects any namespace replacement after publication
            # without ever contacting a non-local transport.
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(1)
                probe.connect(os.fspath(self.socket_path))
                accepted, _ = listener.accept()
                accepted.close()
            self._assert_socket_binding()
        except Exception:
            try:
                os.unlink(temporary, dir_fd=runtime_root.fd)
            except OSError:
                pass
            listener.close()
            raise

    @staticmethod
    def _clamp_scope(principal: AuthenticatedPrincipal, scope: PrincipalScope, tiers: frozenset[str]) -> PrincipalScope:
        """Intersect a resolved scope's readable tiers with a disclosure ceiling."""

        selectors = tuple(
            EventSelector(selector.policy_id, selector.producer_selector, selector.readable_tiers & tiers)
            for selector in scope.permitted_event_selectors
            if selector.readable_tiers & tiers
        )
        return PrincipalScope(principal, frozenset(tiers), selectors)

    def _scope(self, principal: AuthenticatedPrincipal, request: ReadRequest):
        assert self.policy is not None
        matches = tuple(rule for rule in self.policy.bundle.rules if rule.subject == principal.subject and rule.claim_selector.matches(request.claim) and rule.policy_id == request.policy_id)
        if len(matches) != 1:
            return None
        rule = matches[0]
        scope = resolve_scope(PolicyBundle((rule,)), principal, request.claim)
        if scope is None:
            return None
        tiers = scope.readable_tiers & _ACCESS_CEILINGS[request.requested_access]
        if not tiers:
            return None
        clamped = self._clamp_scope(principal, scope, tiers)
        if not clamped.permitted_event_selectors:
            return None
        return clamped

    def _commit_scope(self, principal: AuthenticatedPrincipal, request: CommitRequest):
        """Select exactly one policy/rule and clamp output and lineage scope to its ceiling."""

        assert self.policy is not None
        claim = ProducerClaim(request.producer.owner_id, request.producer.capability, request.producer.run_id)
        matches = tuple(
            rule
            for rule in self.policy.bundle.rules
            if rule.subject == principal.subject and rule.claim_selector.matches(claim) and rule.policy_id == request.policy_id
        )
        if len(matches) != 1:
            return None
        access = resolve_commit_access(matches[0], request.requested_access)
        if type(access) is AccessRefusal:
            return None
        # The read scope is used only to authorize the legacy lineage scan;
        # source, record and transaction work occurs after this point. An
        # empty clamped scope is a legitimate "selects nothing" lineage scan,
        # not an authorization denial, so it is never collapsed to None here.
        scope = resolve_scope(PolicyBundle((matches[0],)), principal, claim)
        if scope is None:
            return None
        tiers = scope.readable_tiers & _ACCESS_CEILINGS[request.requested_access]
        return access.access, self._clamp_scope(principal, scope, tiers)

    def _assert_socket_binding(self) -> None:
        listener = self._listener
        identity = self._socket_identity
        runtime_root = self._runtime_root
        if listener is None or identity is None or runtime_root is None:
            raise ServiceError("service socket is unavailable")
        try:
            with runtime_root.operation():
                visible = os.stat(self.socket_path.name, dir_fd=runtime_root.fd, follow_symlinks=False)
        except OSError as error:
            raise ServiceError("service socket binding is unavailable") from error
        if (
            not stat.S_ISSOCK(visible.st_mode)
            or (visible.st_dev, visible.st_ino) != identity
        ):
            raise ServiceError("service socket binding changed")

    def _frozen_phi_snapshot(self) -> PhiScanner:
        """Load one bounded manifest snapshot that still matches startup truth."""

        scanner = self.phi_scanner
        fingerprint = self._phi_fingerprint
        if scanner is None or fingerprint is None:
            raise PhiManifestError("clear manifest is unavailable")
        path = phi_manifest_path(self.state_root)
        before = _phi_fingerprint(path)
        if before != fingerprint:
            raise PhiManifestError("clear manifest changed after service startup")
        current = PhiScanner.from_path(path)
        after = _phi_fingerprint(path)
        if before != after or current.manifest_entries != scanner.manifest_entries:
            raise PhiManifestError("clear manifest changed after service startup")
        return current

    def _assert_frozen_phi(self) -> None:
        self._frozen_phi_snapshot()

    def _dispatch_commit(self, principal: AuthenticatedPrincipal, frame: dict[str, Any]) -> dict[str, Any]:
        """Dispatch the two 3C1 routes after peer/policy authorization."""

        request_id = _request_id(frame.get("body"))
        if request_id is None:
            raise RequestError("commit request ID is invalid")
        try:
            if self._owner_pid != os.getpid():
                raise CommitUnavailable("service cannot dispatch commits after fork")
            route = resolve_route(frame["method"], frame["path"], require_available=True)
            request = parse_commit_request(frame["body"], route)
            assert self.policy is not None
            _assert_frozen(self.policy, self.state_root)
            authorized = self._commit_scope(principal, request)
            if authorized is None:
                return _commit_response(request.request_id, 404, ok=False, outcome="invalid")
            if self.commit_runtime is None:
                return _commit_response(request.request_id, 503, ok=False, outcome="unavailable", error_code="unavailable")
            access, lineage_scope = authorized
            replay = self.commit_runtime.probe(request, route, principal=principal.subject)
            if replay.response_template is not None:
                response = replay.response_template
                return _commit_response(
                    request.request_id,
                    200,
                    ok=response["ok"], outcome=response["outcome"], record_ids=response["record_ids"], entry_ids=response["entry_ids"], usage=response["usage"],
                )
            if route.operation in ADAPTER_OPERATIONS:
                # These operations declare no SOURCE and are gated by the
                # post-acceptance text scan inside the runtime, so the 3C1
                # clear manifest is not a readiness prerequisite for them.
                response = self.commit_runtime.execute_adapter(
                    request,
                    route,
                    principal=principal.subject,
                    access=access,
                    adapter_host=self.adapter_host,
                    scope=lineage_scope,
                )
                return _commit_response(
                    request.request_id,
                    200,
                    ok=response["ok"], outcome=response["outcome"], record_ids=response["record_ids"], entry_ids=response["entry_ids"], usage=response["usage"],
                )
            scanner = self._frozen_phi_snapshot()
            source = normalize_source(request.source.to_wire())
            decision = scanner.scan(source.data, "application/octet-stream", "identity", request.operation)
            if decision != "clear":
                return _commit_response(request.request_id, 400, ok=False, outcome="invalid", error_code="source_refused")
            # Re-read the frozen leaf after source normalization and scanning,
            # then once more inside the commit lock immediately before durable
            # reservation.  A replacement is unavailable, never acceptance.
            self._assert_frozen_phi()
            response = self.commit_runtime.execute(
                request,
                route,
                principal=principal.subject,
                access=access,
                source=source,
                scanner_clear=True,
                scope=lineage_scope,
                pre_accept=self._assert_frozen_phi,
            )
            return _commit_response(
                request.request_id,
                200,
                ok=response["ok"], outcome=response["outcome"], record_ids=response["record_ids"], entry_ids=response["entry_ids"], usage=response["usage"],
            )
        except CommitCollision:
            return _commit_response(request_id, 400, ok=False, outcome="invalid", error_code="request_conflict")
        except CommitRefusal:
            return _commit_response(request_id, 400, ok=False, outcome="invalid", error_code="invalid_request")
        except (PolicyError, PhiManifestError):
            return _commit_response(request_id, 503, ok=False, outcome="unavailable", error_code="unavailable")
        except (CommitContractError, SourceError, PhiInputError, ValueError):
            return _commit_response(request_id, 400, ok=False, outcome="invalid", error_code="invalid_request")
        except (CommitIntegrityError, CommitUnavailable, CommitRuntimeError, StoreError, JournalError, OSError):
            return _commit_response(request_id, 503, ok=False, outcome="unavailable", error_code="unavailable")

    def _dispatch_entry(self, principal: AuthenticatedPrincipal, request: ReadRequest) -> dict[str, Any]:
        """Return exactly one authorized canonical journal event."""

        try:
            assert self.policy is not None and self.store is not None
            _assert_frozen(self.policy, self.state_root)
            scope = self._scope(principal, request)
            if scope is None:
                return _response(request.request_id, 404, outcome="not_found")
            entry = parse_entry_request(request.payload)
            event = select_entry(verified_events(self.store.journal), scope, entry.entry_id)
            if event is None:
                return _response(request.request_id, 404, outcome="not_found")
            return _response(request.request_id, 200, outcome="completed", result=[_plain_json(event)])
        except ResponseTooLarge:
            return _response(request.request_id, 503, outcome="unavailable", error=("response_too_large", True, "service response is unavailable"))
        except (PolicyError, QuerySnapshotError, StoreError, OSError):
            # Integrity conditions are listed before the request-shape clause
            # because a verified-snapshot failure is also a ``ValueError``.
            return _response(request.request_id, 503, outcome="unavailable", error=("service_unavailable", True, "service is unavailable"))
        except (ReadContractError, ValueError):
            return _response(request.request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))

    def _dispatch_record(self, principal: AuthenticatedPrincipal, request: ReadRequest) -> dict[str, Any]:
        """Return exactly one authorized stored object with its exact bytes."""

        try:
            assert self.policy is not None and self.store is not None
            _assert_frozen(self.policy, self.state_root)
            scope = self._scope(principal, request)
            if scope is None:
                return _response(request.request_id, 404, outcome="not_found")
            record = parse_record_request(request.payload)
            binding = select_record(verified_events(self.store.journal), scope, record.record_id)
            if binding is None:
                return _response(request.request_id, 404, outcome="not_found")
            result = read_record(self.store.records, binding, include_content=record.include_content)
            return _response(request.request_id, 200, outcome="completed", result=[result], entry_ids=[], record_ids=[binding.record_id])
        except ResponseTooLarge:
            # Never a partial or re-encoded object: the caller learns only that
            # this exact response cannot cross the fixed wire bound.
            return _response(request.request_id, 400, outcome="invalid", error=("content_too_large", False, "record content is too large"))
        except (PolicyError, QuerySnapshotError, StoreError, OSError):
            return _response(request.request_id, 503, outcome="unavailable", error=("service_unavailable", True, "service is unavailable"))
        except (ReadContractError, ValueError):
            return _response(request.request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))

    def _dispatch(self, principal: AuthenticatedPrincipal, frame: dict[str, Any]) -> dict[str, Any]:
        if frame["method"] == "POST":
            return self._dispatch_commit(principal, frame)
        if frame["method"] != "GET":
            raise RequestError("method is invalid")
        request = parse_read_request(frame["body"])
        path = frame["path"]
        if path not in {"/v1/journal", "/v1/journal/entry", "/v1/record", "/v1/health", "/v1/ready"}:
            raise RequestError("path is invalid")
        if path == "/v1/health":
            if request.operation != "service.health" or request.claim.capability != "service.health":
                raise RequestError("health route operation binding is invalid")
            return _generic_response(request.request_id, ready=True)
        if path == "/v1/ready":
            if request.operation != "service.ready" or request.claim.capability != "service.ready":
                raise RequestError("ready route operation binding is invalid")
            try:
                assert self.policy is not None
                _assert_frozen(self.policy, self.state_root)
            except PolicyError:
                return _generic_response(request.request_id, ready=False)
            return _generic_response(request.request_id, ready=True)
        if path == "/v1/journal/entry":
            if request.operation != "journal.get" or request.claim.capability != "journal.get":
                raise RequestError("journal entry route operation binding is invalid")
            return self._dispatch_entry(principal, request)
        if path == "/v1/record":
            if request.operation != "record.get" or request.claim.capability != "record.get":
                raise RequestError("record route operation binding is invalid")
            return self._dispatch_record(principal, request)
        if request.operation != "journal.query" or request.claim.capability != "journal.query":
            raise RequestError("journal route operation binding is invalid")
        try:
            assert self.policy is not None and self.store is not None and self.identity is not None
            _assert_frozen(self.policy, self.state_root)
            scope = self._scope(principal, request)
            if scope is None:
                return _response(request.request_id, 404, outcome="not_found")
            query_request = parse_query_request(request.payload)
            if query_request.filter.access is not None and not set(query_request.filter.access) <= scope.readable_tiers:
                return _response(request.request_id, 404, outcome="not_found")
            adapter = DurableJournalQueryAdapter(self.store.journal, self.identity)
        except QueryFilterNotAvailable:
            return _response(request.request_id, 400, outcome="invalid", error=("filter_not_available", False, "filter is not available"))
        except (QueryContractError, ValueError):
            return _response(request.request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))
        except (PolicyError, ServiceIdentityError, DurableQueryError, OSError):
            return _response(request.request_id, 503, outcome="unavailable", error=("service_unavailable", True, "service is unavailable"))
        prepared: EncodedResponse | None = None

        def fits(page: Any) -> bool:
            nonlocal prepared
            try:
                events = [_plain_json(item.event) for item in page.items]
                prepared = _response(request.request_id, 200, outcome="completed", result=events, cursor=page.next_cursor)
            except ResponseTooLarge:
                return False
            return True

        try:
            if query_request.view is None:
                page = adapter.execute_bounded(query_request, scope, fits)
            else:
                def ledger_fits(ledger_page: Any, high_watermark: str) -> bool:
                    nonlocal prepared
                    try:
                        rows = list(project_intake_ledger_page(ledger_page))
                        prepared = _response(
                            request.request_id,
                            200,
                            outcome="completed",
                            result=rows,
                            cursor=ledger_page.next_cursor,
                            projection={
                                "schema_version": "houndd.intake-ledger.v1",
                                "integrity": "verified",
                                "high_watermark": high_watermark,
                            },
                        )
                    except (ResponseTooLarge, IntakeProjectionError):
                        return False
                    return True

                ledger = adapter.execute_ledger_bounded(query_request, scope, ledger_fits)
                page = None if ledger is None else ledger[0]
        except QueryFilterNotAvailable:
            return _response(request.request_id, 400, outcome="invalid", error=("filter_not_available", False, "filter is not available"))
        except (QueryContractError, ValueError):
            return _response(request.request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))
        except (PolicyError, ServiceIdentityError, DurableQueryError, OSError):
            return _response(request.request_id, 503, outcome="unavailable", error=("service_unavailable", True, "service is unavailable"))
        if page is not None and prepared is not None:
            return prepared
        return _response(request.request_id, 503, outcome="unavailable", error=("response_too_large", True, "service response is unavailable"))

    @staticmethod
    def _principal(connection: socket.socket) -> AuthenticatedPrincipal:
        if not hasattr(socket, "SO_PEERCRED"):
            raise ServiceError("SO_PEERCRED is unavailable")
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII"))
            _pid, uid, _gid = struct.unpack("iII", raw)
        except OSError as error:
            raise ServiceError("cannot certify Unix peer credentials") from error
        return AuthenticatedPrincipal(f"linux-uid:{uid}")

    def serve_forever(self) -> None:
        if self._owner_pid != os.getpid():
            raise ServiceError("service cannot serve after fork")
        if self._listener is None:
            raise ServiceError("service is closed")
        while not self._closed:
            self._assert_socket_binding()
            listener = self._listener
            if listener is None:
                break
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._closed:
                    break
                raise
            with connection:
                connection.settimeout(CONNECTION_TIMEOUT_SECONDS)
                try:
                    principal = self._principal(connection)
                    frame = read_frame(connection)
                    response = self._dispatch(principal, frame)
                except FrameError as error:
                    if error.request_id is None:
                        continue
                    response = (
                        _commit_response(error.request_id, 400, ok=False, outcome="invalid", error_code="invalid_request")
                        if error.commit
                        else _response(error.request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))
                    )
                except (RequestError, ValueError) as error:
                    request_id = _request_id(locals().get("frame", {}).get("body") if isinstance(locals().get("frame"), dict) else None)
                    if request_id is None:
                        continue
                    response = (
                        _commit_response(request_id, 400, ok=False, outcome="invalid", error_code="invalid_request")
                        if isinstance(locals().get("frame"), dict) and locals()["frame"].get("method") == "POST"
                        else _response(request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))
                    )
                except (ServiceError, OSError):
                    # A broken or idle peer is not a daemon failure.  The
                    # connection is already scoped by the context manager;
                    # discard it and continue accepting later callers.
                    continue
                try:
                    wire = response.wire if isinstance(response, EncodedResponse) else _encode_response(response)
                    connection.sendall(wire)
                except ResponseTooLarge:
                    request_id = _request_id(locals().get("frame", {}).get("body") if isinstance(locals().get("frame"), dict) else None)
                    if request_id is None:
                        continue
                    fallback = (
                        _commit_response(request_id, 503, ok=False, outcome="unavailable", error_code="unavailable")
                        if isinstance(locals().get("frame"), dict) and locals()["frame"].get("method") == "POST"
                        else _response(request_id, 503, outcome="unavailable", error=("response_too_large", True, "service response is unavailable"))
                    )
                    connection.sendall(fallback.wire)
                except OSError:
                    pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        runtime_root, self._runtime_root = self._runtime_root, None
        if runtime_root is not None and self._owner_pid == os.getpid():
            try:
                with runtime_root.operation():
                    info = os.stat(self.socket_path.name, dir_fd=runtime_root.fd, follow_symlinks=False)
                    if self._socket_identity == (info.st_dev, info.st_ino) and stat.S_ISSOCK(info.st_mode):
                        os.unlink(self.socket_path.name, dir_fd=runtime_root.fd)
            except OSError:
                pass
            finally:
                runtime_root.close()
        elif runtime_root is not None:
            runtime_root.close()
        self._socket_identity = None
        policy, self.policy = self.policy, None
        if policy is not None:
            os.close(policy.policy_fd)
            policy.service_root.close()
        identity, self.identity = self.identity, None
        if identity is not None:
            identity.close()
        commit_runtime, self.commit_runtime = self.commit_runtime, None
        if commit_runtime is not None:
            commit_runtime.close()
        store, self.store = self.store, None
        if store is not None:
            store.close()


__all__ = ["FrameError", "HounddService", "MAX_FRAME_BYTES", "PolicyError", "REQUEST_SCHEMA", "RESPONSE_SCHEMA", "ResponseTooLarge", "ServiceError", "WIRE_VERSION", "load_frozen_policy", "read_frame"]
