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

from .access import AuthenticatedPrincipal, PolicyBundle, PolicyRule, ProducerClaim, ProducerSelector, resolve_scope
from .contracts import canonical_bytes
from .query_contracts import QueryContractError, parse_query_request
from .snapshot import DurableJournalQueryAdapter, DurableQueryError, QueryFilterNotAvailable
from .service_identity import ServiceIdentity, ServiceIdentityError
from . import HounddStore
from ._safety import AnchoredRoot


WIRE_VERSION = "houndd.uds.v1"
MAX_FRAME_BYTES = 1_048_576
MAX_WIRE_FRAME_BYTES = MAX_FRAME_BYTES + 2_048
REQUEST_SCHEMA = "houndd.read-request.v1"
RESPONSE_SCHEMA = "houndd.read-response.v1"
_REQUEST_FIELDS = frozenset({"schema_version", "request_id", "producer", "requested_access", "policy_id", "operation"})
_RESPONSE_REQUIRED = frozenset({"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage"})
_RESPONSE_OPTIONAL = frozenset({"result", "cursor", "error"})
_FRAME_FIELDS = frozenset({"wire_version", "method", "path", "body"})
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

    def __init__(self, message: str, *, request_id: str | None = None) -> None:
        super().__init__(message)
        self.request_id = request_id


class RequestError(ServiceError):
    """The authenticated request does not meet the Slice 3B contract."""


class PolicyError(ServiceError):
    """The operator-provisioned policy is absent, unsafe, or ambiguous."""


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


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise FrameError("truncated frame")
        data.extend(part)
    return bytes(data)


def _recover_frame_request_id(raw: bytes) -> str | None:
    """Extract precisely one body request ID without accepting the frame."""

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=lambda pairs: pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeError, ValueError):
        return None
    if type(value) is not list:
        return None
    bodies = [item for key, item in value if type(key) is str and key == "body"]
    if len(bodies) != 1 or type(bodies[0]) is not list:
        return None
    ids = [item for key, item in bodies[0] if type(key) is str and key == "request_id"]
    if len(ids) != 1:
        return None
    try:
        return _text(ids[0], "request_id")
    except RequestError:
        return None


def read_frame(connection: socket.socket) -> dict[str, Any]:
    header = _read_exact(connection, 4)
    size = int.from_bytes(header, "big")
    if not 0 < size <= MAX_WIRE_FRAME_BYTES:
        raise FrameError("frame size is invalid")
    raw = _read_exact(connection, size)
    request_id = _recover_frame_request_id(raw)
    if connection.recv(1):
        raise FrameError("connection contains trailing or second frame bytes", request_id=request_id)
    try:
        value = _canonical_load(raw, "wire frame", FrameError)
    except FrameError as error:
        raise FrameError(str(error), request_id=request_id) from error
    if set(value) != _FRAME_FIELDS or value.get("wire_version") != WIRE_VERSION or value.get("method") != "GET" or type(value.get("path")) is not str or type(value.get("body")) is not dict:
        raise FrameError("wire frame fields are invalid", request_id=request_id)
    if len(canonical_bytes(value["body"])) > MAX_FRAME_BYTES:
        raise FrameError("read envelope body exceeds 1048576 bytes", request_id=request_id)
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


def _response(request_id: str, status: int, *, outcome: str, result: list[dict[str, Any]] | None = None, cursor: str | None = None, error: tuple[str, bool, str] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"schema_version": RESPONSE_SCHEMA, "request_id": request_id, "ok": status == 200, "outcome": outcome, "record_ids": [], "entry_ids": [], "usage": {"requests": 0, "bytes": 0, "cost": 0}}
    if result is not None:
        body["result"] = result
        body["entry_ids"] = [event["entry_id"] for event in result]
        body["record_ids"] = [event["artifact"]["record_id"] for event in result]
    if cursor is not None:
        body["cursor"] = cursor
    if error is not None:
        body["error"] = {"code": error[0], "retryable": error[1], "message": error[2]}
    return {"wire_version": WIRE_VERSION, "status": status, "body": body}


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


def _generic_response(request_id: str, *, ready: bool) -> dict[str, Any]:
    return _response(request_id, 200 if ready else 503, outcome="completed" if ready else "unavailable", error=None if ready else ("service_unavailable", True, "service is not ready"))


class HounddService:
    """Foreground-only local service; it owns no scheduler or request cache."""

    def __init__(self, *, state_root: str | Path, socket_path: str | Path) -> None:
        self._owner_pid = os.getpid()
        self.state_root = Path(state_root)
        self.socket_path = Path(socket_path)
        if not self.state_root.is_absolute() or not self.socket_path.is_absolute():
            raise ServiceError("state and socket paths must be absolute")
        self._listener: socket.socket | None = None
        self._closed = False
        self.store: HounddStore | None = None
        self.identity: ServiceIdentity | None = None
        self.policy: FrozenPolicy | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._runtime_root: AnchoredRoot | None = None
        try:
            self.store = HounddStore(self.state_root)
            self.store.recover()
            if not self.store.verify()["valid"]:
                raise ServiceError("startup recovery verification failed")
            self.policy = load_frozen_policy(self.state_root)
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
        selectors = tuple(selector for selector in scope.permitted_event_selectors if selector.readable_tiers & tiers)
        if not selectors:
            return None
        from .access import EventSelector, PrincipalScope
        return PrincipalScope(principal, frozenset(tiers), tuple(EventSelector(selector.policy_id, selector.producer_selector, selector.readable_tiers & tiers) for selector in selectors))

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

    def _dispatch(self, principal: AuthenticatedPrincipal, frame: dict[str, Any]) -> dict[str, Any]:
        request = parse_read_request(frame["body"])
        path = frame["path"]
        if path not in {"/v1/journal", "/v1/health", "/v1/ready"}:
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
            page = DurableJournalQueryAdapter(self.store.journal, self.identity).execute(query_request, scope)
        except (QueryContractError, QueryFilterNotAvailable, ValueError):
            return _response(request.request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))
        except (PolicyError, ServiceIdentityError, DurableQueryError, OSError):
            return _response(request.request_id, 503, outcome="unavailable", error=("service_unavailable", True, "service is unavailable"))
        events = [_plain_json(item.event) for item in page.items]
        return _response(request.request_id, 200, outcome="completed", result=events, cursor=page.next_cursor)

    @staticmethod
    def _principal(connection: socket.socket) -> AuthenticatedPrincipal:
        if not hasattr(socket, "SO_PEERCRED"):
            raise ServiceError("SO_PEERCRED is unavailable")
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
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
            except OSError:
                if self._closed:
                    break
                raise
            with connection:
                connection.settimeout(5)
                try:
                    principal = self._principal(connection)
                    frame = read_frame(connection)
                    response = self._dispatch(principal, frame)
                except FrameError as error:
                    if error.request_id is None:
                        continue
                    response = _response(error.request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))
                except (RequestError, ValueError) as error:
                    request_id = _request_id(locals().get("frame", {}).get("body") if isinstance(locals().get("frame"), dict) else None)
                    if request_id is None:
                        continue
                    response = _response(request_id, 400, outcome="invalid", error=("invalid_request", False, "request is invalid"))
                except ServiceError:
                    continue
                try:
                    connection.sendall(len(canonical_bytes(response)).to_bytes(4, "big") + canonical_bytes(response))
                except OSError:
                    pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        if self._owner_pid != os.getpid():
            return
        runtime_root, self._runtime_root = self._runtime_root, None
        if runtime_root is not None:
            try:
                with runtime_root.operation():
                    info = os.stat(self.socket_path.name, dir_fd=runtime_root.fd, follow_symlinks=False)
                    if self._socket_identity == (info.st_dev, info.st_ino) and stat.S_ISSOCK(info.st_mode):
                        os.unlink(self.socket_path.name, dir_fd=runtime_root.fd)
            except OSError:
                pass
            finally:
                runtime_root.close()
        self._socket_identity = None
        policy, self.policy = self.policy, None
        if policy is not None:
            os.close(policy.policy_fd)
            policy.service_root.close()
        identity, self.identity = self.identity, None
        if identity is not None:
            identity.close()
        store, self.store = self.store, None
        if store is not None:
            store.close()


__all__ = ["FrameError", "HounddService", "MAX_FRAME_BYTES", "PolicyError", "REQUEST_SCHEMA", "RESPONSE_SCHEMA", "ServiceError", "WIRE_VERSION", "load_frozen_policy", "read_frame"]
