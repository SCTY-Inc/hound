"""Research extension commands built on Hound's driver primitive."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import sys
from typing import Any, Sequence

from hound_cli.cli import _HoundArgumentParser, _emit, _exit_for_result, _input_arguments, _payload
from hound_cli.contracts import ContractError
from hound_cli.orchestrator import HoundError
from hound_cli.runtime import RuntimeErrorHound
from houndd.commit import CommitContractError, MAX_WIRE_BODY_BYTES, parse_commit_request, resolve_route
from houndd.contracts import canonical_bytes
from houndd.query_contracts import parse_query_request
from houndd.service import WIRE_VERSION
from .commit_client import CommitClientError, exchange as commit_exchange, exit_code as commit_exit_code
from .evidence import EvidenceError, validate_public_url
from .journal_client import JournalClientError, exchange, record_exchange


def verify_web_run(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .web import verify_web_run as implementation
    return implementation(*args, **kwargs)


def discover_sources(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .source import discover_sources as implementation
    return implementation(*args, **kwargs)


def capture_sources(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .source import capture_sources as implementation
    return implementation(*args, **kwargs)


def inspect_sources(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .source import inspect_sources as implementation
    return implementation(*args, **kwargs)


def run_web(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .web import run_web as implementation
    return implementation(*args, **kwargs)


def store_capture(*args: Any, **kwargs: Any) -> dict[str, Any]:
    from .evidence import store_capture as implementation
    return implementation(*args, **kwargs)


def verify_capture(*args: Any, **kwargs: Any) -> bool:
    from .evidence import verify_capture as implementation
    return implementation(*args, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = _HoundArgumentParser(
        prog="hound-research",
        description="Optional source, web, and capture records for Hound drivers.",
    )
    top = parser.add_subparsers(dest="command", required=True)

    verify = top.add_parser("verify", help="Verify an immutable research record")
    verify.add_argument("record")
    verify.set_defaults(handler=_handle_verify)

    source = top.add_parser("source", help="Compose source records from web adapters")
    source_sub = source.add_subparsers(dest="source_command", required=True)
    for verb in ("discover", "capture", "inspect"):
        operation = source_sub.add_parser(verb, help=f"Run source.{verb}")
        operation.add_argument("--driver", required=True)
        _input_arguments(operation)
        operation.add_argument("--as-of", help="Optional owner data cutoff")
        operation.set_defaults(handler=_handle_source, source_verb=verb)

    for verb in ("search", "extract", "interact"):
        web = top.add_parser(verb, help=f"Run one bounded web {verb} adapter")
        web.add_argument("--adapter", required=True)
        _input_arguments(web)
        web.add_argument("--as-of", help="Optional owner data cutoff")
        web.add_argument("--record-root", default=".hound/web")
        web.set_defaults(handler=_handle_web, web_verb=verb)

    capture = top.add_parser("capture", help="Store or verify immutable origin bytes")
    capture_sub = capture.add_subparsers(dest="capture_command", required=True)
    store = capture_sub.add_parser("store", help="Store raw bytes by content hash")
    store.add_argument("--root", required=True)
    store.add_argument("--provider", required=True)
    store.add_argument("--source-url", required=True)
    store.add_argument("--body", required=True)
    store.add_argument("--media-type", required=True)
    store.add_argument("--retrieved-at", required=True)
    store.add_argument("--metadata-json")
    store.set_defaults(handler=_handle_capture_store)
    check = capture_sub.add_parser("verify", help="Verify a capture manifest and blob")
    check.add_argument("--root", required=True)
    check.add_argument("--capture-id", required=True)
    check.set_defaults(handler=_handle_capture_verify)

    journal = top.add_parser("journal", help="Read the local houndd journal")
    journal_sub = journal.add_subparsers(dest="journal_command", required=True)
    query = journal_sub.add_parser("query", help="Query canonical journal events through houndd")
    query.add_argument("--socket", required=True)
    query.add_argument("--owner-id", required=True)
    query.add_argument("--run-id", required=True)
    query.add_argument("--policy-id", required=True)
    query.add_argument("--requested-access", choices=("public", "workspace", "restricted"), default="restricted")
    query.add_argument("--filter-json", default="{}")
    query.add_argument("--limit", type=int, default=50)
    query.add_argument("--cursor")
    query.add_argument("--view", choices=("intake-ledger.v1",))
    query.add_argument("--request-id", default="hound-research-query")
    query.set_defaults(handler=_handle_journal_query)

    get = journal_sub.add_parser("get", help="Fetch one canonical journal event through houndd")
    get.add_argument("--socket", required=True)
    get.add_argument("--owner-id", required=True)
    get.add_argument("--run-id", required=True)
    get.add_argument("--policy-id", required=True)
    get.add_argument("--requested-access", choices=("public", "workspace", "restricted"), default="restricted")
    get.add_argument("--entry-id", required=True)
    get.add_argument("--request-id", default="hound-research-journal-get")
    get.set_defaults(handler=_handle_journal_get)

    record = top.add_parser("record", help="Fetch one committed record through houndd")
    record_sub = record.add_subparsers(dest="record_command", required=True)
    record_get = record_sub.add_parser("get", help="Fetch one record body through houndd")
    record_get.add_argument("--socket", required=True)
    record_get.add_argument("--owner-id", required=True)
    record_get.add_argument("--run-id", required=True)
    record_get.add_argument("--policy-id", required=True)
    record_get.add_argument("--requested-access", choices=("public", "workspace", "restricted"), default="restricted")
    record_get.add_argument("--record-id", required=True)
    record_get.add_argument("--include-content", action="store_true")
    record_get.add_argument("--decode-to")
    record_get.add_argument("--raw", action="store_true")
    record_get.add_argument("--request-id", default="hound-research-record-get")
    record_get.set_defaults(handler=_handle_record_get)

    ingest = top.add_parser("ingest", help="Submit one source declaration to local houndd")
    ingest_sub = ingest.add_subparsers(dest="ingest_command", required=True)
    file_commit = ingest_sub.add_parser("file", help="Commit one certified local file through houndd")
    _commit_arguments(file_commit)
    file_commit.set_defaults(handler=_handle_ingest_file)

    search_ingest = ingest_sub.add_parser("search", help="Submit one search lead through houndd")
    _envelope_arguments(search_ingest)
    search_ingest.add_argument("--query", required=True)
    search_ingest.add_argument("--limit", type=int, default=10)
    search_ingest.set_defaults(handler=_handle_ingest_search)

    url_ingest = ingest_sub.add_parser("url", help="Submit one URL extraction through houndd")
    _envelope_arguments(url_ingest)
    url_ingest.add_argument("--url", required=True)
    url_ingest.add_argument("--max-pages", type=int)
    url_ingest.add_argument("--lineage-search-record")
    url_ingest.add_argument("--lead-id")
    url_ingest.set_defaults(handler=_handle_ingest_url)

    import_record = top.add_parser("import-record", help="Mirror one legacy record through local houndd")
    _commit_arguments(import_record)
    import_record.add_argument("--record-id", required=True)
    import_record.set_defaults(handler=_handle_import_record)
    return parser


def _envelope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--socket", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--requested-access", choices=("public", "workspace", "restricted"), default="restricted")
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--request-id", required=True)


def _commit_arguments(parser: argparse.ArgumentParser) -> None:
    _envelope_arguments(parser)
    parser.add_argument("--path", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--byte-length", type=int, required=True)


def _handle_verify(args: argparse.Namespace) -> dict[str, Any]:
    result = verify_web_run(Path(args.record))
    if not result["valid"]:
        failures = ", ".join(result.get("failures", [])) or "unknown failure"
        raise HoundError(f"record verification failed: {failures}")
    return result


def _handle_source(args: argparse.Namespace) -> dict[str, Any]:
    handlers = {
        "discover": discover_sources,
        "capture": capture_sources,
        "inspect": inspect_sources,
    }
    return handlers[args.source_verb](
        Path(args.driver).resolve(),
        _payload(args),
        as_of=args.as_of,
    )


def _handle_web(args: argparse.Namespace) -> dict[str, Any]:
    return run_web(
        Path(args.adapter).resolve(),
        args.web_verb,
        _payload(args),
        record_root=Path(args.record_root).resolve(),
        as_of=args.as_of,
    )


def _handle_capture_store(args: argparse.Namespace) -> dict[str, Any]:
    try:
        body = Path(args.body).read_bytes()
    except OSError as exc:
        raise HoundError(f"cannot read capture body {args.body}: {exc}", exit_code=2) from exc
    try:
        metadata = json.loads(args.metadata_json) if args.metadata_json else None
    except json.JSONDecodeError as exc:
        raise HoundError(f"invalid JSON in --metadata-json: {exc}", exit_code=2) from exc
    if metadata is not None and not isinstance(metadata, dict):
        raise HoundError("--metadata-json must contain a JSON object", exit_code=2)
    return store_capture(
        args.root,
        provider=args.provider,
        source_url=args.source_url,
        body=body,
        media_type=args.media_type,
        retrieved_at=args.retrieved_at,
        metadata=metadata,
    )


def _handle_capture_verify(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "schema_version": "hound.capture.verification.v1",
        "capture_id": args.capture_id,
        "valid": verify_capture(args.root, args.capture_id),
    }


def _handle_journal_query(args: argparse.Namespace) -> dict[str, Any]:
    try:
        filter_value = json.loads(args.filter_json)
        payload: dict[str, Any] = {"filter": filter_value, "limit": args.limit}
        if args.cursor is not None:
            payload["cursor"] = args.cursor
        if args.view is not None:
            payload["view"] = args.view
        parse_query_request(payload)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise HoundError("journal query payload is invalid", exit_code=2) from error
    socket_path = Path(args.socket)
    if not socket_path.is_absolute():
        raise HoundError("--socket must be an absolute path", exit_code=2)
    request = {
        "wire_version": WIRE_VERSION,
        "method": "GET",
        "path": "/v1/journal",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": args.request_id,
            "producer": {"owner_id": args.owner_id, "capability": "journal.query", "run_id": args.run_id},
            "requested_access": args.requested_access,
            "policy_id": args.policy_id,
            "operation": {"name": "journal.query", "payload": payload},
        },
    }
    try:
        response = exchange(socket_path, request)
    except JournalClientError as error:
        raise HoundError(str(error), exit_code=5) from error
    status = response["status"]
    if status == 200:
        return response["body"]
    raise HoundError(json.dumps(response["body"], sort_keys=True, separators=(",", ":")), exit_code={400: 2, 404: 3, 503: 5}[status])


def _handle_journal_get(args: argparse.Namespace) -> dict[str, Any]:
    socket_path = _envelope_socket(args)
    request = {
        "wire_version": WIRE_VERSION,
        "method": "GET",
        "path": "/v1/journal/entry",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": args.request_id,
            "producer": {"owner_id": args.owner_id, "capability": "journal.get", "run_id": args.run_id},
            "requested_access": args.requested_access,
            "policy_id": args.policy_id,
            "operation": {"name": "journal.get", "payload": {"entry_id": args.entry_id}},
        },
    }
    try:
        response = exchange(socket_path, request)
    except JournalClientError as error:
        raise HoundError(str(error), exit_code=5) from error
    status = response["status"]
    if status != 200:
        raise HoundError(json.dumps(response["body"], sort_keys=True, separators=(",", ":")), exit_code={400: 2, 404: 3, 503: 5}[status])
    result = response["body"].get("result")
    if type(result) is not list or len(result) != 1:
        raise HoundError("houndd response violates the read contract", exit_code=5)
    return result[0]


def _write_record_bytes(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _write_record_decode(destination: str, result: dict[str, Any]) -> None:
    target = Path(destination)
    _write_record_bytes(target, base64.b64decode(result["body_base64"]))
    if "content_base64" in result:
        _write_record_bytes(Path(f"{target}.content"), base64.b64decode(result["content_base64"]))


def _elide_record_base64(result: dict[str, Any]) -> dict[str, Any]:
    elided = dict(result)
    elided["body_base64"] = f"<{result['byte_length']} bytes>"
    if "content_base64" in elided:
        elided["content_base64"] = f"<{result['content_byte_length']} bytes>"
    return elided


def _handle_record_get(args: argparse.Namespace) -> dict[str, Any]:
    socket_path = _envelope_socket(args)
    payload: dict[str, Any] = {"record_id": args.record_id}
    if args.include_content:
        payload["include_content"] = True
    request = {
        "wire_version": WIRE_VERSION,
        "method": "GET",
        "path": "/v1/record",
        "body": {
            "schema_version": "houndd.read-request.v1",
            "request_id": args.request_id,
            "producer": {"owner_id": args.owner_id, "capability": "record.get", "run_id": args.run_id},
            "requested_access": args.requested_access,
            "policy_id": args.policy_id,
            "operation": {"name": "record.get", "payload": payload},
        },
    }
    try:
        response = record_exchange(socket_path, request)
    except JournalClientError as error:
        raise HoundError(str(error), exit_code=5) from error
    status = response["status"]
    if status != 200:
        raise HoundError(json.dumps(response["body"], sort_keys=True, separators=(",", ":")), exit_code={400: 2, 404: 3, 503: 5}[status])
    result = dict(response["body"]["result"][0])
    if args.decode_to:
        _write_record_decode(args.decode_to, result)
    if not args.raw:
        result = _elide_record_base64(result)
    return result


def _commit_request(args: argparse.Namespace, operation: str) -> tuple[Path, dict[str, Any]]:
    socket_path = Path(args.socket)
    if not socket_path.is_absolute():
        raise HoundError("--socket must be an absolute path", exit_code=2)
    source = {
        "kind": "path",
        "path": args.path,
        "sha256": args.sha256,
        "byte_length": args.byte_length,
    }
    payload: dict[str, Any] = {"source": source}
    path = "/v1/ingest/file"
    if operation == "ingest.file":
        payload["media_type"] = "application/octet-stream"
    else:
        path = "/v1/import-record"
        payload["record_id"] = args.record_id
    body = {
        "schema_version": "houndd.commit-request.v1",
        "request_id": args.request_id,
        "idempotency_key": args.idempotency_key,
        "producer": {"owner_id": args.owner_id, "capability": operation, "run_id": args.run_id},
        "requested_access": args.requested_access,
        "policy_id": args.policy_id,
        "operation": {"name": operation, "payload": payload},
    }
    try:
        request = parse_commit_request(body, resolve_route("POST", path, require_available=True))
    except (CommitContractError, TypeError, ValueError) as error:
        raise HoundError("commit request is invalid", exit_code=2) from error
    return socket_path, {"wire_version": WIRE_VERSION, "method": "POST", "path": path, "body": request.to_wire_dict()}


def _submit_commit(args: argparse.Namespace, socket_path: Path, request: dict[str, Any]) -> dict[str, Any]:
    try:
        response = commit_exchange(socket_path, request)
    except CommitClientError as error:
        raise HoundError(str(error), exit_code=5) from error
    args._commit_exit_code = commit_exit_code(response)
    return response["body"]


def _handle_commit(args: argparse.Namespace, operation: str) -> dict[str, Any]:
    socket_path, request = _commit_request(args, operation)
    return _submit_commit(args, socket_path, request)


def _handle_ingest_file(args: argparse.Namespace) -> dict[str, Any]:
    return _handle_commit(args, "ingest.file")


def _handle_import_record(args: argparse.Namespace) -> dict[str, Any]:
    return _handle_commit(args, "import.record")


def _envelope_socket(args: argparse.Namespace) -> Path:
    socket_path = Path(args.socket)
    if not socket_path.is_absolute():
        raise HoundError("--socket must be an absolute path", exit_code=2)
    return socket_path


def _reserved_commit_request(args: argparse.Namespace, path: str, operation: str, payload: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    """Build a commit-request envelope for a Slice 3C route not yet available in houndd.commit.

    ``houndd.commit.parse_commit_request`` only validates ``ingest.file`` and
    ``import.record`` payloads today, so these two operations assemble their
    own strict envelope instead of routing through it.
    """

    resolve_route("POST", path)  # confirms the raw path/operation stay bound to the frozen table
    socket_path = _envelope_socket(args)
    body = {
        "schema_version": "houndd.commit-request.v1",
        "request_id": args.request_id,
        "idempotency_key": args.idempotency_key,
        "producer": {"owner_id": args.owner_id, "capability": operation, "run_id": args.run_id},
        "requested_access": args.requested_access,
        "policy_id": args.policy_id,
        "operation": {"name": operation, "payload": payload},
    }
    if len(canonical_bytes(body)) > MAX_WIRE_BODY_BYTES:
        raise HoundError("commit request body exceeds the encoded JSON limit", exit_code=2)
    return socket_path, {"wire_version": WIRE_VERSION, "method": "POST", "path": path, "body": body}


def _handle_ingest_search(args: argparse.Namespace) -> dict[str, Any]:
    if not args.query:
        raise HoundError("--query must not be empty", exit_code=2)
    limit = max(1, min(50, args.limit))
    payload = {"query": args.query, "limit": limit}
    socket_path, request = _reserved_commit_request(args, "/v1/ingest/search", "ingest.search", payload)
    return _submit_commit(args, socket_path, request)


def _handle_ingest_url(args: argparse.Namespace) -> dict[str, Any]:
    try:
        url = validate_public_url(args.url, "--url")
    except EvidenceError as error:
        raise HoundError(str(error), exit_code=2) from error
    if args.max_pages is not None and not 2 <= args.max_pages <= 20:
        raise HoundError("--max-pages must be between 2 and 20", exit_code=2)
    if bool(args.lineage_search_record) != bool(args.lead_id):
        raise HoundError("--lineage-search-record and --lead-id must be given together", exit_code=2)
    if args.lineage_search_record and args.lead_id:
        lineage = {"kind": "search", "record_id": args.lineage_search_record, "lead_id": args.lead_id}
    else:
        lineage = {"kind": "direct"}
    payload: dict[str, Any] = {"url": url, "lineage": lineage}
    if args.max_pages is not None:
        payload["max_pages"] = args.max_pages
    socket_path, request = _reserved_commit_request(args, "/v1/ingest/url", "ingest.url", payload)
    return _submit_commit(args, socket_path, request)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = args.handler(args)
        _emit(result)
        if hasattr(args, "_commit_exit_code"):
            return args._commit_exit_code
        return _exit_for_result(result)
    except HoundError as exc:
        _emit({"schema_version": "hound.error.v1", "error": str(exc)}, stream=sys.stderr)
        return exc.exit_code
    except (ContractError, RuntimeErrorHound) as exc:
        _emit({"schema_version": "hound.error.v1", "error": str(exc)}, stream=sys.stderr)
        return 2 if isinstance(exc, ContractError) else 1
    except KeyboardInterrupt:
        _emit({"schema_version": "hound.error.v1", "error": "interrupted"}, stream=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
