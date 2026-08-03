"""Research extension commands built on Hound's driver primitive."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from hound_cli.cli import _HoundArgumentParser, _emit, _exit_for_result, _input_arguments, _payload
from hound_cli.contracts import ContractError
from hound_cli.orchestrator import HoundError
from hound_cli.runtime import RuntimeErrorHound
from houndd.commit import CommitContractError, parse_commit_request, resolve_route
from houndd.query_contracts import parse_query_request
from houndd.service import WIRE_VERSION
from .commit_client import CommitClientError, exchange as commit_exchange, exit_code as commit_exit_code
from .journal_client import JournalClientError, exchange


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
    query.add_argument("--request-id", default="hound-research-query")
    query.set_defaults(handler=_handle_journal_query)

    ingest = top.add_parser("ingest", help="Submit one source declaration to local houndd")
    ingest_sub = ingest.add_subparsers(dest="ingest_command", required=True)
    file_commit = ingest_sub.add_parser("file", help="Commit one certified local file through houndd")
    _commit_arguments(file_commit)
    file_commit.set_defaults(handler=_handle_ingest_file)

    import_record = top.add_parser("import-record", help="Mirror one legacy record through local houndd")
    _commit_arguments(import_record)
    import_record.add_argument("--record-id", required=True)
    import_record.set_defaults(handler=_handle_import_record)
    return parser


def _commit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--socket", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--requested-access", choices=("public", "workspace", "restricted"), default="restricted")
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--request-id", required=True)
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


def _handle_commit(args: argparse.Namespace, operation: str) -> dict[str, Any]:
    socket_path, request = _commit_request(args, operation)
    try:
        response = commit_exchange(socket_path, request)
    except CommitClientError as error:
        raise HoundError(str(error), exit_code=5) from error
    args._commit_exit_code = commit_exit_code(response)
    return response["body"]


def _handle_ingest_file(args: argparse.Namespace) -> dict[str, Any]:
    return _handle_commit(args, "ingest.file")


def _handle_import_record(args: argparse.Namespace) -> dict[str, Any]:
    return _handle_commit(args, "import.record")


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
