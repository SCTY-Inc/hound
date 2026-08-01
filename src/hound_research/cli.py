"""Research extension commands built on Hound's driver primitive."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import sys
from typing import Any, Sequence

from hound_cli.cli import _HoundArgumentParser, _emit, _exit_for_result, _input_arguments, _payload
from hound_cli.contracts import ContractError
from hound_cli.orchestrator import HoundError
from hound_cli.runtime import RuntimeErrorHound
from houndd.contracts import canonical_bytes
from houndd.query_contracts import parse_query_request
from houndd.service import MAX_FRAME_BYTES, RESPONSE_SCHEMA, WIRE_VERSION

from .evidence import EvidenceError, store_capture, verify_capture
from .source import capture_sources, discover_sources, inspect_sources
from .web import WebError, run_web, verify_web_run


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
    return parser


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


def _read_socket_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise HoundError("houndd response was truncated", exit_code=5)
        data.extend(chunk)
    return bytes(data)


def _strict_response(raw: bytes) -> dict[str, Any]:
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
        raise HoundError("houndd response is invalid", exit_code=5) from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise HoundError("houndd response is not canonical", exit_code=5)
    if set(value) != {"wire_version", "status", "body"} or value["wire_version"] != WIRE_VERSION or value["status"] not in {200, 400, 404, 503}:
        raise HoundError("houndd response has an invalid wire contract", exit_code=5)
    body = value["body"]
    required = {"schema_version", "request_id", "ok", "outcome", "record_ids", "entry_ids", "usage"}
    optional = {"result", "cursor", "error"}
    if type(body) is not dict or set(body) - required - optional or required - set(body) or body["schema_version"] != RESPONSE_SCHEMA:
        raise HoundError("houndd response has an invalid body contract", exit_code=5)
    return value


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
    raw = canonical_bytes(request)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(os.fspath(socket_path))
            connection.sendall(len(raw).to_bytes(4, "big") + raw)
            connection.shutdown(socket.SHUT_WR)
            length = int.from_bytes(_read_socket_exact(connection, 4), "big")
            if not 0 < length <= MAX_FRAME_BYTES:
                raise HoundError("houndd response frame is invalid", exit_code=5)
            response = _strict_response(_read_socket_exact(connection, length))
            if connection.recv(1):
                raise HoundError("houndd returned multiple response frames", exit_code=5)
    except HoundError:
        raise
    except OSError as error:
        raise HoundError("houndd is unavailable", exit_code=5) from error
    status = response["status"]
    if status == 200:
        return response["body"]
    raise HoundError(json.dumps(response["body"], sort_keys=True, separators=(",", ":")), exit_code={400: 2, 404: 3, 503: 5}[status])


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        result = args.handler(args)
        _emit(result)
        return _exit_for_result(result)
    except HoundError as exc:
        _emit({"schema_version": "hound.error.v1", "error": str(exc)}, stream=sys.stderr)
        return exc.exit_code
    except (ContractError, RuntimeErrorHound, EvidenceError, WebError) as exc:
        _emit({"schema_version": "hound.error.v1", "error": str(exc)}, stream=sys.stderr)
        return 2 if isinstance(exc, ContractError) else 1
    except KeyboardInterrupt:
        _emit({"schema_version": "hound.error.v1", "error": "interrupted"}, stream=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
