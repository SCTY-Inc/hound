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
