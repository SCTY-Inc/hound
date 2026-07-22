"""Command-line interface for Hound."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from . import __version__
from .contracts import ContractError
from .evidence import EvidenceError, store_capture, verify_capture
from .orchestrator import (
    HoundError,
    check_driver,
    create_approval,
    execute_plan,
    invoke_read,
    make_plan,
    verify_run,
)
from .runtime import RuntimeErrorHound, write_json_create_only
from .source import capture_sources, discover_sources, inspect_sources
from .web import WebError, run_web, verify_web_run


class _HoundArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise HoundError(message, exit_code=2)


def _json_object(raw: str, *, source: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HoundError(f"invalid JSON in {source}: {exc}", exit_code=2) from exc
    if not isinstance(value, dict):
        raise HoundError(f"{source} must contain a JSON object", exit_code=2)
    return value


def _read_json(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    try:
        return _json_object(target.read_text(encoding="utf-8"), source=str(target))
    except UnicodeDecodeError as exc:
        raise HoundError(f"cannot read {target}: input is not UTF-8", exit_code=2) from exc
    except OSError as exc:
        raise HoundError(f"cannot read {target}: {exc}", exit_code=2) from exc


def _payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.input and args.json:
        raise HoundError("use only one of --input and --json", exit_code=2)
    if args.input:
        return _read_json(args.input)
    if args.json:
        return _json_object(args.json, source="--json")
    return {}


def _emit(value: dict[str, Any], *, stream: Any | None = None) -> None:
    if stream is None:
        stream = sys.stdout
    stream.write(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    )


def _input_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", help="Path to a JSON input object")
    parser.add_argument("--json", help="Inline JSON input object")


def _driver_arguments(parser: argparse.ArgumentParser, *, operation: bool = True) -> None:
    parser.add_argument("--driver", required=True, help="Path to hound.driver.v1 manifest")
    if operation:
        parser.add_argument("--operation", required=True, help="Declared driver capability")


def build_parser() -> argparse.ArgumentParser:
    parser = _HoundArgumentParser(
        prog="hound",
        description="Bounded research and evidence operations.",
    )
    parser.add_argument("--version", action="version", version=f"hound {__version__}")
    top = parser.add_subparsers(dest="command", required=True)

    driver = top.add_parser("driver", help="Inspect driver contracts")
    driver_sub = driver.add_subparsers(dest="driver_command", required=True)
    check = driver_sub.add_parser("check", help="Validate and handshake with a driver")
    check.add_argument("--driver", required=True)
    check.set_defaults(handler=_handle_driver_check)

    invoke = top.add_parser("invoke", help="Invoke one declared read capability")
    _driver_arguments(invoke)
    _input_arguments(invoke)
    invoke.add_argument("--as-of", help="Optional owner data cutoff")
    invoke.set_defaults(handler=_handle_invoke)

    plan = top.add_parser("plan", help="Create one deterministic write plan")
    _driver_arguments(plan)
    _input_arguments(plan)
    plan.add_argument("--as-of", required=True, help="Explicit owner data cutoff")
    plan.add_argument("--output", required=True, help="Create the plan at this path")
    plan.set_defaults(handler=_handle_plan)

    execute = top.add_parser("execute", help="Execute one unchanged plan")
    _driver_arguments(execute, operation=False)
    execute.add_argument("--plan", required=True)
    execute.add_argument("--approval")
    execute.set_defaults(handler=_handle_execute)

    approve = top.add_parser("approve", help="Approve exactly one plan and write scope")
    approve.add_argument("--plan", required=True)
    approve.add_argument("--reviewer", required=True)
    approve.add_argument("--approved-at")
    approve.add_argument("--expires-at")
    approve.add_argument("--output", required=True)
    approve.set_defaults(handler=_handle_approve)

    verify = top.add_parser("verify", help="Verify an immutable web or write record")
    verify.add_argument("record")
    verify.set_defaults(handler=_handle_verify)

    source = top.add_parser("source", help="Compose source records from web adapters")
    source_sub = source.add_subparsers(dest="source_command", required=True)
    for verb in ("discover", "capture", "inspect"):
        operation = source_sub.add_parser(verb, help=f"Run source.{verb}")
        _driver_arguments(operation, operation=False)
        _input_arguments(operation)
        operation.add_argument("--as-of", help="Optional owner data cutoff")
        operation.set_defaults(handler=_handle_source, source_verb=verb)

    for verb in ("search", "extract", "interact"):
        web = top.add_parser(verb, help=f"Run one bounded web {verb} adapter")
        web.add_argument(
            "--adapter", required=True, help="Path to a hound.driver.v1 adapter manifest"
        )
        _input_arguments(web)
        web.add_argument("--as-of", help="Optional owner data cutoff")
        web.add_argument(
            "--record-root",
            default=".hound/web",
            help="Directory for immutable web provenance records",
        )
        web.set_defaults(handler=_handle_web, web_verb=verb)

    capture = top.add_parser("capture", help="Store or verify immutable origin bytes")
    capture_sub = capture.add_subparsers(dest="capture_command", required=True)
    capture_store = capture_sub.add_parser("store", help="Store raw bytes by content hash")
    capture_store.add_argument("--root", required=True)
    capture_store.add_argument("--provider", required=True)
    capture_store.add_argument("--source-url", required=True)
    capture_store.add_argument("--body", required=True, help="Path to raw source bytes")
    capture_store.add_argument("--media-type", required=True)
    capture_store.add_argument("--retrieved-at", required=True)
    capture_store.add_argument("--metadata-json", help="Optional JSON metadata object")
    capture_store.set_defaults(handler=_handle_capture_store)
    capture_verify = capture_sub.add_parser("verify", help="Verify a capture manifest and blob")
    capture_verify.add_argument("--root", required=True)
    capture_verify.add_argument("--capture-id", required=True)
    capture_verify.set_defaults(handler=_handle_capture_verify)
    return parser


def _handle_driver_check(args: argparse.Namespace) -> dict[str, Any]:
    return check_driver(Path(args.driver).resolve())


def _handle_invoke(args: argparse.Namespace) -> dict[str, Any]:
    return invoke_read(
        Path(args.driver).resolve(),
        args.operation,
        _payload(args),
        as_of=args.as_of,
    )


def _handle_plan(args: argparse.Namespace) -> dict[str, Any]:
    plan = make_plan(
        Path(args.driver).resolve(),
        args.operation,
        _payload(args),
        as_of=args.as_of,
    )
    write_json_create_only(Path(args.output), plan)
    return plan


def _handle_execute(args: argparse.Namespace) -> dict[str, Any]:
    plan = _read_json(args.plan)
    approval = _read_json(args.approval) if args.approval else None
    return execute_plan(Path(args.driver).resolve(), plan, approval=approval)


def _handle_approve(args: argparse.Namespace) -> dict[str, Any]:
    approval = create_approval(
        _read_json(args.plan),
        reviewer=args.reviewer,
        approved_at=args.approved_at,
        expires_at=args.expires_at,
    )
    write_json_create_only(Path(args.output), approval)
    return approval


def _handle_verify(args: argparse.Namespace) -> dict[str, Any]:
    record = Path(args.record)
    index = _read_json(record / "index.json")
    result = (
        verify_web_run(record)
        if index.get("schema_version") == "hound.web.run.index.v1"
        else verify_run(record)
    )
    if not result["valid"]:
        raise HoundError("record verification failed")
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
    metadata = (
        _json_object(args.metadata_json, source="--metadata-json") if args.metadata_json else None
    )
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


def _exit_for_result(result: dict[str, Any]) -> int:
    outcome = result.get("outcome")
    if outcome == "held":
        return 3
    if outcome == "failed" or result.get("ok") is False or result.get("valid") is False:
        return 1
    return 0


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
