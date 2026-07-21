"""Command-line interface for Hound."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from . import __version__
from .contracts import ContractError, load_manifest
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
from .providers import (
    ProviderError,
    execute_request as execute_provider_request,
    load_provider_environment,
    validate_request as validate_provider_request,
)
from .runtime import RuntimeErrorHound, write_json_create_only
from .source import capture_sources, discover_sources, inspect_sources


OPERATIONS = {
    "source": ("discover", "capture", "inspect"),
    "corpus": ("status", "propose", "apply", "project"),
    "edition": ("build", "publish", "replay"),
}


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
        raise HoundError(
            f"cannot read {target}: input is not UTF-8", exit_code=2
        ) from exc
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
    stream.write(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")


def _add_operation_parser(parent: argparse._SubParsersAction[Any], namespace: str, verb: str) -> None:
    parser = parent.add_parser(verb, help=f"Run {namespace}.{verb}")
    parser.set_defaults(handler=_handle_operation, operation=f"{namespace}.{verb}")
    parser.add_argument("--driver", required=True, help="Path to hound.driver.v1 manifest")
    parser.add_argument("--input", help="Path to a JSON input object")
    parser.add_argument("--json", help="Inline JSON input object")
    parser.add_argument("--as-of", help="Explicit data cutoff; required when planning writes")
    parser.add_argument("--plan-out", help="Create the deterministic plan at this path")
    parser.add_argument("--execute", metavar="PLAN", help="Execute an existing plan")
    parser.add_argument("--approval", help="Approval artifact for a human-gated plan")


def build_parser() -> argparse.ArgumentParser:
    parser = _HoundArgumentParser(
        prog="hound",
        description="Bounded research and evidence operations.",
    )
    parser.add_argument("--version", action="version", version=f"hound {__version__}")
    top = parser.add_subparsers(dest="namespace", required=True)

    driver = top.add_parser("driver", help="Inspect driver contracts")
    driver_sub = driver.add_subparsers(dest="driver_command", required=True)
    check = driver_sub.add_parser("check", help="Validate and handshake with a driver")
    check.add_argument("--driver", required=True)
    check.set_defaults(handler=_handle_driver_check)

    for namespace, verbs in OPERATIONS.items():
        group = top.add_parser(namespace, help=f"{namespace.title()} lifecycle operations")
        group_sub = group.add_subparsers(dest=f"{namespace}_command", required=True)
        for verb in verbs:
            _add_operation_parser(group_sub, namespace, verb)

    provider = top.add_parser("provider", help="Run credential-safe provider transport")
    provider_sub = provider.add_subparsers(dest="provider_command", required=True)
    provider_run = provider_sub.add_parser("run", help="Execute a versioned provider request")
    provider_input = provider_run.add_mutually_exclusive_group(required=True)
    provider_input.add_argument("--request", help="Path to hound.provider.request.v1 JSON")
    provider_input.add_argument("--json", help="Inline hound.provider.request.v1 JSON")
    provider_run.add_argument(
        "--env-file",
        help="Private dotenv-style file; only the selected provider credential is loaded",
    )
    provider_run.set_defaults(handler=_handle_provider_run)

    capture = top.add_parser("capture", help="Store and verify immutable source captures")
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

    approval = top.add_parser("approval", help="Create explicit approval artifacts")
    approval_sub = approval.add_subparsers(dest="approval_command", required=True)
    create = approval_sub.add_parser("create", help="Approve exactly one plan and write scope")
    create.add_argument("--plan", required=True)
    create.add_argument("--reviewer", required=True)
    create.add_argument("--approved-at")
    create.add_argument("--expires-at")
    create.add_argument("--output", required=True)
    create.set_defaults(handler=_handle_approval_create)

    run = top.add_parser("run", help="Inspect immutable run records")
    run_sub = run.add_subparsers(dest="run_command", required=True)
    verify = run_sub.add_parser("verify", help="Verify hashes in a run directory")
    verify.add_argument("run_dir")
    verify.set_defaults(handler=_handle_run_verify)
    return parser


def _handle_driver_check(args: argparse.Namespace) -> dict[str, Any]:
    return check_driver(Path(args.driver).resolve())


def _handle_operation(args: argparse.Namespace) -> dict[str, Any]:
    manifest_path = Path(args.driver).resolve()
    manifest = load_manifest(manifest_path)
    capability = manifest["capabilities"].get(args.operation)
    if capability is None:
        raise HoundError(f"driver does not declare {args.operation}", exit_code=2)

    if args.execute:
        if args.input or args.json or args.plan_out or args.as_of:
            raise HoundError("--execute cannot be combined with planning inputs", exit_code=2)
        plan = _read_json(args.execute)
        approval = _read_json(args.approval) if args.approval else None
        if plan.get("operation") != args.operation:
            raise HoundError("plan operation does not match the selected command", exit_code=2)
        return execute_plan(manifest_path, plan, approval=approval)

    if args.approval:
        raise HoundError("--approval is only valid with --execute", exit_code=2)
    payload = _payload(args)
    if capability["effect"] == "read":
        if args.plan_out:
            raise HoundError("read operations do not create execution plans", exit_code=2)
        if capability.get("composition") == "hound.source.v1" and args.operation == "source.discover":
            return discover_sources(manifest_path, payload, as_of=args.as_of)
        if capability.get("composition") == "hound.source.v1" and args.operation == "source.capture":
            return capture_sources(manifest_path, payload, as_of=args.as_of)
        if capability.get("composition") == "hound.source.v1" and args.operation == "source.inspect":
            return inspect_sources(manifest_path, payload, as_of=args.as_of)
        return invoke_read(manifest_path, args.operation, payload, as_of=args.as_of)
    if not args.as_of:
        raise HoundError("--as-of is required for deterministic write plans", exit_code=2)
    plan = make_plan(manifest_path, args.operation, payload, as_of=args.as_of)
    if args.plan_out:
        write_json_create_only(Path(args.plan_out), plan)
    return plan


def _handle_provider_run(args: argparse.Namespace) -> dict[str, Any]:
    request = _read_json(args.request) if args.request else _json_object(args.json, source="--json")
    try:
        validated = validate_provider_request(request)
    except ProviderError as exc:
        raise HoundError(str(exc), exit_code=2) from exc
    if args.env_file:
        environment = load_provider_environment(args.env_file, validated["provider"])
        return execute_provider_request(validated, env=environment)
    return execute_provider_request(validated)


def _handle_capture_store(args: argparse.Namespace) -> dict[str, Any]:
    try:
        body = Path(args.body).read_bytes()
    except OSError as exc:
        raise HoundError(f"cannot read capture body {args.body}: {exc}", exit_code=2) from exc
    metadata = (
        _json_object(args.metadata_json, source="--metadata-json")
        if args.metadata_json
        else None
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


def _handle_approval_create(args: argparse.Namespace) -> dict[str, Any]:
    plan = _read_json(args.plan)
    approval = create_approval(
        plan,
        reviewer=args.reviewer,
        approved_at=args.approved_at,
        expires_at=args.expires_at,
    )
    write_json_create_only(Path(args.output), approval)
    return approval


def _handle_run_verify(args: argparse.Namespace) -> dict[str, Any]:
    result = verify_run(args.run_dir)
    if not result["valid"]:
        raise HoundError("run verification failed")
    return result


def _exit_for_result(result: dict[str, Any]) -> int:
    outcome = result.get("outcome")
    if outcome == "held":
        return 3
    if outcome == "failed" or result.get("ok") is False:
        return 1
    if result.get("valid") is False:
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
    except (ContractError, RuntimeErrorHound, ProviderError, EvidenceError) as exc:
        _emit({"schema_version": "hound.error.v1", "error": str(exc)}, stream=sys.stderr)
        return 2 if isinstance(exc, ContractError) else 1
    except KeyboardInterrupt:
        _emit({"schema_version": "hound.error.v1", "error": "interrupted"}, stream=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
