#!/usr/bin/env python3
"""Read-only CLI for the canonical consumer inventory and baseline gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from migration.consumer_inventory import InventoryError, load_catalog, load_inventory, scan_workspace, validate_catalog, validate_inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-consumer-inventory", exit_on_error=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--workspace", type=Path, help="workspace to audit")
    mode.add_argument("--schema-only", action="store_true", help="validate only the checked-in schemas")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("consumer-inventory.v1.json"))
    parser.add_argument("--catalog", type=Path, default=Path(__file__).with_name("provider-indicators.v1.json"))
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    try:
        args = parser.parse_args(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        return 0 if getattr(exc, "code", None) == 0 else 2
    errors: list[str] = []
    result = None
    try:
        manifest = load_inventory(args.manifest)
        catalog = load_catalog(args.catalog)
        errors.extend(validate_inventory(manifest, require_paths=args.workspace is not None, workspace=args.workspace))
        errors.extend(validate_catalog(catalog))
        if not errors and args.workspace is not None:
            result = scan_workspace(manifest, catalog, args.workspace)
            errors.extend(result.failures)
    except InventoryError as exc:
        errors.append(str(exc))
    report = {
        "schema_version": "hound.migration.inventory-report.v1",
        "valid": not errors,
        "errors": errors,
        "findings": [] if result is None else result.findings,
        "baseline_findings": [] if result is None else result.baseline_findings,
        "coverage": [] if result is None else result.coverage,
        "workspace": None if args.workspace is None else str(args.workspace),
    }
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print("valid" if report["valid"] else "invalid")
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for finding in report["baseline_findings"]:
            print(f"BASELINE: {finding['path']}:{finding['line']} {finding['indicator_id']}")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
