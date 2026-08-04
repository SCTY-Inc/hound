#!/usr/bin/env python3
"""Read-only CLI for the HSP-15 stage ledger and deletion-safety gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from migration.stage_ledger import LedgerError, lane_stage, load_ledger, validate_deletion, validate_ledger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-stage-ledger", exit_on_error=False)
    parser.add_argument("--ledger", type=Path, required=True, help="stage ledger JSON document to validate")
    parser.add_argument(
        "--check-deletion",
        metavar="LANE",
        help="also verify LANE has reached the retired stage before its legacy paths may be deleted",
    )
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    try:
        args = parser.parse_args(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        return 0 if getattr(exc, "code", None) == 0 else 2

    errors: list[str] = []
    ledger: dict[str, object] | None = None
    try:
        ledger = load_ledger(args.ledger)
        errors.extend(validate_ledger(ledger))
    except LedgerError as exc:
        errors.append(str(exc))

    lane_report = None
    if not errors and ledger is not None and args.check_deletion is not None:
        deletion_errors = validate_deletion(ledger, args.check_deletion)
        errors.extend(deletion_errors)
        lane_report = {"lane": args.check_deletion, "stage": lane_stage(ledger, args.check_deletion)}

    report = {
        "schema_version": "hound.migration.stage-ledger-report.v1",
        "valid": not errors,
        "errors": errors,
        "ledger": str(args.ledger),
        "deletion_check": lane_report,
    }
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print("valid" if report["valid"] else "invalid")
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if lane_report is not None:
            print(f"LANE: {lane_report['lane']} stage={lane_report['stage']}")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
