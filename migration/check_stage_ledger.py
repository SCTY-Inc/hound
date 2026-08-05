#!/usr/bin/env python3
"""Read-only CLI for the HSP-15 stage ledger and deletion-safety gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from migration.stage_ledger import LedgerError, lane_stage, load_ledger, validate_anchor, validate_deletion, validate_ledger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-stage-ledger", exit_on_error=False)
    parser.add_argument("--ledger", type=Path, required=True, help="stage ledger JSON document to validate")
    parser.add_argument(
        "--check-deletion",
        metavar="LANE",
        help="also verify LANE has reached the retired stage before its legacy paths may be deleted",
    )
    parser.add_argument(
        "--anchor-ref",
        default="HEAD",
        metavar="REF",
        help=(
            "git ref to anchor the ledger against (default: HEAD). The hash chain alone cannot tell a legitimate "
            "append from a historical entry that was rewritten with every downstream hash re-derived to match; "
            "this check additionally requires every entry already committed at REF to still appear byte-identical "
            "at the same position -- the ledger may only append. It runs automatically whenever --ledger sits "
            "inside a git checkout and degrades to a non-fatal 'unavailable' status outside one (e.g. an exported "
            "copy) or when the file is untracked at REF. KNOWN CONSEQUENCE: a working tree that has rewritten any "
            "historical entry in place -- even one that re-derives a self-consistent hash chain -- will correctly "
            "fail this check until that rewrite is committed. That is the check doing its job, not a bug."
        ),
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

    anchor_report = None
    if ledger is not None:
        anchor_report = validate_anchor(args.ledger, ledger, ref=args.anchor_ref)
        if anchor_report["status"] == "violation":
            errors.extend(anchor_report["errors"])

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
        "anchor_check": anchor_report,
        "deletion_check": lane_report,
    }
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print("valid" if report["valid"] else "invalid")
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if anchor_report is not None:
            print(f"ANCHOR: status={anchor_report['status']} ref={anchor_report['ref']}")
        if lane_report is not None:
            print(f"LANE: {lane_report['lane']} stage={lane_report['stage']}")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
