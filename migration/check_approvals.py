#!/usr/bin/env python3
"""Read-only CLI for the HSP-10/HSP-22 approval seam (E4)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from migration.approvals import check


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-approvals", exit_on_error=False)
    parser.add_argument("--receipts", type=Path, required=True, help="directory of hound.approval.gate-receipt.v1 JSON files")
    parser.add_argument("--decisions", type=Path, required=True, help="decisions.jsonl hash-chained audit log")
    parser.add_argument("--workspace", type=Path, required=True, help="workspace root to resolve receipt subject artifacts against")
    parser.add_argument("--annotations", type=Path, help="directory of hound.approval.annotation.v1 JSON files")
    parser.add_argument("--stage-ledger", type=Path, help="stage ledger JSON to walk the HSP-22 approval_ref binding")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    try:
        args = parser.parse_args(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        return 0 if getattr(exc, "code", None) == 0 else 2

    report = check(
        receipts_dir=args.receipts,
        decisions_path=args.decisions,
        workspace=args.workspace,
        annotations_dir=args.annotations,
        stage_ledger_path=args.stage_ledger,
    )
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print("valid" if report["valid"] else "invalid")
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        for state in report["legal_states"]:
            print(f"STATE: {state}")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
