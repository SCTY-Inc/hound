#!/usr/bin/env python3
"""Read-only CLI over the generated ``houndd.policy.v1`` artifact.

Two modes, both read-only with respect to the live daemon state:

``--verify EXISTING`` regenerates the policy from the inventory + overlay and
byte-compares it against ``EXISTING`` (normally a copy of the live
``policy.json``). Any difference -- a hand edit, a lane added to the
inventory without a matching grant, a review-surface selector list that
fell behind a cutover -- exits nonzero with every added/removed rule named.
This is the drift check that would have caught today's incidents before
they reached the daemon.

``--emit OUTPUT`` writes the freshly generated canonical bytes to ``OUTPUT``.
It refuses to target the live houndd state root (XDG_STATE_HOME-resolved or
the historical ``~/.local/state/hound`` default): this tool only ever
produces a file for a human to review and move into place, it never touches
``${state}/service/policy.json`` itself.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from houndd.contracts import canonical_bytes

from migration.policy_generator import (
    DEFAULT_INVENTORY_PATH,
    DEFAULT_OVERLAY_PATH,
    PolicyGeneratorError,
    generate_policy,
    generate_policy_bytes,
    load_overlay,
)
from migration.consumer_inventory import InventoryError, load_inventory


def _live_state_roots() -> list[Path]:
    """Every path this tool must refuse to write under.

    Mirrors ``houndd.cli``'s XDG_STATE_HOME-or-default resolution
    (``${XDG_STATE_HOME:-~/.local/state}/hound``) without importing it, so
    this stays a read-only CLI with no daemon-runtime dependency.
    """

    xdg = Path(os.environ.get("XDG_STATE_HOME", os.fspath(Path.home() / ".local" / "state"))) / "hound"
    default = Path.home() / ".local" / "state" / "hound"
    roots = {xdg.resolve(strict=False), default.resolve(strict=False)}
    return sorted(roots)


def _under_any(path: Path, roots: list[Path]) -> bool:
    resolved = path.resolve(strict=False)
    return any(resolved == root or root in resolved.parents for root in roots)


def _diff_rules(expected: list[dict], actual: list[dict]) -> tuple[list[dict], list[dict], list[tuple[dict, dict]]]:
    """Split into (missing-from-target, unexpected-in-target, changed-in-place).

    A rule that keeps its (owner_id, capability, run_id) key but gains or
    loses producer selectors -- e.g. a review surface whose derived selector
    list grew after a new lane cut over -- is a same-key content change, not
    an add/remove, and needs its own bucket or it silently passes as a
    byte-mismatch with no actionable detail.
    """

    def key(rule: dict) -> tuple:
        cs = rule["claim_selector"]
        return (cs["owner_id"], cs["capability"], cs["run_id"])

    expected_by_key = {key(rule): rule for rule in expected}
    actual_by_key = {key(rule): rule for rule in actual}
    missing_keys = expected_by_key.keys() - actual_by_key.keys()
    extra_keys = actual_by_key.keys() - expected_by_key.keys()
    shared_keys = expected_by_key.keys() & actual_by_key.keys()
    missing = [expected_by_key[k] for k in sorted(missing_keys, key=str)]
    extra = [actual_by_key[k] for k in sorted(extra_keys, key=str)]
    changed = [
        (expected_by_key[k], actual_by_key[k])
        for k in sorted(shared_keys, key=str)
        if canonical_bytes(expected_by_key[k]) != canonical_bytes(actual_by_key[k])
    ]
    return missing, extra, changed


def _run_verify(args: argparse.Namespace) -> tuple[bool, dict]:
    errors: list[str] = []
    try:
        inventory = load_inventory(args.manifest)
        overlay = load_overlay(args.overlay)
        policy = generate_policy(inventory, overlay)
        expected = generate_policy_bytes(inventory, overlay)
    except (InventoryError, PolicyGeneratorError) as error:
        return False, {"valid": False, "errors": [str(error)], "drift": None}

    try:
        actual = args.verify.read_bytes()
    except OSError as error:
        return False, {"valid": False, "errors": [f"cannot read {args.verify}: {error}"], "drift": None}

    if expected == actual:
        return True, {"valid": True, "errors": [], "drift": None}

    try:
        actual_policy = json.loads(actual.decode("utf-8"))
        actual_rules = actual_policy["rules"] if isinstance(actual_policy, dict) else []
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        actual_rules = []
    missing, extra, changed = _diff_rules(policy["rules"], actual_rules if isinstance(actual_rules, list) else [])
    drift = {
        "missing_from_target": [rule["claim_selector"] for rule in missing],
        "unexpected_in_target": [rule["claim_selector"] for rule in extra],
        "changed_in_target": [
            {
                "claim_selector": expected["claim_selector"],
                "expected_producer_selectors": expected["event_producer_selectors"],
                "actual_producer_selectors": actual_rule["event_producer_selectors"],
            }
            for expected, actual_rule in changed
        ],
        "byte_identical": False,
    }
    errors.append(f"generated policy does not byte-match {args.verify}")
    return False, {"valid": False, "errors": errors, "drift": drift}


def _run_emit(args: argparse.Namespace) -> tuple[bool, dict]:
    roots = _live_state_roots()
    if _under_any(args.emit, roots):
        return False, {"valid": False, "errors": [f"refusing to write under the live houndd state root ({args.emit}); emit to a temp path and move it yourself"], "drift": None}
    try:
        inventory = load_inventory(args.manifest)
        overlay = load_overlay(args.overlay)
        data = generate_policy_bytes(inventory, overlay)
    except (InventoryError, PolicyGeneratorError) as error:
        return False, {"valid": False, "errors": [str(error)], "drift": None}
    try:
        args.emit.write_bytes(data)
    except OSError as error:
        return False, {"valid": False, "errors": [f"cannot write {args.emit}: {error}"], "drift": None}
    return True, {"valid": True, "errors": [], "drift": None, "bytes_written": len(data)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-policy", exit_on_error=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify", type=Path, metavar="POLICY_JSON", help="byte-compare the generated policy against this file")
    mode.add_argument("--emit", type=Path, metavar="OUTPUT_JSON", help="write the generated policy's canonical bytes to this path")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_INVENTORY_PATH, help="consumer inventory (default: migration/consumer-inventory.v1.json)")
    parser.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY_PATH, help="policy overlay (default: migration/policy_overlay.v1.json)")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    try:
        args = parser.parse_args(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        return 0 if getattr(exc, "code", None) == 0 else 2

    if args.verify is not None:
        ok, report = _run_verify(args)
    else:
        ok, report = _run_emit(args)

    report = {"schema_version": "hound.migration.policy-check-report.v1", **report}
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print("valid" if ok else "invalid")
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        drift = report.get("drift")
        if drift:
            for selector in drift["missing_from_target"]:
                print(f"MISSING FROM TARGET: {selector}", file=sys.stderr)
            for selector in drift["unexpected_in_target"]:
                print(f"UNEXPECTED IN TARGET: {selector}", file=sys.stderr)
            for entry in drift["changed_in_target"]:
                print(f"CHANGED IN TARGET: {entry['claim_selector']}", file=sys.stderr)
                print(f"  expected producers: {entry['expected_producer_selectors']}", file=sys.stderr)
                print(f"  actual producers:   {entry['actual_producer_selectors']}", file=sys.stderr)
        if ok and args.emit is not None:
            print(f"EMITTED: {args.emit} ({report.get('bytes_written', 0)} bytes)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
