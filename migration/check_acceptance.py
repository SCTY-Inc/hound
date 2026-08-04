#!/usr/bin/env python3
"""The HSP-21 acceptance gate: validate the manifest, then prove it.

``migration/acceptance.v1.json`` claims every VISION.md HSP row exactly once.
This checker refuses to let that document drift away from the repository:

* the manifest has a closed shape -- no unknown keys, exactly 22 ordered rows;
* every named artifact resolves on disk;
* traceability is one-to-one -- every proof artifact in the declared scope is
  owned by exactly one row, no row owns another row's artifact, and a
  ``supporting`` citation must name an artifact some *other* row owns;
* no row claims more than its artifacts prove -- ``complete`` requires proving
  tests and an empty ``missing`` list, ``partial``/``open`` require a nonempty
  one;
* each row's ``vision_line`` really points at that row in VISION.md.

With ``--run-tests`` it also executes the manifest's test command and every
CI-safe command the rows name, so one entry point covers the manifest, the
suites, and the sibling migration checkers.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "migration" / "acceptance.v1.json"
VISION_PATH = ROOT / "VISION.md"

SCHEMA_VERSION = "hound.migration.acceptance.v1"
ROW_IDS = tuple(f"HSP-{n:02d}" for n in range(1, 23))
STATUSES = ("complete", "partial", "open")

TOP_FIELDS = {"schema_version", "goal", "acceptance_command", "test_command", "traceability_scope", "summary", "rows"}
SCOPE_FIELDS = {"note", "globs", "excluded", "src_exclusion_reason"}
SUMMARY_FIELDS = {"total", "complete", "partial", "open"}
ROW_FIELDS = {"id", "vision_line", "status", "claim", "tests", "evidence", "commands", "supporting", "assertions", "missing", "deviations"}
COMMAND_FIELDS = {"command", "ci"}
COMMAND_OPTIONAL = {"ci_reason"}


class ManifestError(Exception):
    """The manifest could not be loaded or parsed at all."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ManifestError(f"duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def load_manifest(path: Path) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ManifestError(f"{path} must be a JSON object")
    return document


def _closure(errors: list[str], where: str, value: dict[str, object], required: set[str], optional: set[str] = frozenset()) -> None:
    unknown = sorted(set(value) - required - set(optional))
    missing = sorted(required - set(value))
    for key in unknown:
        errors.append(f"{where}: unknown field {key!r}")
    for key in missing:
        errors.append(f"{where}: missing field {key!r}")


def _strings(errors: list[str], where: str, value: object) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        errors.append(f"{where}: must be a list of strings")
        return []
    if len(set(value)) != len(value):
        errors.append(f"{where}: contains a duplicate entry")
    return list(value)


def validate_shape(manifest: dict[str, object], errors: list[str]) -> list[dict[str, object]]:
    _closure(errors, "manifest", manifest, TOP_FIELDS)
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"manifest: schema_version must be {SCHEMA_VERSION!r}")
    for field in ("goal", "acceptance_command", "test_command"):
        if not isinstance(manifest.get(field), str) or not manifest.get(field):
            errors.append(f"manifest: {field} must be a nonempty string")

    scope = manifest.get("traceability_scope")
    if isinstance(scope, dict):
        _closure(errors, "traceability_scope", scope, SCOPE_FIELDS)
        _strings(errors, "traceability_scope.globs", scope.get("globs"))
        _strings(errors, "traceability_scope.excluded", scope.get("excluded"))
    else:
        errors.append("manifest: traceability_scope must be an object")

    rows = manifest.get("rows")
    if not isinstance(rows, list):
        errors.append("manifest: rows must be a list")
        return []
    if tuple(row.get("id") for row in rows if isinstance(row, dict)) != ROW_IDS or len(rows) != len(ROW_IDS):
        errors.append(f"manifest: rows must be exactly {len(ROW_IDS)} entries ordered HSP-01..HSP-22")

    validated: list[dict[str, object]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"rows[{index}]: must be an object")
            continue
        where = f"row {row.get('id', index)}"
        _closure(errors, where, row, ROW_FIELDS)
        if row.get("status") not in STATUSES:
            errors.append(f"{where}: status must be one of {STATUSES}")
        if not isinstance(row.get("claim"), str) or not row.get("claim"):
            errors.append(f"{where}: claim must be a nonempty string")
        if not isinstance(row.get("vision_line"), int):
            errors.append(f"{where}: vision_line must be an integer")
        for field in ("tests", "evidence", "supporting", "assertions", "missing", "deviations"):
            _strings(errors, f"{where}.{field}", row.get(field))
        commands = row.get("commands")
        if not isinstance(commands, list):
            errors.append(f"{where}.commands: must be a list")
        else:
            for position, command in enumerate(commands):
                if not isinstance(command, dict):
                    errors.append(f"{where}.commands[{position}]: must be an object")
                    continue
                _closure(errors, f"{where}.commands[{position}]", command, COMMAND_FIELDS, COMMAND_OPTIONAL)
                if not isinstance(command.get("command"), str) or not command.get("command"):
                    errors.append(f"{where}.commands[{position}]: command must be a nonempty string")
                if not isinstance(command.get("ci"), bool):
                    errors.append(f"{where}.commands[{position}]: ci must be a boolean")
                elif command["ci"] is False and not command.get("ci_reason"):
                    errors.append(f"{where}.commands[{position}]: a non-CI command must carry ci_reason")
                elif command["ci"] is True and "ci_reason" in command:
                    errors.append(f"{where}.commands[{position}]: a CI command must not carry ci_reason")
        validated.append(row)

    summary = manifest.get("summary")
    if isinstance(summary, dict):
        _closure(errors, "summary", summary, SUMMARY_FIELDS)
        counted = {"total": len(validated)} | {status: sum(1 for row in validated if row.get("status") == status) for status in STATUSES}
        for field, value in counted.items():
            if summary.get(field) != value:
                errors.append(f"summary.{field} says {summary.get(field)!r}, the rows count {value}")
    else:
        errors.append("manifest: summary must be an object")
    return validated


def validate_claims(rows: list[dict[str, object]], errors: list[str]) -> None:
    """No row may claim more than its artifacts prove."""
    for row in rows:
        where = f"row {row.get('id')}"
        status, missing = row.get("status"), row.get("missing")
        tests, evidence = row.get("tests"), row.get("evidence")
        if not isinstance(missing, list) or not isinstance(tests, list) or not isinstance(evidence, list):
            continue
        if status == "complete":
            if missing:
                errors.append(f"{where}: status 'complete' but names {len(missing)} missing item(s); use 'partial'")
            if not tests:
                errors.append(f"{where}: status 'complete' with no proving test file")
            if not row.get("assertions"):
                errors.append(f"{where}: status 'complete' with no asserted behavior")
        elif status in {"partial", "open"} and not missing:
            errors.append(f"{where}: status {status!r} must say what is missing")
        if status == "open" and (tests or evidence) and not missing:
            errors.append(f"{where}: status 'open' while naming proving artifacts")


def validate_vision_lines(rows: list[dict[str, object]], errors: list[str]) -> None:
    try:
        lines = VISION_PATH.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        errors.append(f"cannot read {VISION_PATH}: {exc}")
        return
    for row in rows:
        identifier, line_number = row.get("id"), row.get("vision_line")
        if not isinstance(line_number, int):
            continue
        if not 1 <= line_number <= len(lines):
            errors.append(f"row {identifier}: vision_line {line_number} is outside VISION.md")
        elif not lines[line_number - 1].startswith(f"| {identifier} |"):
            errors.append(f"row {identifier}: VISION.md:{line_number} does not begin the {identifier} acceptance row")


def _in_scope(scope: dict[str, object], root: Path) -> set[str]:
    """Every file the declared globs cover, minus the declared exclusions."""
    included: set[str] = set()
    for pattern in scope.get("globs", []):
        for path in root.glob(pattern):
            if path.is_file():
                included.add(path.relative_to(root).as_posix())
    excluded: set[str] = set()
    for pattern in scope.get("excluded", []):
        for path in root.glob(pattern):
            if path.is_file():
                excluded.add(path.relative_to(root).as_posix())
    return included - excluded


def validate_traceability(rows: list[dict[str, object]], scope: dict[str, object], root: Path, errors: list[str]) -> dict[str, str]:
    """One artifact, one owning row; every in-scope file owned; nothing invented."""
    owner: dict[str, str] = {}
    for row in rows:
        identifier = str(row.get("id"))
        for field in ("tests", "evidence"):
            for entry in row.get(field, []) if isinstance(row.get(field), list) else []:
                if entry in owner:
                    errors.append(f"artifact {entry} is owned by both {owner[entry]} and {identifier}; ownership must be one-to-one")
                    continue
                owner[entry] = identifier

    for entry, identifier in sorted(owner.items()):
        target = root / entry
        if entry.endswith("/"):
            if not target.is_dir():
                errors.append(f"row {identifier}: evidence directory {entry} does not exist")
            elif not any(target.rglob("*")):
                errors.append(f"row {identifier}: evidence directory {entry} is empty")
        elif not target.is_file():
            errors.append(f"row {identifier}: artifact {entry} does not exist")

    for row in rows:
        identifier = str(row.get("id"))
        for entry in row.get("supporting", []) if isinstance(row.get("supporting"), list) else []:
            if entry not in owner:
                errors.append(f"row {identifier}: supporting artifact {entry} is owned by no row")
            elif owner[entry] == identifier:
                errors.append(f"row {identifier}: supporting artifact {entry} is its own; cite it under tests or evidence")

    directories = tuple(entry for entry in owner if entry.endswith("/"))
    for path in sorted(_in_scope(scope, root)):
        owners = [owner[entry] for entry in (path, *(d for d in directories if path.startswith(d)))if entry in owner]
        if not owners:
            errors.append(f"orphan artifact {path}: in the declared traceability scope but claimed by no row")
        elif len(owners) > 1:
            errors.append(f"artifact {path} traces to {len(owners)} rows ({', '.join(sorted(owners))}); traceability must be one-to-one")
    return owner


def validate_row_commands(rows: list[dict[str, object]], owner: dict[str, str], errors: list[str]) -> None:
    """A row's pytest command may only run test files that row owns."""
    for row in rows:
        identifier = str(row.get("id"))
        tests = row.get("tests")
        owned = set(tests) if isinstance(tests, list) else set()
        for command in row.get("commands", []) if isinstance(row.get("commands"), list) else []:
            if not isinstance(command, dict) or not isinstance(command.get("command"), str):
                continue
            if "pytest" not in command["command"]:
                continue
            for token in shlex.split(command["command"]):
                if token.startswith("tests/") and token not in owned:
                    errors.append(f"row {identifier}: its command runs {token}, which the row does not own")


def _parse(command: str) -> tuple[list[str], dict[str, str]]:
    """Split a documented command into argv plus its leading VAR=value prefix.

    ``python`` resolves to the running interpreter so the gate uses the same
    environment under ``uv run``, a bare ``.venv``, and CI alike.
    """
    tokens = shlex.split(command)
    overrides: dict[str, str] = {}
    while tokens:
        name, separator, value = tokens[0].partition("=")
        if not separator or not name.replace("_", "").isalnum() or not name.isupper():
            break
        overrides[name] = value
        tokens.pop(0)
    return [sys.executable if token == "python" else token for token in tokens], os.environ | overrides


def run_commands(manifest: dict[str, object], rows: list[dict[str, object]], root: Path, errors: list[str]) -> list[dict[str, object]]:
    """Run the manifest test command once, then every CI-safe row command."""
    runs: list[dict[str, object]] = []
    planned: list[tuple[str, str]] = [("manifest", str(manifest["test_command"]))]
    for row in rows:
        for command in row.get("commands", []) if isinstance(row.get("commands"), list) else []:
            if not isinstance(command, dict) or command.get("ci") is not True:
                continue
            text = str(command.get("command"))
            if "check_acceptance.py" in text or "pytest" in text:
                continue  # self-reference, or already covered by the one full-suite run
            planned.append((str(row.get("id")), text))

    seen: set[str] = set()
    for source, command in planned:
        if command in seen:
            continue
        seen.add(command)
        argv, env = _parse(command)
        print(f"--- {source}: {command}", flush=True)
        completed = subprocess.run(argv, cwd=root, env=env)
        runs.append({"source": source, "command": command, "returncode": completed.returncode})
        if completed.returncode != 0:
            errors.append(f"{source}: command failed (exit {completed.returncode}): {command}")
    return runs


def check(manifest_path: Path = MANIFEST_PATH, root: Path = ROOT, run_tests: bool = False) -> dict[str, object]:
    errors: list[str] = []
    runs: list[dict[str, object]] = []
    rows: list[dict[str, object]] = []
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        errors.append(str(exc))
        manifest = {}
    if manifest:
        rows = validate_shape(manifest, errors)
        validate_claims(rows, errors)
        validate_vision_lines(rows, errors)
        scope = manifest.get("traceability_scope")
        owner = validate_traceability(rows, scope, root, errors) if isinstance(scope, dict) else {}
        validate_row_commands(rows, owner, errors)
        if run_tests and not errors:
            runs = run_commands(manifest, rows, root, errors)
        elif run_tests:
            errors.append("refusing to run the suites: the manifest itself does not validate")
    return {
        "schema_version": "hound.migration.acceptance-report.v1",
        "valid": not errors,
        "errors": errors,
        "manifest": str(manifest_path),
        "ran_tests": run_tests,
        "runs": runs,
        "rows": [{"id": row.get("id"), "status": row.get("status"), "missing": len(row.get("missing") or [])} for row in rows],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-acceptance", exit_on_error=False)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH, help="acceptance manifest to validate")
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root the manifest's paths resolve against")
    parser.add_argument("--run-tests", action="store_true", help="also run the manifest test command and every CI-safe row command")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    try:
        args = parser.parse_args(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        return 0 if getattr(exc, "code", None) == 0 else 2

    report = check(manifest_path=args.manifest, root=args.root, run_tests=args.run_tests)
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        for row in report["rows"]:
            print(f"{row['id']} {row['status']}" + (f" ({row['missing']} missing)" if row["missing"] else ""))
        for run in report["runs"]:
            print(f"RAN {run['command']} -> exit {run['returncode']}")
        print("valid" if report["valid"] else "invalid")
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
