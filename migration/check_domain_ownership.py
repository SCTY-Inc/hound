#!/usr/bin/env python3
"""HSP-19 domain-ownership static checker and capability dump.

This module intentionally has no Hound service imports and performs no writes
or network access. It is usable from a copied Hound checkout, just like
``migration.consumer_inventory``.

HSP-19 draws one boundary in both directions:

* ``repos/hound`` (the daemon, adapters, CLIs) is the only place allowed to
  hold evidence mechanics -- provider credentials/SDKs/endpoints and
  houndd-internal journal/store writes -- and it must never hold domain logic
  (scheduler, approval DB, queue, CRM, wiki, Helm, Pulse curation, Benefits
  registry, social publishing, or internal BB/Git/Discord/calendar event
  ownership).
* Every other repo ("domain repos") is free to hold domain logic but must
  never hold evidence mechanics; the only sanctioned way to reach Hound is
  through the ``hound-research`` CLI or the ``hound_client`` library, neither
  of which trips these indicators.

The scanner reuses consumer_inventory's bounded, symlink-safe directory walk
(``_scan_candidates``/``_path_problem``) so the same fail-closed discipline
governs both checkers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from migration.consumer_inventory import (
    EXCLUSIONS,
    InventoryError,
    MAX_LINE_BYTES,
    MAX_SCAN_BYTES,
    _matches,
    _path_problem,
    _scan_candidates,
    load_catalog,
)

SCHEMA_VERSION = "hound.migration.domain-ownership.v1"
HOUND_LANE = "repos/hound"

# Directories that are never source-of-truth for ownership evidence, on top
# of consumer_inventory's own scanner exclusions.
_EXTRA_EXCLUSIONS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build"})
_ALL_EXCLUSIONS = EXCLUSIONS | _EXTRA_EXCLUSIONS

# Provider-indicator categories that represent a domain repo directly holding
# evidence mechanics. outbound_transport/evidence_artifact are deliberately
# excluded: they need consumer_inventory's same-file provider-pairing to stay
# meaningful, and pairing here would just duplicate that checker.
_EVIDENCE_CATALOG_CATEGORIES = frozenset({"credential_name", "sdk_import", "client", "endpoint", "prompt_skill_acquisition"})

# houndd's own internal evidence-mechanics surface: importing these modules,
# or referencing the journal's on-disk files directly, bypasses the
# hound-research/hound_client seam a domain repo is supposed to use.
HOUND_INTERNAL_INDICATORS: tuple[dict[str, Any], ...] = (
    {"id": "houndd-journal-import", "category": "journal_write", "match": {"kind": "token", "value": "houndd.journal"}},
    {"id": "houndd-store-import", "category": "journal_write", "match": {"kind": "token", "value": "houndd.store"}},
    {"id": "houndd-commit-runtime-import", "category": "journal_write", "match": {"kind": "token", "value": "houndd.commit_runtime"}},
    {"id": "houndd-service-import", "category": "journal_write", "match": {"kind": "token", "value": "houndd.service"}},
    {"id": "chain-jsonl-reference", "category": "journal_write", "match": {"kind": "literal", "value": "chain.jsonl"}},
    {"id": "events-jsonl-reference", "category": "journal_write", "match": {"kind": "literal", "value": "events.jsonl"}},
)

# Bounded HSP-19 domain-logic vocabulary: none of this belongs inside
# repos/hound. Kept small and literal on purpose -- this is a fixture-graded
# static signal, not a generic classifier.
DOMAIN_LOGIC_INDICATORS: tuple[dict[str, Any], ...] = (
    {"id": "scheduler-apscheduler", "category": "scheduler", "match": {"kind": "token", "value": "apscheduler"}},
    {"id": "scheduler-croniter", "category": "scheduler", "match": {"kind": "token", "value": "croniter"}},
    {"id": "approval-db-store", "category": "approval_db", "match": {"kind": "token", "value": "ApprovalStore"}},
    {"id": "approval-db-file", "category": "approval_db", "match": {"kind": "literal", "value": "decisions.jsonl"}},
    {"id": "queue-celery", "category": "queue", "match": {"kind": "token", "value": "celery"}},
    {"id": "crm-contact-store", "category": "crm", "match": {"kind": "token", "value": "ContactStore"}},
    {"id": "crm-module-path", "category": "crm", "match": {"kind": "literal", "value": "gc-gtm/crm"}},
    {"id": "wiki-write", "category": "wiki", "match": {"kind": "token", "value": "WikiPage"}},
    {"id": "helm-events-db", "category": "helm", "match": {"kind": "literal", "value": "events.db"}},
    {"id": "pulse-curation", "category": "pulse_curation", "match": {"kind": "token", "value": "PulseEdition"}},
    {"id": "benefits-registry", "category": "benefits_registry", "match": {"kind": "token", "value": "BenefitsRegistry"}},
    {"id": "social-tweepy", "category": "social_publishing", "match": {"kind": "token", "value": "tweepy"}},
    {"id": "social-linkedin", "category": "social_publishing", "match": {"kind": "token", "value": "linkedin_api"}},
    {"id": "bb-runtime", "category": "bb_runtime", "match": {"kind": "token", "value": "bb_runtime"}},
    {"id": "discord-bot-client", "category": "discord", "match": {"kind": "token", "value": "discord_client"}},
    {"id": "calendar-event-write", "category": "calendar", "match": {"kind": "token", "value": "CalendarEvent"}},
    {"id": "git-domain-commit", "category": "git", "match": {"kind": "token", "value": "GitPython"}},
)

DEFAULT_ROOTS: tuple[str, ...] = ("repos", "agents")


def lane_for_path(relative: Path) -> str:
    """Group a workspace-relative path into its owning lane (repo/subrepo)."""

    parts = relative.parts
    if not parts:
        return "unknown"
    if parts[0] == "repos" and len(parts) >= 2:
        if parts[1] == "givecare" and len(parts) >= 3:
            return f"repos/givecare/{parts[2]}"
        return f"repos/{parts[1]}"
    if parts[0] == "agents" and len(parts) >= 2:
        return f"agents/{parts[1]}"
    return parts[0]


def classify_line(line: str, catalog: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """Return (domain_logic_indicator_ids, evidence_mechanics_indicator_ids) for one line."""

    domain_ids = sorted({indicator["id"] for indicator in DOMAIN_LOGIC_INDICATORS if _matches(indicator, line)})
    evidence_ids = sorted(
        {indicator["id"] for indicator in HOUND_INTERNAL_INDICATORS if _matches(indicator, line)}
        | {
            indicator["id"]
            for indicator in catalog.get("indicators", [])
            if indicator.get("category") in _EVIDENCE_CATALOG_CATEGORIES and _matches(indicator, line)
        }
    )
    return domain_ids, evidence_ids


def _excluded(path: Path) -> bool:
    return any(part in _ALL_EXCLUSIONS for part in path.parts)


@dataclass(frozen=True)
class LaneCapability:
    lane: str
    domain_logic_files: list[dict[str, Any]] = field(default_factory=list)
    evidence_mechanics_files: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class OwnershipResult:
    capability_dump: dict[str, Any]
    violations: list[str]
    failures: list[str]


def scan_workspace(workspace: Path, catalog: Mapping[str, Any], *, roots: Sequence[str] = DEFAULT_ROOTS) -> OwnershipResult:
    """Scan bounded *roots* under *workspace* and classify every file's ownership."""

    workspace = workspace.resolve()
    failures: list[str] = []
    lanes: dict[str, LaneCapability] = {}
    seen: set[Path] = set()

    for raw_root in roots:
        requested = workspace / raw_root
        problem = _path_problem(requested, workspace)
        if problem:
            failures.append(f"scan root {raw_root}: {problem}")
            continue
        root = requested.resolve()
        if not (root.is_file() or root.is_dir()):
            failures.append(f"scan root {raw_root}: not a file or directory")
            continue
        for path in _scan_candidates(root, workspace, failures):
            if path in seen:
                continue
            relative = path.relative_to(workspace)
            if _excluded(relative):
                continue
            problem = _path_problem(path, workspace)
            if problem:
                failures.append(f"scan file {relative}: {problem}")
                continue
            if path.is_dir() or not path.is_file():
                continue
            seen.add(path)
            try:
                size = path.stat().st_size
                if size > MAX_SCAN_BYTES:
                    failures.append(f"scan file {relative}: oversize ({size} bytes)")
                    continue
                text = path.read_bytes().decode("utf-8")
            except OSError as exc:
                failures.append(f"scan file {relative}: unreadable: {exc}")
                continue
            except UnicodeDecodeError:
                failures.append(f"scan file {relative}: non-UTF-8")
                continue
            lines = text.splitlines()
            if any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in lines):
                failures.append(f"scan file {relative}: line exceeds {MAX_LINE_BYTES} bytes")
                continue

            lane = lane_for_path(relative)
            domain_ids: set[str] = set()
            evidence_ids: set[str] = set()
            for line in lines:
                found_domain, found_evidence = classify_line(line, catalog)
                domain_ids.update(found_domain)
                evidence_ids.update(found_evidence)

            entry = lanes.setdefault(lane, LaneCapability(lane))
            if domain_ids:
                entry.domain_logic_files.append({"path": str(relative), "indicator_ids": sorted(domain_ids)})
            if evidence_ids:
                entry.evidence_mechanics_files.append({"path": str(relative), "indicator_ids": sorted(evidence_ids)})

    violations: list[str] = []
    for lane in sorted(lanes):
        capability = lanes[lane]
        if lane == HOUND_LANE:
            for finding in capability.domain_logic_files:
                violations.append(
                    f"Hound repo path {finding['path']} holds domain-logic indicator(s) "
                    f"{', '.join(finding['indicator_ids'])} (HSP-19 forbids domain ownership inside Hound)"
                )
        else:
            for finding in capability.evidence_mechanics_files:
                violations.append(
                    f"domain repo path {finding['path']} holds evidence-mechanics indicator(s) "
                    f"{', '.join(finding['indicator_ids'])} outside the allowed hound seams (HSP-19)"
                )

    capability_dump = {
        "schema_version": SCHEMA_VERSION,
        "lanes": [
            {
                "lane": lane,
                "domain_logic_files": sorted(lanes[lane].domain_logic_files, key=lambda item: item["path"]),
                "evidence_mechanics_files": sorted(lanes[lane].evidence_mechanics_files, key=lambda item: item["path"]),
            }
            for lane in sorted(lanes)
        ],
    }
    return OwnershipResult(capability_dump, violations, failures)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="check-domain-ownership", exit_on_error=False)
    parser.add_argument("--workspace", type=Path, required=True, help="workspace to scan")
    parser.add_argument("--catalog", type=Path, default=Path(__file__).with_name("provider-indicators.v1.json"))
    parser.add_argument("--root", action="append", dest="roots", help="workspace-relative scan root (repeatable)")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    try:
        args = parser.parse_args(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        return 0 if getattr(exc, "code", None) == 0 else 2

    errors: list[str] = []
    result: OwnershipResult | None = None
    try:
        catalog = load_catalog(args.catalog)
        result = scan_workspace(args.workspace, catalog, roots=tuple(args.roots) if args.roots else DEFAULT_ROOTS)
        errors.extend(result.failures)
        errors.extend(result.violations)
    except InventoryError as exc:
        errors.append(str(exc))

    report = {
        "schema_version": "hound.migration.domain-ownership-report.v1",
        "valid": not errors,
        "errors": errors,
        "capability_dump": None if result is None else result.capability_dump,
        "workspace": str(args.workspace),
    }
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print("valid" if report["valid"] else "invalid")
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
