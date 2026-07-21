import hashlib
import json

import pytest

from hound_cli.contracts import (
    ContractError,
    canonical_hash,
    canonical_json,
    load_manifest,
    validate_manifest,
    validate_response,
)


def manifest(**overrides):
    value = {
        "schema_version": "hound.driver.v1",
        "id": "example-status",
        "protocol": "hound.protocol.v1",
        "owner": {"repo": "owners/example"},
        "exec": ["uv", "run", "scripts/knowledge-status.ts"],
        "capabilities": {
            "diagnose": {"effect": "read", "gate": "none"},
            "publish": {"effect": "write", "gate": "human"},
        },
    }
    value.update(overrides)
    return value


def response(**overrides):
    value = {
        "schema_version": "hound.driver.response.v1",
        "ok": True,
        "outcome": "completed",
    }
    value.update(overrides)
    return value


def test_validate_manifest_accepts_complete_manifest():
    value = manifest(
        run_root=".hound/runs",
        capture_root=".hound/captures",
        write_scopes=[".hound", "exports/report.json"],
        ignored_snapshot_excludes=["node_modules", "apps/web-pulse/.wrangler"],
        timeouts_seconds={"diagnose": 30, "publish": 120.5},
        env_allowlist=["FIRECRAWL_API_KEY", "CI"],
    )
    value["capabilities"]["diagnose"]["env_allowlist"] = ["EXA_API_KEY"]

    assert validate_manifest(value) == value


def test_validate_manifest_accepts_complete_source_composition():
    value = manifest(capabilities={
        operation: {
            "effect": "read",
            "gate": "none",
            "composition": "hound.source.v1",
        }
        for operation in ("source.discover", "source.capture", "source.inspect")
    })

    assert validate_manifest(value) == value


def test_validate_manifest_rejects_partial_source_composition():
    value = manifest(capabilities={
        "source.discover": {
            "effect": "read",
            "gate": "none",
            "composition": "hound.source.v1",
        }
    })

    with pytest.raises(ContractError, match="requires discover, capture, and inspect"):
        validate_manifest(value)


@pytest.mark.parametrize("locator", [".", "..", "../..", "../owner-repo"])
def test_validate_manifest_accepts_relative_owner_repo_locator(locator):
    value = manifest(owner={"repo": locator})

    assert validate_manifest(value) == value


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("schema_version", "hound.driver.v2"),
        ("id", ""),
        ("protocol", "hound.protocol.v2"),
        ("owner", {"repo": ""}),
        ("owner", {"repo": "/srv/owner-repo"}),
        ("owner", {"repo": "owner-repo", "team": "research"}),
        ("exec", "uv run driver.py"),
        ("exec", []),
        ("exec", [""]),
        ("exec", ["python", "bad\x00argument"]),
        ("capabilities", []),
        ("capabilities", {}),
        ("capabilities", {"diagnose": {"effect": "network", "gate": "none"}}),
        ("capabilities", {"diagnose": {"effect": [], "gate": "none"}}),
        ("capabilities", {"diagnose": {"effect": "read", "gate": "auto"}}),
        ("capabilities", {"diagnose": {"effect": "read", "gate": "human"}}),
        ("capabilities", {"diagnose": {"effect": "read", "gate": []}}),
        (
            "capabilities",
            {"diagnose": {"effect": "read", "gate": "none", "shell": True}},
        ),
        (
            "capabilities",
            {
                "diagnose": {
                    "effect": "read",
                    "gate": "none",
                    "env_allowlist": ["NOT-VALID"],
                }
            },
        ),
        (
            "capabilities",
            {
                "diagnose": {
                    "effect": "read",
                    "gate": "none",
                    "env_allowlist": ["DUPLICATE", "DUPLICATE"],
                }
            },
        ),
        (
            "capabilities",
            {
                "diagnose": {
                    "effect": "read",
                    "gate": "none",
                    "env_allowlist": ["PATH"],
                }
            },
        ),
        ("write_scopes", ["../outside"]),
        ("write_scopes", ["/tmp/output"]),
        ("ignored_snapshot_excludes", ["../outside"]),
        ("ignored_snapshot_excludes", ["cache", "cache"]),
        ("ignored_snapshot_excludes", ["."]),
        ("run_root", "../runs"),
        ("capture_root", "/tmp/captures"),
        ("timeouts_seconds", {"diagnose": 0}),
        ("timeouts_seconds", {"diagnose": True}),
        ("timeouts_seconds", {"diagnose": float("inf")}),
        ("env_allowlist", ["VALID_NAME", "NOT-VALID"]),
        ("env_allowlist", ["DUPLICATE", "DUPLICATE"]),
        ("env_allowlist", ["PATH"]),
    ],
)
def test_validate_manifest_rejects_malformed_values(field, bad_value):
    with pytest.raises(ContractError):
        validate_manifest(manifest(**{field: bad_value}))


@pytest.mark.parametrize(
    "missing", ["schema_version", "id", "protocol", "owner", "exec", "capabilities"]
)
def test_validate_manifest_requires_every_core_field(missing):
    value = manifest()
    value.pop(missing)

    with pytest.raises(ContractError, match=missing):
        validate_manifest(value)


def test_validate_manifest_rejects_unknown_top_level_field():
    with pytest.raises(ContractError, match="unknown"):
        validate_manifest(manifest(shell=True))


def test_validate_manifest_rejects_declarative_read_scopes():
    with pytest.raises(ContractError, match="read_scopes"):
        validate_manifest(manifest(read_scopes=["docs"]))


def test_validate_manifest_rejects_non_string_top_level_field():
    value = manifest()
    value[1] = True

    with pytest.raises(ContractError):
        validate_manifest(value)


def test_validate_manifest_rejects_non_object():
    with pytest.raises(ContractError):
        validate_manifest([])


def test_load_manifest_reads_and_validates_json(tmp_path):
    path = tmp_path / "driver.json"
    value = manifest()
    path.write_text(json.dumps(value), encoding="utf-8")

    assert load_manifest(path) == value


@pytest.mark.parametrize(
    "contents", ["not json", "[]", '{"schema_version": "hound.driver.v1"}']
)
def test_load_manifest_wraps_invalid_files_as_contract_errors(tmp_path, contents):
    path = tmp_path / "driver.json"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(ContractError):
        load_manifest(path)


def test_load_manifest_wraps_read_errors_as_contract_errors(tmp_path):
    with pytest.raises(ContractError):
        load_manifest(tmp_path / "missing.json")


@pytest.mark.parametrize(
    "outcome",
    ["planned", "completed", "no-change", "no-edition", "held", "failed"],
)
def test_validate_response_accepts_every_outcome(outcome):
    value = response(
        outcome=outcome,
        data_schema="hound.plan.v1",
        data={"items": []},
        artifacts=[{"path": ".hound/runs/run.json", "sha256": "abc"}],
        proofs=[{"kind": "test", "passed": True}],
        diagnostics=[{"level": "info", "message": "done"}],
    )

    assert validate_response(value) == value


@pytest.mark.parametrize(
    "value",
    [
        [],
        {"ok": True, "outcome": "completed"},
        response(schema_version="hound.driver.response.v2"),
        response(ok=1),
        response(outcome="success"),
        response(outcome=[]),
        response(extra=True),
        response(data_schema=""),
        response(artifacts={}),
        response(proofs={}),
        response(diagnostics={}),
    ],
)
def test_validate_response_rejects_protocol_mismatch_and_malformed_values(value):
    with pytest.raises(ContractError):
        validate_response(value)


def test_canonical_json_is_sorted_compact_and_unicode_preserving():
    value = {"z": [3, 2, 1], "é": "care", "a": {"b": True}}

    assert canonical_json(value) == '{"a":{"b":true},"z":[3,2,1],"é":"care"}'


def test_canonical_hash_is_sha256_of_canonical_utf8():
    value = {"é": "care", "a": 1}
    expected = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()

    assert canonical_hash(value) == expected
    assert canonical_hash({"a": 1, "é": "care"}) == expected


@pytest.mark.parametrize("value", [{"bad": float("nan")}, {1: "non-string key"}, {"bad": object()}])
def test_canonical_json_rejects_values_outside_the_json_contract(value):
    with pytest.raises(ContractError):
        canonical_json(value)
