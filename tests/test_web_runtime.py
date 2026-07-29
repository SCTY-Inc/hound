from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from hound_cli.contracts import canonical_hash, canonical_json
from hound_research.web import WebError, run_web, verify_web_run


def _raw(value: object) -> tuple[str, str]:
    body = canonical_json(value).encode("utf-8")
    return base64.b64encode(body).decode("ascii"), hashlib.sha256(body).hexdigest()


def _lead(url: str = "https://example.test/listing") -> dict[str, object]:
    return {
        "schema_version": "hound.lead.v1",
        "evidence_status": "not-evidence",
        "provider": "exa",
        "query": "used family SUV Long Island",
        "url": url,
        "title": "2021 family SUV",
        "metadata": {"rank": 1},
    }


def _search_adapter_data() -> dict[str, object]:
    body_base64, sha256 = _raw({"query": "used family SUV Long Island", "results": []})
    return {
        "schema_version": "hound.web.adapter.v1",
        "retrieved_at": "2026-07-21T12:00:00Z",
        "raw": {
            "media_type": "application/json",
            "body_base64": body_base64,
            "sha256": sha256,
        },
        "output": {
            "schema_version": "hound.web.search.v1",
            "trust": "untrusted",
            "evidence_status": "not-evidence",
            "leads": [_lead()],
        },
        "usage": {
            "requests": 1,
            "bytes": len(base64.b64decode(body_base64)),
        },
    }


def _configure_adapter(repo: Path, data: dict[str, object]) -> None:
    (repo / "fake-web-response.json").write_text(
        json.dumps(data, sort_keys=True) + "\n", encoding="utf-8"
    )


def _search_input() -> dict[str, object]:
    return {"query": "used family SUV Long Island", "limit": 5}


def test_search_persists_a_verifiable_provenance_record(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    record_root = tmp_path / "records"
    _configure_adapter(repo, _search_adapter_data())

    result = run_web(
        manifest_path,
        "search",
        _search_input(),
        record_root=record_root,
        as_of="2026-07-21",
    )

    assert result["ok"] is True
    assert result["operation"] == "search"
    assert result["data"]["leads"][0]["url"] == _lead()["url"]
    assert len(result["data"]["leads"][0]["lead_id"]) == 64
    assert result["data"]["leads"][0]["search_record_id"] == result["record_id"]
    assert result["evidence_status"] == "not-evidence"
    run_dir = Path(result["run_dir"])
    assert run_dir.parent == record_root.resolve()
    assert (run_dir / "raw.bin").read_bytes() == canonical_json(
        {"query": "used family SUV Long Island", "results": []}
    ).encode("utf-8")
    assert verify_web_run(run_dir) == {
        "schema_version": "hound.run.verification.v1",
        "valid": True,
        "plan_id": result["record_id"],
        "failures": [],
    }


def test_web_record_uses_the_manifest_and_state_from_the_completed_invocation(
    driver_repo: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path = driver_repo
    executed_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    executed_manifest["id"] = "executed-adapter"
    fingerprint = "a" * 64
    response = {
        "schema_version": "hound.driver.response.v1",
        "ok": True,
        "outcome": "completed",
        "data_schema": "hound.web.adapter.v1",
        "data": _search_adapter_data(),
        "artifacts": [],
        "proofs": [],
        "diagnostics": [],
    }
    receipt = {
        "schema_version": "hound.invocation.receipt.v1",
        "manifest": executed_manifest,
        "manifest_sha256": canonical_hash(executed_manifest),
        "repository": {"head": "b" * 40, "fingerprint_sha256": fingerprint},
        "environment_sha256": "c" * 64,
        "kernel": {"version": "0.3.0", "sha256": "d" * 64, "dependencies": {}},
    }
    monkeypatch.setattr(
        "hound_research.web.invoke_read_with_receipt",
        lambda *_args, **_kwargs: (response, receipt),
    )

    result = run_web(
        manifest_path,
        "search",
        _search_input(),
        record_root=tmp_path / "records",
    )

    run_dir = Path(result["run_dir"])
    stored_manifest = json.loads((run_dir / "adapter-manifest.json").read_text())
    stored_state = json.loads((run_dir / "adapter-state.json").read_text())
    assert stored_manifest["id"] == "executed-adapter"
    assert stored_state["repository"]["fingerprint_sha256"] == fingerprint
    assert verify_web_run(run_dir)["valid"] is True


def test_web_record_verification_detects_raw_byte_tampering(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    _configure_adapter(repo, _search_adapter_data())
    result = run_web(
        manifest_path,
        "search",
        _search_input(),
        record_root=tmp_path / "records",
    )
    raw_path = Path(result["run_dir"]) / "raw.bin"
    raw_path.write_bytes(b"tampered")

    verified = verify_web_run(result["run_dir"])

    assert verified["valid"] is False
    assert "raw.bin" in verified["failures"]


def test_search_options_and_routing_are_bound_into_the_record(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    adapter_data = _search_adapter_data()
    adapter_data["output"]["routing"] = {
        "completed_pages": 1,
        "config_sha256": "c" * 64,
        "corrections": [],
        "requested_categories": ["government"],
        "requested_engines": [],
        "suggestions": ["caregiver benefits"],
        "unresponsive_engines": [{"engine": "google", "error": "timeout"}],
    }
    _configure_adapter(repo, adapter_data)

    result = run_web(
        manifest_path,
        "search",
        {
            "query": "used family SUV Long Island",
            "limit": 5,
            "options": {"categories": ["government"], "max_pages": 1},
        },
        record_root=tmp_path / "records",
    )

    request = json.loads((Path(result["run_dir"]) / "request.json").read_text(encoding="utf-8"))
    assert request["input"]["options"] == {
        "categories": ["government"],
        "max_pages": 1,
    }
    assert result["data"]["routing"]["suggestions"] == ["caregiver benefits"]
    assert verify_web_run(result["run_dir"])["valid"] is True


def test_web_record_verification_rejects_symlinked_files(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    _configure_adapter(repo, _search_adapter_data())
    result = run_web(
        manifest_path,
        "search",
        _search_input(),
        record_root=tmp_path / "records",
    )
    raw_path = Path(result["run_dir"]) / "raw.bin"
    outside = tmp_path / "outside.bin"
    outside.write_bytes(raw_path.read_bytes())
    raw_path.unlink()
    raw_path.symlink_to(outside)

    verified = verify_web_run(result["run_dir"])

    assert verified["valid"] is False
    assert "raw.bin" in verified["failures"]


def test_decoded_adapter_credentials_are_rejected_before_record_persistence(
    driver_repo: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, manifest_path = driver_repo
    secret = "secret-inside-provider-body"
    adapter_data = _search_adapter_data()
    inner = canonical_json({"token": secret}).encode()
    body_base64, sha256 = _raw(
        {"exchange": {"body_base64": base64.b64encode(inner).decode("ascii")}}
    )
    adapter_data["raw"] = {
        "media_type": "application/json",
        "body_base64": body_base64,
        "sha256": sha256,
    }
    adapter_data["usage"]["bytes"] = len(base64.b64decode(body_base64))
    _configure_adapter(repo, adapter_data)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["capabilities"]["web.search"]["env_allowlist"] = ["WEB_API_KEY"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("WEB_API_KEY", secret)

    result = run_web(
        manifest_path,
        "search",
        _search_input(),
        record_root=tmp_path / "records",
    )

    assert result["ok"] is False
    assert "credential" in result["error"]
    for path in Path(result["run_dir"]).iterdir():
        assert secret.encode() not in path.read_bytes()


def test_invalid_adapter_hash_fails_closed_and_records_the_attempt(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    adapter_data = _search_adapter_data()
    adapter_data["raw"]["sha256"] = "0" * 64
    _configure_adapter(repo, adapter_data)

    result = run_web(
        manifest_path,
        "search",
        _search_input(),
        record_root=tmp_path / "records",
    )

    assert result["ok"] is False
    assert result["outcome"] == "failed"
    assert "raw sha256" in result["error"]
    assert verify_web_run(result["run_dir"])["valid"] is True


def test_search_rejects_private_result_urls_and_records_failure(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    adapter_data = _search_adapter_data()
    adapter_data["output"]["leads"] = [_lead("http://127.0.0.1/admin")]
    _configure_adapter(repo, adapter_data)

    result = run_web(
        manifest_path,
        "search",
        _search_input(),
        record_root=tmp_path / "records",
    )

    assert result["ok"] is False
    assert "public HTTP URL" in result["error"]
    assert verify_web_run(result["run_dir"])["valid"] is True


def test_extract_returns_a_bounded_context_view_and_keeps_the_full_record(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    markdown = "vehicle detail " * 2_000
    body_base64, raw_sha256 = _raw({"markdown": markdown})
    _configure_adapter(
        repo,
        {
            "schema_version": "hound.web.adapter.v1",
            "retrieved_at": "2026-07-21T12:00:00Z",
            "raw": {
                "media_type": "application/json",
                "body_base64": body_base64,
                "sha256": raw_sha256,
            },
            "output": {
                "schema_version": "hound.web.extract.v1",
                "trust": "untrusted",
                "evidence_class": "provider-derived",
                "documents": [
                    {
                        "url": "https://example.test/listing",
                        "markdown": markdown,
                        "markdown_sha256": hashlib.sha256(markdown.encode()).hexdigest(),
                        "links": [],
                        "metadata": {},
                    }
                ],
            },
            "usage": {"requests": 1, "bytes": len(base64.b64decode(body_base64))},
        },
    )

    result = run_web(
        manifest_path,
        "extract",
        {"url": "https://example.test/listing", "lineage": {"kind": "direct"}},
        record_root=tmp_path / "records",
    )

    preview = result["data"]["documents"][0]
    assert len(preview["markdown"]) == 12_000
    assert preview["markdown_truncated"] is True
    assert preview["markdown_total_chars"] == len(markdown)
    stored = json.loads(Path(result["output_path"]).read_text(encoding="utf-8"))
    assert stored["documents"][0]["markdown"] == markdown
    assert verify_web_run(result["run_dir"])["valid"] is True


def test_extract_binds_an_exact_search_record_and_lead(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    record_root = tmp_path / "records"
    _configure_adapter(repo, _search_adapter_data())
    search = run_web(
        manifest_path,
        "search",
        _search_input(),
        record_root=record_root,
    )
    lead = search["data"]["leads"][0]
    markdown = "verified detail"
    body_base64, raw_sha256 = _raw({"markdown": markdown})
    _configure_adapter(
        repo,
        {
            "schema_version": "hound.web.adapter.v1",
            "retrieved_at": "2026-07-21T12:01:00Z",
            "raw": {
                "media_type": "application/json",
                "body_base64": body_base64,
                "sha256": raw_sha256,
            },
            "output": {
                "schema_version": "hound.web.extract.v1",
                "trust": "untrusted",
                "evidence_class": "provider-derived",
                "documents": [
                    {
                        "url": lead["url"],
                        "markdown": markdown,
                        "markdown_sha256": hashlib.sha256(markdown.encode()).hexdigest(),
                        "links": [],
                        "metadata": {},
                    }
                ],
            },
            "usage": {"requests": 1, "bytes": len(base64.b64decode(body_base64))},
        },
    )
    lineage = {
        "kind": "search",
        "record_id": search["record_id"],
        "lead_id": lead["lead_id"],
    }

    extracted = run_web(
        manifest_path,
        "extract",
        {"url": lead["url"], "lineage": lineage},
        record_root=record_root,
    )

    assert extracted["ok"] is True
    request = json.loads((Path(extracted["run_dir"]) / "request.json").read_text())
    assert request["input"]["lineage"] == lineage
    assert verify_web_run(extracted["run_dir"])["valid"] is True

    with pytest.raises(WebError, match="lead does not match"):
        run_web(
            manifest_path,
            "extract",
            {"url": "https://example.test/other", "lineage": lineage},
            record_root=record_root,
        )


def _interact_adapter_data(action: str, session_id: str) -> dict[str, object]:
    body_base64, sha256 = _raw({"action": action, "session": session_id})
    return {
        "schema_version": "hound.web.adapter.v1",
        "retrieved_at": "2026-07-21T12:00:00Z",
        "raw": {
            "media_type": "application/json",
            "body_base64": body_base64,
            "sha256": sha256,
        },
        "output": {
            "schema_version": "hound.web.interact.v1",
            "trust": "untrusted",
            "evidence_class": "provider-derived",
            "action": action,
            "session_id": session_id,
            "result": {"ok": True},
        },
        "usage": {"requests": 1, "bytes": len(base64.b64decode(body_base64))},
    }


def test_interact_enforces_one_record_root_session_and_action_budget(
    driver_repo: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, manifest_path = driver_repo
    record_root = tmp_path / "records"
    session_id = "hound-session-1"
    _configure_adapter(repo, _interact_adapter_data("open", session_id))
    opened = run_web(
        manifest_path,
        "interact",
        {"action": "open", "url": "https://example.test/listing"},
        record_root=record_root,
    )
    assert opened["ok"] is True

    _configure_adapter(repo, _interact_adapter_data("snapshot", session_id))
    for offset in range(29):
        result = run_web(
            manifest_path,
            "interact",
            {
                "action": "snapshot",
                "session_id": session_id,
                "tab_id": "tab-1",
                "offset": offset,
            },
            record_root=record_root,
        )
        assert result["ok"] is True

    with pytest.raises(WebError, match="action budget"):
        run_web(
            manifest_path,
            "interact",
            {
                "action": "snapshot",
                "session_id": session_id,
                "tab_id": "tab-1",
            },
            record_root=record_root,
        )


@pytest.mark.parametrize(
    ("verb", "payload", "message"),
    [
        ("search", {"query": "cars", "limit": 51}, "limit"),
        (
            "extract",
            {
                "url": "https://example.test",
                "lineage": {"kind": "direct"},
                "max_pages": 21,
            },
            "max_pages",
        ),
        (
            "interact",
            {
                "action": "type",
                "session_id": "session-1",
                "tab_id": "tab-1",
                "ref": "e1",
                "text": "send this",
                "submit": True,
            },
            "unknown fields",
        ),
    ],
)
def test_web_input_bounds_fail_before_adapter_execution(
    driver_repo: tuple[Path, Path],
    tmp_path: Path,
    verb: str,
    payload: dict[str, object],
    message: str,
) -> None:
    _, manifest_path = driver_repo

    with pytest.raises(WebError, match=message):
        run_web(manifest_path, verb, payload, record_root=tmp_path / "records")

    assert not (tmp_path / "records").exists()
