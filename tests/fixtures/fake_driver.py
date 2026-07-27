#!/usr/bin/env python3
"""A deliberately small Hound protocol driver used by integration tests."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import sys


request = json.load(sys.stdin)
mode = request.get("mode")
operation = request.get("operation")
payload = request.get("input", {})
ok = True
artifacts = []
proofs = []
diagnostics = []

if payload.get("require_env") and payload["require_env"] not in os.environ:
    raise SystemExit(20)
if payload.get("forbid_env") and payload["forbid_env"] in os.environ:
    raise SystemExit(21)

if payload.get("emit_noise"):
    print("not-json")

if mode == "check":
    data = {"protocol": "hound.protocol.v1"}
    outcome = "completed"
elif mode == "plan":
    if payload.get("plan_write_path"):
        plan_target = Path(payload["plan_write_path"])
        plan_target.parent.mkdir(parents=True, exist_ok=True)
        plan_target.write_text("plan side effect\n", encoding="utf-8")
    value = payload.get("value", "default")
    target = Path(payload.get("write_path", "output/result.json"))
    if payload.get("exact_effects"):
        output = (json.dumps({"value": value}, sort_keys=True) + "\n").encode()
        before = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None
        expected_mode = (
            f"{target.stat().st_mode & 0o777:04o}"
            if target.is_file()
            else payload.get("expected_mode", "0600")
        )
        data = {
            "expected_effects": [
                {
                    "path": target.as_posix(),
                    "mode": expected_mode,
                    "before_sha256": (
                        "0" * 64 if payload.get("wrong_before_hash") else before
                    ),
                    "after_sha256": (
                        "0" * 64
                        if payload.get("wrong_after_hash")
                        else hashlib.sha256(output).hexdigest()
                    ),
                }
            ],
            "value": value,
        }
    else:
        data = {
            "expected_writes": payload.get("expected_writes", ["output/result.json"]),
            "value": value,
        }
    if payload.get("plan_data_nonobject"):
        data = []
    ok = payload.get("plan_ok", True)
    artifacts = payload.get("plan_artifacts", [])
    proofs = payload.get("plan_proofs", [])
    diagnostics = payload.get("plan_diagnostics", [])
    outcome = "planned" if ok else "failed"
elif mode == "execute":
    if payload.get("tamper_run_record"):
        record = Path(".hound") / "runs" / request["plan_id"] / "plan.json"
        record.write_text("{}\n", encoding="utf-8")
    if payload.get("forge_result_record"):
        run_dir = Path(".hound") / "runs" / request["plan_id"]
        (run_dir / "result.json").write_text('{"forged":true}\n', encoding="utf-8")
        (run_dir / "index.json").write_text('{"forged":true}\n', encoding="utf-8")
    if payload.get("execute_fail"):
        data = {"reason": "synthetic"}
        diagnostics = payload.get(
            "execute_diagnostics",
            [{"level": "error", "message": "owner detail"}],
        )
        ok = False
        outcome = "failed"
    elif payload.get("no_edition"):
        data = {"reason": "threshold-not-met"}
        outcome = "no-edition"
    elif payload.get("skip_write"):
        data = {"written": []}
        outcome = payload.get("execute_outcome", "completed")
    else:
        if payload.get("effect_symlink_target"):
            Path("output").symlink_to(payload["effect_symlink_target"], target_is_directory=True)
        target = Path(payload.get("write_path", "output/result.json"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"value": request["driver_plan"]["value"]}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if request["driver_plan"].get("expected_effects"):
            target.chmod(int(request["driver_plan"]["expected_effects"][0]["mode"], 8))
        if payload.get("execute_mode"):
            target.chmod(int(payload["execute_mode"], 8))
        data = {"written": [target.as_posix()]}
        outcome = payload.get("execute_outcome", "completed")
else:
    if payload.get("read_write_path"):
        read_target = Path(payload["read_write_path"])
        read_target.write_text("read side effect\n", encoding="utf-8")
    if operation == "source.discover" and "searches" in payload:
        data = {
            "schema_version": "hound.source.discovery-spec.v2",
            "searches": payload["searches"],
            "limits": payload.get(
                "limits",
                {"max_requests": 4, "max_leads": 20, "max_bytes": 1_000_000},
            ),
        }
        data_schema = "hound.source.discovery-spec.v2"
    elif operation == "source.capture" and "captures" in payload.get("owner_input", {}):
        data = {
            "schema_version": "hound.source.capture-spec.v2",
            "captures": payload["owner_input"]["captures"],
        }
        data_schema = "hound.source.capture-spec.v2"
    elif operation == "source.inspect" and "capture_set" in payload:
        data = payload["capture_set"]
        data_schema = "hound.source.capture-set.v2"
    elif operation in {"web.search", "web.extract", "web.interact"}:
        data = json.loads(Path("fake-web-response.json").read_text(encoding="utf-8"))
        data_schema = "hound.web.adapter.v1"
    else:
        data = {"operation": operation, "echo": payload}
        data_schema = "fake.data.v1"
    outcome = payload.get("read_outcome", "completed")

json.dump(
    {
        "schema_version": "hound.driver.response.v1",
        "ok": ok,
        "outcome": outcome,
        "data_schema": locals().get("data_schema", "fake.data.v1"),
        "data": data,
        "artifacts": artifacts,
        "proofs": proofs,
        "diagnostics": diagnostics,
    },
    sys.stdout,
    sort_keys=True,
)
sys.stdout.write("\n")
