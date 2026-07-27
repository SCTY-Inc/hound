#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def response(outcome: str, data: dict[str, object]) -> None:
    json.dump(
        {
            "schema_version": "hound.driver.response.v1",
            "ok": outcome not in {"held", "failed"},
            "outcome": outcome,
            "data_schema": "config-migration.v1",
            "data": data,
            "artifacts": [],
            "proofs": [],
            "diagnostics": [],
        },
        sys.stdout,
        sort_keys=True,
    )
    sys.stdout.write("\n")


request = json.load(sys.stdin)
mode = request["mode"]
path = Path("config.json")
if mode == "check":
    response("completed", {"protocol": "hound.protocol.v1"})
elif mode == "read":
    response("completed", {"config": json.loads(path.read_text())})
else:
    target = request["input"]["target"]
    payload = (json.dumps(target, indent=2, sort_keys=True) + "\n").encode()
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    after = hashlib.sha256(payload).hexdigest()
    mode_value = f"{path.stat().st_mode & 0o777:04o}"
    plan = {
        "expected_effects": [
            {
                "path": "config.json",
                "mode": mode_value,
                "before_sha256": before,
                "after_sha256": after,
            }
        ],
        "target": target,
    }
    if mode == "plan":
        response("planned", plan)
    else:
        if request["driver_plan"] != plan:
            response("failed", {"reason": "plan mismatch"})
        else:
            path.write_bytes(payload)
            path.chmod(int(mode_value, 8))
            response("completed", {"written": ["config.json"]})
