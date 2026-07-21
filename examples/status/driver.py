#!/usr/bin/env python3
"""Minimal read-only Hound protocol driver."""

from __future__ import annotations

import json
import sys


request = json.load(sys.stdin)
mode = request.get("mode")

if mode == "check":
    data = {"protocol": "hound.protocol.v1"}
else:
    data = {
        "operation": request.get("operation"),
        "echo": request.get("input", {}),
    }

json.dump(
    {
        "schema_version": "hound.driver.response.v1",
        "ok": True,
        "outcome": "completed",
        "data_schema": "example.status.v1",
        "data": data,
        "artifacts": [],
        "proofs": [],
        "diagnostics": [],
    },
    sys.stdout,
    sort_keys=True,
)
sys.stdout.write("\n")
