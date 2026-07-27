from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.fixture
def fake_driver_path() -> Path:
    return Path(__file__).parent / "fixtures" / "fake_driver.py"


@pytest.fixture
def driver_repo(tmp_path: Path, fake_driver_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "owner"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "hound@example.test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Hound Tests"], cwd=repo, check=True)
    (repo / ".gitignore").write_text(".hound/\n", encoding="utf-8")
    (repo / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore", "seed.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "seed"], cwd=repo, check=True)

    manifest = {
        "schema_version": "hound.driver.v1",
        "id": "fake",
        "protocol": "hound.protocol.v1",
        "owner": {"repo": "."},
        "exec": [sys.executable, str(fake_driver_path)],
        "capabilities": {
            operation: {"effect": "read", "gate": "none"}
            for operation in ("source.discover", "source.capture", "source.inspect")
        }
        | {
            "web.search": {"effect": "read", "gate": "none"},
            "web.extract": {"effect": "read", "gate": "none"},
            "web.interact": {"effect": "read", "gate": "none"},
            "corpus.status": {"effect": "read", "gate": "none"},
            "corpus.apply": {"effect": "write", "gate": "human"},
            "edition.build": {"effect": "write", "gate": "none"},
        },
        "extensions": {
            "research": {
                "schema_version": "hound.source.v2",
                "adapters": {
                    "search": "hound-driver.json",
                    "extract": "hound-driver.json",
                },
            },
        },
        "run_root": ".hound/runs",
        "write_scopes": ["output"],
        "timeouts_seconds": {"default": 10},
        "env_allowlist": [],
    }
    manifest_path = repo / "hound-driver.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return repo, manifest_path
