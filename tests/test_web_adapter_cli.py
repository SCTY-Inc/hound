from __future__ import annotations

from pathlib import Path

import pytest

from hound_cli.orchestrator import check_driver
from hound_web_adapters._http import AdapterError
from hound_web_adapters.cli import run


ROOT = Path(__file__).parents[1]


def test_retired_searxng_adapter_is_not_callable() -> None:
    with pytest.raises(AdapterError, match="unknown first-party adapter 'searxng'"):
        run("searxng", {"mode": "check"}, {})


def test_first_party_adapter_manifests_handshake_through_the_public_driver_protocol() -> None:
    for name in ("exa", "firecrawl", "camofox"):
        result = check_driver(ROOT / "adapters" / name / "hound-driver.json")
        assert result["ok"] is True
        assert result["data"]["adapter"] == name
