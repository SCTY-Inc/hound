from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from hound_cli.orchestrator import check_driver
from hound_research.web import run_web, verify_web_run


ROOT = Path(__file__).parents[1]


def test_first_party_adapter_manifests_handshake_through_the_public_driver_protocol() -> None:
    for name in ("searxng", "exa", "firecrawl", "camofox"):
        result = check_driver(ROOT / "adapters" / name / "hound-driver.json")
        assert result["ok"] is True
        assert result["data"]["adapter"] == name


def test_searxng_adapter_runs_out_of_process_and_leaves_a_verifiable_record(
    tmp_path: Path, monkeypatch
) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/config":
                value = {
                    "categories": ["general"],
                    "engines": [
                        {
                            "categories": ["general"],
                            "enabled": True,
                            "name": "brave",
                            "shortcut": "br",
                        }
                    ],
                }
            else:
                value = {
                    "query": "2020 Lexus GX 460 Long Island",
                    "results": [
                        {
                            "url": "https://example.com/listings/gx-460",
                            "title": "2020 Lexus GX 460",
                            "content": "Dealer listing",
                            "engines": ["brave"],
                            "score": 4.2,
                            "category": "general",
                        }
                    ],
                }
            body = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("SEARXNG_ENDPOINT", f"http://127.0.0.1:{server.server_port}")
    try:
        result = run_web(
            ROOT / "adapters" / "searxng" / "hound-driver.json",
            "search",
            {"query": "2020 Lexus GX 460 Long Island", "limit": 5},
            record_root=tmp_path / "records",
            as_of="2026-07-21",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["ok"] is True
    assert result["data"]["leads"][0]["url"] == "https://example.com/listings/gx-460"
    assert verify_web_run(result["run_dir"])["valid"] is True


def test_failed_adapter_response_bytes_remain_in_the_provenance_record(
    tmp_path: Path, monkeypatch
) -> None:
    failure_body = b"JSON output is disabled"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(403)
            self.send_header("Content-Length", str(len(failure_body)))
            self.end_headers()
            self.wfile.write(failure_body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("SEARXNG_ENDPOINT", f"http://127.0.0.1:{server.server_port}")
    try:
        result = run_web(
            ROOT / "adapters" / "searxng" / "hound-driver.json",
            "search",
            {"query": "family SUV", "limit": 5},
            record_root=tmp_path / "records",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["ok"] is False
    raw = json.loads((Path(result["run_dir"]) / "raw.bin").read_bytes())
    assert raw["config"]["status"] == 403
    assert base64.b64decode(raw["config"]["body_base64"]) == failure_body
    assert raw["pages"] == []
    assert verify_web_run(result["run_dir"])["valid"] is True
