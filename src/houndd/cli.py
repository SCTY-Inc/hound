"""Foreground command for the Slice 3B local service."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
from typing import Sequence

from .service import HounddService, ServiceError


def _default_state() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", os.fspath(Path.home() / ".local" / "state"))) / "hound" / "discovery"


def _default_socket() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime or not os.path.isabs(runtime):
        raise ServiceError("XDG_RUNTIME_DIR must be an absolute path or --socket must be supplied")
    return Path(runtime) / "hound" / "houndd.sock"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="houndd")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Run the local read service in the foreground")
    serve.add_argument("--state", type=Path, default=_default_state())
    serve.add_argument("--socket", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        socket_path = args.socket if args.socket is not None else _default_socket()
        if not args.state.is_absolute() or not socket_path.is_absolute():
            raise ServiceError("--state and --socket must be absolute paths")
        service = HounddService(state_root=args.state, socket_path=socket_path)
    except ServiceError:
        return 5
    previous = signal.signal(signal.SIGTERM, lambda *_: service.close())
    try:
        service.serve_forever()
        return 0
    finally:
        signal.signal(signal.SIGTERM, previous)
        service.close()


if __name__ == "__main__":
    raise SystemExit(main())
