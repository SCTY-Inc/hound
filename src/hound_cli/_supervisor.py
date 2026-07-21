"""Internal driver-tree supervisor.

On Linux this process becomes a child subreaper, so descendants that detach from
the driver's session remain attributable and can be terminated before the
supervisor exits. This is containment hygiene for trusted drivers, not a sandbox.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import NoReturn


_PR_SET_CHILD_SUBREAPER = 36
_PR_SET_PDEATHSIG = 1
_child: subprocess.Popen[bytes] | None = None
_terminating = False


def _enable_linux_containment(parent_pid: int) -> bool:
    if not sys.platform.startswith("linux"):
        return True
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        return False
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
        return False
    return os.getppid() == parent_pid


def _linux_descendants(parent: int) -> set[int]:
    if not sys.platform.startswith("linux"):
        return set()
    descendants: set[int] = set()
    pending = [parent]
    while pending:
        current = pending.pop()
        children_file = Path(f"/proc/{current}/task/{current}/children")
        try:
            children = {
                int(value)
                for value in children_file.read_text(encoding="ascii").split()
            }
        except (OSError, ValueError):
            continue
        unseen = children - descendants
        descendants.update(unseen)
        pending.extend(unseen)
    descendants.discard(parent)
    return descendants


def _signal_processes(processes: set[int], signum: int) -> None:
    for pid in processes:
        try:
            os.kill(pid, signum)
        except ProcessLookupError:
            pass


def _terminate_descendants() -> None:
    targets = _linux_descendants(os.getpid())
    if _child is not None and _child.poll() is None:
        targets.add(_child.pid)
    _signal_processes(targets, signal.SIGTERM)
    deadline = time.monotonic() + 0.1
    while time.monotonic() < deadline:
        remaining = _linux_descendants(os.getpid())
        if not remaining:
            break
        time.sleep(0.01)
    targets.update(_linux_descendants(os.getpid()))
    _signal_processes(targets, signal.SIGKILL)
    reap_deadline = time.monotonic() + 0.5
    while time.monotonic() < reap_deadline:
        try:
            waited, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if waited == 0:
            time.sleep(0.01)


def _handle_termination(signum: int, _frame: object) -> NoReturn:
    global _terminating
    if not _terminating:
        _terminating = True
        _terminate_descendants()
    os._exit(128 + signum)


def main(argv: list[str] | None = None) -> int:
    global _child
    arguments = sys.argv[1:] if argv is None else argv
    if (
        len(arguments) < 4
        or arguments[0] != "--parent-pid"
        or arguments[2] != "--"
    ):
        return 125
    try:
        parent_pid = int(arguments[1])
    except ValueError:
        return 125
    if parent_pid <= 0:
        return 125
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, _handle_termination)
    if not _enable_linux_containment(parent_pid):
        sys.stderr.write("hound could not establish Linux driver-tree containment\n")
        return 125
    try:
        _child = subprocess.Popen(
            arguments[3:],
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
            stderr=sys.stderr.buffer,
            shell=False,
        )
    except OSError as error:
        sys.stderr.write(f"hound could not start driver: {error}\n")
        return 126

    returncode = _child.wait()
    _terminate_descendants()
    return returncode if returncode >= 0 else 128 - returncode


if __name__ == "__main__":
    raise SystemExit(main())
