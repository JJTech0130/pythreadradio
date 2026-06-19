"""
daemonslayer — keep a named macOS daemon suppressed.

With SIP enabled you cannot unload system launch daemons, so instead:
  1. Kill any running instance (SIGKILL).
  2. Watch for launchd to restart it (it will, quickly).
  3. The moment the new instance appears, SIGSTOP it.
  4. Loop forever — if it somehow resumes, kill and stop it again.

On exit (SIGINT/SIGTERM), resume the daemon so the system is left clean.
Must run as root.
"""

import argparse
import os
import signal
import subprocess
import sys
import time

_POLL_INTERVAL = 0.005  # 5 ms


def _find_pids(name: str) -> list[int]:
    result = subprocess.run(
        ["pgrep", "-x", name], capture_output=True, text=True
    )
    return [int(p) for p in result.stdout.split() if p]


def _is_stopped(pid: int) -> bool:
    result = subprocess.run(
        ["ps", "-o", "state=", "-p", str(pid)], capture_output=True, text=True
    )
    return result.stdout.strip().startswith("T")


def run(target: str, resume_on_exit: bool = True) -> None:
    running = True
    stopped_pid: int = 0

    def handle_sig(signum: int, frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT,  handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    print(f"[slayer] starting — watching for {target!r}", file=sys.stderr)

    for pid in _find_pids(target):
        print(f"[slayer] killing existing pid {pid}", file=sys.stderr)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if _find_pids(target):
        time.sleep(0.05)  # give launchd 50 ms to restart

    while running:
        for pid in _find_pids(target):
            if pid == stopped_pid:
                if not _is_stopped(pid):
                    print(f"[slayer] pid {pid} resumed unexpectedly, stopping", file=sys.stderr)
                    os.kill(pid, signal.SIGSTOP)
                continue
            print(f"[slayer] new {target!r} pid {pid} — stopping", file=sys.stderr)
            try:
                os.kill(pid, signal.SIGSTOP)
                stopped_pid = pid
            except ProcessLookupError:
                pass
        time.sleep(_POLL_INTERVAL)

    if resume_on_exit:
        print("[slayer] exiting — resuming daemon", file=sys.stderr)
        for pid in ([stopped_pid] if stopped_pid else []) + _find_pids(target):
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
    else:
        print("[slayer] exiting — leaving daemon stopped", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="daemonslayer",
        description="Keep a named macOS daemon suppressed via SIGSTOP (must run as root).",
    )
    parser.add_argument("daemon", help="Process name to suppress (e.g. threadradiod)")
    parser.add_argument(
        "--no-resume", action="store_true",
        help="Leave the daemon stopped on exit instead of resuming it",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("error: daemonslayer must run as root", file=sys.stderr)
        sys.exit(1)

    run(args.daemon, resume_on_exit=not args.no_resume)
