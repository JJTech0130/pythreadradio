"""
scanner.py — Zigbee network active scan.
"""

import sys
import time
from collections.abc import Generator

from ..hardware import scanner as _raw
from . import beacon as _beacon


def scan(
    radio,
    channels: list[int] | range = range(11, 27),
    period_ms: int = 300,
) -> list[dict]:
    """Single-pass scan; returns deduplicated list of Zigbee network dicts."""
    results: list[dict] = []
    seen:    set[str]   = set()

    for frame, channel, rssi, lqi in _raw.raw_scan(radio, channels, period_ms):
        net = _beacon.parse_frame(frame, channel, rssi, lqi)
        if radio.debug and net is None:
            print(f"[dwell ch={channel}] not a Zigbee beacon", file=sys.stderr)
        if net:
            key = net['ext_pan_id']
            if key not in seen:
                seen.add(key)
                results.append(net)

    return results


def scan_iter(
    radio,
    channels: list[int] | range = range(11, 27),
    period_ms: int = 300,
    deadline: float | None = None,
) -> Generator[dict, None, None]:
    """
    Generator: loops through channels repeatedly, yielding each newly-seen
    Zigbee network as it is first discovered.  Runs until the caller breaks,
    a KeyboardInterrupt is raised, or deadline (monotonic time) is reached.
    Deduplication is maintained globally across all passes.
    """
    seen: set[str] = set()
    while True:
        for frame, channel, rssi, lqi in _raw.raw_scan(radio, channels, period_ms, deadline):
            net = _beacon.parse_frame(frame, channel, rssi, lqi)
            if radio.debug and net is None:
                print(f"[dwell ch={channel}] not a Zigbee beacon", file=sys.stderr)
            if net:
                key = net['ext_pan_id']
                if key not in seen:
                    seen.add(key)
                    yield net
        if deadline is not None and time.monotonic() >= deadline:
            return
