"""
scanner.py — Zigbee network active scan.
"""

import sys

from ..hardware import scanner as _raw
from . import beacon as _beacon


def scan(
    radio,
    channels: list[int] | range = range(11, 27),
    period_ms: int = 300,
    timeout: float | None = None,
) -> list[dict]:
    """
    Scan for Zigbee networks; returns a list of network dicts (one per unique
    channel+pan_id+ext_pan_id).
    """
    results: list[dict] = []
    seen:    set[tuple] = set()

    for frame, channel, rssi, lqi in _raw.raw_scan(radio, channels, period_ms, timeout):
        net = _beacon.parse_frame(frame, channel, rssi, lqi)
        if radio.debug and net is None:
            print(f"[dwell ch={channel}] not a Zigbee beacon", file=sys.stderr)
        if net:
            # §5 / NLME-NETWORK-DISCOVERY.confirm: deduplicate by Extended PAN ID
            key = net['ext_pan_id']
            if key not in seen:
                seen.add(key)
                results.append(net)

    return results
