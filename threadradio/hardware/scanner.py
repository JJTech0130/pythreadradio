"""
scanner.py — generic IEEE 802.15.4 active scan over Spinel RCP.

Yields raw received beacon frames; protocol-specific parsing (Thread, Zigbee,
…) is handled by the caller.
"""

import struct
import sys
import time
from collections.abc import Generator

from . import spinel


def raw_scan(
    radio,
    channels: list[int] | range = range(11, 27),
    period_ms: int = 300,
    timeout: float | None = None,
) -> Generator[tuple[bytes, int, int, int], None, None]:
    """
    Generator: perform an IEEE 802.15.4 active scan, yielding raw beacon frames.

    Yields (frame_bytes, channel, rssi, lqi) for each PROP_STREAM_RAW IS frame
    received during the scan window.  PHY is enabled on entry and restored to
    disabled on exit — including when the consumer breaks early or raises.

    Protocol:
      1. SET PROP_MAC_15_4_PANID = 0xFFFF   broadcast PAN filter
      2. Per channel: TX Beacon Request via PROP_STREAM_RAW
      3. Listen for PROP_STREAM_RAW IS frames for the full period_ms dwell

    LAST_STATUS is NOT used as an end-of-channel signal here.  In raw RCP mode
    LAST_STATUS means "TX done (CSMA-CA complete, frame on air)" — the NCP then
    stays in RX mode.  Zigbee routers can take 10–30 ms to send a beacon after
    receiving a Beacon Request, so we must hold the dwell window open for the
    full period_ms rather than breaking early on TX-done.
    (Thread beacons arrive quickly enough that the deadline handles termination.)
    """
    channels = list(channels)
    if timeout is not None:
        period_ms = min(period_ms, max(1, int(timeout * 1000 / len(channels))))

    seq = 0x00
    radio.prop_set(spinel.PROP_PHY_ENABLED, 1)
    radio._prop_set_raw_wait(spinel.PROP_MAC_15_4_PANID, struct.pack('<H', 0xFFFF))

    try:
        for channel in channels:
            req    = bytearray(spinel.BEACON_REQUEST)
            req[2] = seq
            seq    = (seq + 1) & 0xFF

            tx = (
                struct.pack('<H', len(req)) + bytes(req)
                + bytes([channel, 4, 15, 1, 0, 0, 0])
                + struct.pack('<II', 0, 0)
                + bytes([channel])
                + struct.pack('<b', 0)
            )
            radio._prop_set_raw(spinel.PROP_STREAM_RAW, tx)

            deadline = time.monotonic() + period_ms / 1000
            while time.monotonic() < deadline:
                ms  = max(1, int((deadline - time.monotonic()) * 1000))
                pkt = radio.recv(timeout_ms=ms)
                if pkt is None:
                    continue
                _, _, prop_id, value = pkt
                if prop_id == spinel.PROP_LAST_STATUS:
                    continue  # TX done — NCP stays in RX; keep listening until deadline
                if prop_id != spinel.PROP_STREAM_RAW:
                    continue
                frame, meta = spinel.parse_stream_raw(value)
                rssi = meta[0]    if meta else 0
                lqi  = meta[3][1] if meta else 0
                if radio.debug:
                    fc = int.from_bytes(frame[:2], 'little') if len(frame) >= 2 else 0
                    print(f"[dwell ch={channel}] frame ({len(frame)}B) "
                          f"FC=0x{fc:04x} rssi={rssi} lqi={lqi}: {frame.hex()}",
                          file=sys.stderr)
                yield frame, channel, rssi, lqi
    finally:
        radio.prop_set(spinel.PROP_PHY_ENABLED, 0)
