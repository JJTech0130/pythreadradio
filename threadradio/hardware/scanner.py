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
    deadline: float | None = None,
) -> Generator[tuple[bytes, int, int, int], None, None]:
    """
    Generator: single-pass IEEE 802.15.4 active scan, yielding raw beacon frames.

    Yields (frame_bytes, channel, rssi, lqi) for each PROP_STREAM_RAW IS frame
    received during the scan window.  PHY is enabled on entry and restored to
    disabled on exit — including when the consumer breaks early or raises.

    Args:
        deadline: optional absolute monotonic time (time.monotonic()) at which
                  to stop early; checked at channel boundaries.  Pass this from
                  scan_iter() to bound continuous scans to a wall-clock timeout.

    LAST_STATUS is NOT used as an end-of-channel signal.  In raw RCP mode it
    means "TX done (CSMA-CA complete, frame on air)"; the NCP stays in RX mode
    afterwards.  Zigbee routers can take 10-30ms to respond, so the dwell window
    stays open for the full period_ms.
    """
    channels = list(channels)

    seq = 0x00
    radio.prop_set(spinel.PROP_PHY_ENABLED, 1)
    radio._prop_set_raw_wait(spinel.PROP_MAC_15_4_PANID, struct.pack('<H', 0xFFFF))

    try:
        for channel in channels:
            if deadline is not None and time.monotonic() >= deadline:
                return
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

            ch_deadline = time.monotonic() + period_ms / 1000
            while time.monotonic() < ch_deadline:
                ms  = max(1, int((ch_deadline - time.monotonic()) * 1000))
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
