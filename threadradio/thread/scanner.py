"""
scanner.py — Thread network active scan over an RCP radio.

Protocol (matches openthread_scan.log):
  1. SET PROP_MAC_15_4_PANID = 0xFFFF  (broadcast PAN filter)
  2. For each channel:
       a. SET PROP_STREAM_RAW — Beacon Request frame with channel in TX metadata
       b. Collect PROP_STREAM_RAW IS frames (beacons) until PROP_LAST_STATUS
       c. period_ms is the max dwell per channel if LAST_STATUS is slow or absent
"""

import struct
import sys
import time

from ..hardware import spinel
from . import beacon as _beacon


def scan(
    radio,
    channels: list[int] | range = range(11, 27),
    period_ms: int = 300,
    timeout: float | None = None,
) -> list[dict]:
    """
    Thread active network scan.  Returns a list of network dicts, one per
    unique (channel, pan_id, ext_addr) tuple seen during the scan.

    Args:
        radio:      A hardware.radio.Radio instance (any backend).
        channels:   802.15.4 channels to scan (default: 11-26).
        period_ms:  Maximum dwell time per channel in milliseconds.
        timeout:    Optional hard total timeout; shrinks period_ms proportionally.
    """
    channels = list(channels)
    if timeout is not None:
        period_ms = min(period_ms, max(1, int(timeout * 1000 / len(channels))))

    results: list[dict] = []
    seen:    set[tuple] = set()
    seq = 0x00

    radio.prop_set(spinel.PROP_PHY_ENABLED, 1)
    radio._prop_set_raw_wait(spinel.PROP_MAC_15_4_PANID, struct.pack('<H', 0xFFFF))

    try:
        for channel in channels:
            req    = bytearray(spinel.BEACON_REQUEST)
            req[2] = seq
            seq    = (seq + 1) & 0xFF

            # PROP_STREAM_RAW TX payload — matches openthread_scan.log:
            #   uint16-LE frame_len · frame(10B) · channel · maxCsmaBackoffs(4) ·
            #   maxFrameRetries(15) · csmaCaEnabled(1) · isHeaderUpdated(0) ·
            #   isARetx(0) · isSecurityProcessed(0) · txDelay(u32) ·
            #   txDelayBaseTime(u32) · rxChannelAfterTxDone · txPower(i8)
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
                    break
                if prop_id != spinel.PROP_STREAM_RAW:
                    continue
                frame, meta = spinel.parse_stream_raw(value)
                rssi        = meta[0]    if meta else 0
                lqi         = meta[3][1] if meta else 0
                if radio.debug:
                    fc = int.from_bytes(frame[:2], 'little') if len(frame) >= 2 else 0
                    print(f"[dwell ch={channel}] frame ({len(frame)}B) "
                          f"FC=0x{fc:04x} rssi={rssi} lqi={lqi}: {frame.hex()}",
                          file=sys.stderr)
                net = _beacon.parse_frame(frame, channel, rssi, lqi)
                if radio.debug and net is None:
                    print(f"[dwell ch={channel}] not a Thread beacon", file=sys.stderr)
                if net:
                    key = (channel, net['pan_id'], net['ext_addr'])
                    if key not in seen:
                        seen.add(key)
                        results.append(net)
    finally:
        radio.prop_set(spinel.PROP_PHY_ENABLED, 0)

    return results
