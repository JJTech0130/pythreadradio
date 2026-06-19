"""
thread.py — Thread radio interface.

Glues Skywalk (raw slot I/O) + HDLC (framing) + Spinel (protocol) into a
single object that sends and receives Spinel packets over a TSI channel.
"""

import struct
import sys
import time

from . import hdlc
from . import spinel
from .skywalk import SkywalkChannel, open_channel, close_channel, read_slot, write_slot

_DEFAULT_TIMEOUT = 2.0   # seconds

_CMD_NAMES = {
    1: "RESET",  2: "GET",    3: "SET",
    6: "IS",     7: "INSERTED",
}
_PROP_NAMES = {
    0x00: "LAST_STATUS",  0x20: "PHY_ENABLED",  0x21: "PHY_CHAN",
    0x34: "15_4_LADDR",  0x35: "15_4_SADDR",   0x36: "15_4_PANID",
    0x30: "SCAN_STATE",   0x31: "SCAN_MASK",    0x32: "SCAN_PERIOD",
    0x33: "SCAN_BEACON",  0x37: "RAW_STREAM_EN", 0x38: "FILTER_MODE",
    0x71: "STREAM_RAW",
}


def _dbg(direction: str, tid: int, cmd: int, prop_id: int, value: bytes) -> None:
    cmd_s  = _CMD_NAMES.get(cmd,     f"cmd={cmd}")
    prop_s = _PROP_NAMES.get(prop_id, f"prop=0x{prop_id:02x}")
    val_s  = value.hex() if len(value) <= 64 else value[:64].hex() + f"…+{len(value)-64}"
    ts     = time.monotonic()
    print(f"[{ts:.3f}] [spinel {direction}] tid=0x{tid:02x} {cmd_s} {prop_s} {val_s}",
          file=sys.stderr)


class ThreadInterface:
    """
    High-level interface to the Thread NCP via the Skywalk TSI channel.

    Usage::

        with ThreadInterface() as radio:
            radio.reset()
            radio.prop_set(spinel.PROP_PHY_CHAN, 15)
            while True:
                pkt = radio.recv(timeout_ms=1000)
                ...
    """

    def __init__(self, protocol: str = "tsi", debug: bool = False) -> None:
        self._ch: SkywalkChannel = open_channel(protocol)
        self._debug = debug

    # ── context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "ThreadInterface":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        close_channel(self._ch)

    # ── low-level send / recv ─────────────────────────────────────────────────

    def send(self, tid: int, cmd: int, payload: bytes = b'') -> None:
        """Build a Spinel frame, HDLC-encode it, and write it as one slot."""
        if self._debug:
            prop_id, n = spinel.decode_i(payload) if payload else (0, 0)
            _dbg("TX", tid, cmd, prop_id, payload[n:])
        frame = hdlc.encode(spinel.build(tid, cmd, payload))
        write_slot(self._ch, frame)

    def recv(self, timeout_ms: int = 1000) -> tuple[int, int, int, bytes] | None:
        """
        Read one slot, HDLC-decode it, and parse the Spinel frame.
        Returns (tid, cmd, prop_id, value) or None on timeout / decode error.
        """
        raw = read_slot(self._ch, timeout_ms=timeout_ms)
        if raw is None:
            return None
        pkt = hdlc.decode(raw)
        if not pkt or len(pkt) < 2:
            return None
        result = spinel.parse(pkt)
        if self._debug and result:
            _dbg("RX", *result)
        return result

    # ── higher-level helpers ──────────────────────────────────────────────────

    def reset(self, wait: float = 1.0) -> None:
        """Send CMD_RESET and give the NCP time to come back up."""
        self.send(spinel.HDR_DEFAULT, spinel.CMD_RESET)
        time.sleep(wait)

    def _prop_set_raw(self, prop_id: int, value_bytes: bytes) -> None:
        """Send CMD_PROP_VALUE_SET without waiting for the echo."""
        payload = spinel.encode_i(prop_id) + value_bytes
        self.send(spinel.HDR_DEFAULT, spinel.CMD_PROP_VALUE_SET, payload)

    def _prop_set_raw_wait(self, prop_id: int, value_bytes: bytes,
                           timeout: float = _DEFAULT_TIMEOUT) -> bool:
        """Send CMD_PROP_VALUE_SET with arbitrary value bytes and wait for the IS echo."""
        self._prop_set_raw(prop_id, value_bytes)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ms  = max(1, int((deadline - time.monotonic()) * 1000))
            pkt = self.recv(timeout_ms=ms)
            if pkt and pkt[0] == spinel.HDR_DEFAULT and pkt[2] == prop_id:
                return True
        return False

    def prop_set(self, prop_id: int, value: int, timeout: float = _DEFAULT_TIMEOUT) -> bool:
        """
        Set a uint8 property and wait for the NCP's RSP_PROP_VALUE_IS echo.
        Returns True on success, False on timeout.
        """
        self._prop_set_raw(prop_id, bytes([value]))

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ms = max(1, int((deadline - time.monotonic()) * 1000))
            pkt = self.recv(timeout_ms=ms)
            if pkt and pkt[0] == spinel.HDR_DEFAULT and pkt[2] == prop_id:
                return True
        return False

    def scan(
        self,
        channels: list[int] | range = range(11, 27),
        period_ms: int = 300,
        timeout: float | None = None,
    ) -> list[dict]:
        """
        Active scan exactly matching the openthread_scan.log protocol:

          1. SET PROP_MAC_15_4_PANID (0x36) = 0xFFFF  — broadcast PAN, wait for echo
          2. For each channel:
               a. SET PROP_STREAM_RAW  — beacon request frame with channel in metadata
               b. Collect async PROP_STREAM_RAW IS frames (beacons) until PROP_LAST_STATUS
                  (LAST_STATUS = NCP's TX-done + receive-window-closed signal)
               c. period_ms is the max dwell per channel if LAST_STATUS is delayed

        PROP_STREAM_RAW TX payload (RadioSpinel::Transmit / openthread_scan.log):
          d(DATA_WLEN): uint16-LE len + frame(10B with 2-byte FCS placeholder)
          channel  maxCsmaBackoffs(4)  maxFrameRetries(15)  csmaCaEnabled(1)
          isHeaderUpdated(0)  isARetx(0)  isSecurityProcessed(0)
          txDelay(uint32)  txDelayBaseTime(uint32)  rxChannelAfterTxDone  txPower(int8)

        No explicit PHY_CHAN, RAW_STREAM_ENABLED, or FILTER_MODE — not in the log.
        """
        channels = list(channels)
        if timeout is not None:
            period_ms = min(period_ms, max(1, int(timeout * 1000 / len(channels))))
        results: list[dict] = []
        seen:    set[tuple] = set()
        seq = 0x00  # NCP overwrites seq# (isHeaderUpdated=0); use 0 as placeholder

        self.prop_set(spinel.PROP_PHY_ENABLED, 1)
        # SET PANID = 0xFFFF — exactly as openthread_scan.log line 2-5
        # prop=0x36 = PROP_MAC_15_4_PANID  (NOT 0x34 which is PROP_MAC_15_4_LADDR!)
        self._prop_set_raw_wait(spinel.PROP_MAC_15_4_PANID, struct.pack('<H', 0xFFFF))

        try:
            for channel in channels:
                req    = bytearray(spinel.BEACON_REQUEST)  # 10 bytes, FCS placeholder=0x0000
                req[2] = seq
                seq    = (seq + 1) & 0xFF

                # PROP_STREAM_RAW TX — values from openthread_scan.log decoded:
                #   frame length (uint16 LE) = 10
                #   frame bytes (10B): FC seq DestPAN DestAddr Cmd FCS_placeholder
                #   channel (uint8)
                #   maxCsmaBackoffs=4  maxFrameRetries=15  csmaCaEnabled=1
                #   isHeaderUpdated=0  isARetx=0  isSecurityProcessed=0
                #   txDelay (uint32 LE)=0  txDelayBaseTime (uint32 LE)=0
                #   rxChannelAfterTxDone=channel  txPower (int8)=0
                tx = (
                    struct.pack('<H', len(req)) + bytes(req)
                    + bytes([channel, 4, 15, 1, 0, 0, 0])
                    + struct.pack('<II', 0, 0)
                    + bytes([channel])
                    + struct.pack('<b', 0)
                )
                self._prop_set_raw(spinel.PROP_STREAM_RAW, tx)

                # Collect beacons until LAST_STATUS (TX done = end of receive window).
                # LAST_STATUS is the NCP's signal that the channel scan is complete.
                # period_ms is the hard deadline if LAST_STATUS is slow or missing.
                deadline = time.monotonic() + period_ms / 1000
                while time.monotonic() < deadline:
                    ms  = max(1, int((deadline - time.monotonic()) * 1000))
                    pkt = self.recv(timeout_ms=ms)
                    if pkt is None:
                        continue
                    _, _, prop_id, value = pkt
                    if prop_id == spinel.PROP_LAST_STATUS:
                        break  # TX done — NCP finished the channel receive window
                    if prop_id != spinel.PROP_STREAM_RAW:
                        continue
                    frame, meta = spinel.parse_stream_raw(value)
                    rssi        = meta[0]    if meta else 0
                    lqi         = meta[3][1] if meta else 0
                    if self._debug:
                        fc = int.from_bytes(frame[:2], 'little') if len(frame) >= 2 else 0
                        print(f"[dwell ch={channel}] frame ({len(frame)}B) "
                              f"FC=0x{fc:04x} rssi={rssi} lqi={lqi}: {frame.hex()}",
                              file=sys.stderr)
                    beacon = spinel.parse_beacon_frame(frame, channel, rssi, lqi)
                    if self._debug and beacon is None:
                        print(f"[dwell ch={channel}] not a Thread beacon", file=sys.stderr)
                    if beacon:
                        key = (channel, beacon['pan_id'], beacon['ext_addr'])
                        if key not in seen:
                            seen.add(key)
                            results.append(beacon)
        finally:
            self.prop_set(spinel.PROP_PHY_ENABLED, 0)

        return results

    def _drain_rx(self) -> None:
        """Non-blocking drain of all buffered RX frames."""
        while self.recv(timeout_ms=0) is not None:
            pass
