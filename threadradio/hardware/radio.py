"""
radio.py — Generic Spinel 802.15.4 RCP radio interface.

Subclasses implement _write(data) and _read(timeout_ms) for a specific
transport backend (Apple Skywalk, USB serial, PTY, etc.).
All Spinel frame operations are provided here.
"""

import sys
import time

from . import hdlc, spinel

_DEFAULT_TIMEOUT = 2.0

_CMD_NAMES = {
    1: "RESET", 2: "GET",  3: "SET",
    6: "IS",    7: "INSERTED",
}
_PROP_NAMES = {
    0x00: "LAST_STATUS",  0x20: "PHY_ENABLED",  0x21: "PHY_CHAN",
    0x34: "15_4_LADDR",   0x35: "15_4_SADDR",   0x36: "15_4_PANID",
    0x30: "SCAN_STATE",   0x31: "SCAN_MASK",     0x32: "SCAN_PERIOD",
    0x33: "SCAN_BEACON",  0x37: "RAW_STREAM_EN", 0x38: "FILTER_MODE",
    0x71: "STREAM_RAW",
}


def _dbg(direction: str, tid: int, cmd: int, prop_id: int, value: bytes) -> None:
    cmd_s  = _CMD_NAMES.get(cmd,      f"cmd={cmd}")
    prop_s = _PROP_NAMES.get(prop_id, f"prop=0x{prop_id:02x}")
    val_s  = value.hex() if len(value) <= 64 else value[:64].hex() + f"…+{len(value)-64}"
    ts     = time.monotonic()
    print(f"[{ts:.3f}] [spinel {direction}] tid=0x{tid:02x} {cmd_s} {prop_s} {val_s}",
          file=sys.stderr)


class Radio:
    """
    Generic Spinel 802.15.4 RCP radio interface.

    Subclasses must implement _write(data) and _read(timeout_ms).
    """

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug

    # ── abstract transport layer ──────────────────────────────────────────────

    def _write(self, data: bytes) -> None:
        raise NotImplementedError

    def _read(self, timeout_ms: int) -> bytes | None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> "Radio":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── Spinel send / recv ────────────────────────────────────────────────────

    def send(self, tid: int, cmd: int, payload: bytes = b'') -> None:
        if self.debug:
            prop_id, n = spinel.decode_i(payload) if payload else (0, 0)
            _dbg("TX", tid, cmd, prop_id, payload[n:])
        frame = hdlc.encode(spinel.build(tid, cmd, payload))
        self._write(frame)

    def recv(self, timeout_ms: int = 1000) -> tuple[int, int, int, bytes] | None:
        raw = self._read(timeout_ms)
        if raw is None:
            return None
        pkt = hdlc.decode(raw)
        if not pkt or len(pkt) < 2:
            return None
        result = spinel.parse(pkt)
        if self.debug and result:
            _dbg("RX", *result)
        return result

    # ── higher-level Spinel helpers ───────────────────────────────────────────

    def reset(self, wait: float = 1.0) -> None:
        self.send(spinel.HDR_DEFAULT, spinel.CMD_RESET)
        time.sleep(wait)

    def _prop_set_raw(self, prop_id: int, value_bytes: bytes) -> None:
        payload = spinel.encode_i(prop_id) + value_bytes
        self.send(spinel.HDR_DEFAULT, spinel.CMD_PROP_VALUE_SET, payload)

    def _prop_set_raw_wait(self, prop_id: int, value_bytes: bytes,
                           timeout: float = _DEFAULT_TIMEOUT) -> bool:
        self._prop_set_raw(prop_id, value_bytes)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ms  = max(1, int((deadline - time.monotonic()) * 1000))
            pkt = self.recv(timeout_ms=ms)
            if pkt and pkt[0] == spinel.HDR_DEFAULT and pkt[2] == prop_id:
                return True
        return False

    def prop_set(self, prop_id: int, value: int,
                 timeout: float = _DEFAULT_TIMEOUT) -> bool:
        self._prop_set_raw(prop_id, bytes([value]))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ms  = max(1, int((deadline - time.monotonic()) * 1000))
            pkt = self.recv(timeout_ms=ms)
            if pkt and pkt[0] == spinel.HDR_DEFAULT and pkt[2] == prop_id:
                return True
        return False

    def _drain_rx(self) -> None:
        while self.recv(timeout_ms=0) is not None:
            pass
