"""
thread.py — Thread radio interface.

Glues Skywalk (raw slot I/O) + HDLC (framing) + Spinel (protocol) into a
single object that sends and receives Spinel packets over a TSI channel.
"""

import time

from . import hdlc
from . import spinel
from .skywalk import SkywalkChannel, open_channel, close_channel, read_slot, write_slot

_DEFAULT_TIMEOUT = 2.0   # seconds


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

    def __init__(self, protocol: str = "tsi") -> None:
        self._ch: SkywalkChannel = open_channel(protocol)

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
        return spinel.parse(pkt)

    # ── higher-level helpers ──────────────────────────────────────────────────

    def reset(self, wait: float = 1.0) -> None:
        """Send CMD_RESET and give the NCP time to come back up."""
        self.send(spinel.HDR_DEFAULT, spinel.CMD_RESET)
        time.sleep(wait)

    def prop_set(self, prop_id: int, value: int, timeout: float = _DEFAULT_TIMEOUT) -> bool:
        """
        Set a uint8 property and wait for the NCP's RSP_PROP_VALUE_IS echo.
        Returns True on success, False on timeout.
        """
        payload = spinel.encode_i(prop_id) + bytes([value])
        self.send(spinel.HDR_DEFAULT, spinel.CMD_PROP_VALUE_SET, payload)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ms = max(1, int((deadline - time.monotonic()) * 1000))
            pkt = self.recv(timeout_ms=ms)
            if pkt and pkt[0] == spinel.HDR_DEFAULT and pkt[2] == prop_id:
                return True
        return False
