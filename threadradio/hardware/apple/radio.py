"""
radio.py — Apple TSI/Skywalk RCP radio backend.
"""

from ..radio import Radio
from .skywalk import SkywalkChannel, open_channel, close_channel, read_slot, write_slot


class AppleRadio(Radio):
    """
    Radio implementation over Apple's TSI/Skywalk nexus channel.

    Usage::

        with AppleRadio() as radio:
            radio.reset()
            networks = thread.scanner.scan(radio)
    """

    def __init__(self, protocol: str = "tsi", debug: bool = False) -> None:
        super().__init__(debug=debug)
        self._ch: SkywalkChannel = open_channel(protocol)

    def _write(self, data: bytes) -> None:
        write_slot(self._ch, data)

    def _read(self, timeout_ms: int) -> bytes | None:
        return read_slot(self._ch, timeout_ms=timeout_ms)

    def close(self) -> None:
        close_channel(self._ch)
