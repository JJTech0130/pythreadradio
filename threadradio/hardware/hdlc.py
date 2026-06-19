"""
hdlc.py — HDLC encode / decode (RFC 1662 FCS-16).
"""

_HDLC_FLAG = 0x7E
_HDLC_ESC  = 0x7D
_FCS_INIT  = 0xFFFF
_FCS_GOOD  = 0xF0B8


def _make_fcstab():
    poly, tab = 0x8408, []
    for byte in range(256):
        fcs = byte
        for _ in range(8):
            fcs = (fcs >> 1) ^ poly if (fcs & 1) else fcs >> 1
        tab.append(fcs & 0xFFFF)
    return tuple(tab)


_FCSTAB = _make_fcstab()


def _fcs(data) -> int:
    fcs = _FCS_INIT
    for b in data:
        fcs = (fcs >> 8) ^ _FCSTAB[(fcs ^ b) & 0xFF]
    return fcs


def encode(payload: bytes) -> bytes:
    """Wrap *payload* in an HDLC frame (flag · escaped payload+FCS · flag)."""
    fcs = _fcs(payload) ^ 0xFFFF
    out = bytearray([_HDLC_FLAG])
    for b in list(payload) + [fcs & 0xFF, fcs >> 8]:
        if b in (_HDLC_FLAG, _HDLC_ESC):
            out.append(_HDLC_ESC)
            out.append(b ^ 0x20)
        else:
            out.append(b)
    out.append(_HDLC_FLAG)
    return bytes(out)


def decode(frame: bytes) -> bytes | None:
    """
    Decode a complete HDLC frame (including outer 0x7E delimiters).
    Returns the payload on success, or None if the FCS is bad.
    """
    # Strip leading/trailing flag bytes.
    i = 0
    while i < len(frame) and frame[i] == _HDLC_FLAG:
        i += 1
    j = len(frame) - 1
    while j >= i and frame[j] == _HDLC_FLAG:
        j -= 1

    result, k = [], i
    while k <= j:
        b = frame[k]
        if b == _HDLC_ESC:
            k += 1
            if k > j:
                return None
            b = frame[k] ^ 0x20
        result.append(b)
        k += 1

    if _fcs(result) != _FCS_GOOD:
        return None
    return bytes(result[:-2])  # strip trailing FCS16
