"""
spinel.py — Spinel protocol constants and frame encode/decode.

No I/O here — just the wire format.
"""

import struct

# ── Headers / TIDs ────────────────────────────────────────────────────────────

HDR_ASYNC   = 0x80  # async NCP-initiated notifications
HDR_DEFAULT = 0x81  # host-initiated transactions (TID 1)

# ── Commands (host → NCP) ─────────────────────────────────────────────────────

CMD_RESET           = 1
CMD_PROP_VALUE_GET  = 2
CMD_PROP_VALUE_SET  = 3

# ── Responses (NCP → host) ────────────────────────────────────────────────────

RSP_PROP_VALUE_IS = 6

# ── Properties ────────────────────────────────────────────────────────────────

PROP_LAST_STATUS             = 0x00

PROP_PHY_ENABLED             = 0x20
PROP_PHY_CHAN                = 0x21

PROP_MAC_RAW_STREAM_ENABLED  = 0x37
PROP_MAC_FILTER_MODE         = 0x38

PROP_STREAM_RAW              = 0x71

# PROP_MAC_FILTER_MODE values
MAC_FILTER_MODE_MONITOR      = 2

# ── EXI (packed unsigned int) ─────────────────────────────────────────────────

def encode_i(v: int) -> bytes:
    """Encode an unsigned integer in Spinel EXI format."""
    if v == 0:
        return b'\x00'
    out = b''
    while v:
        b = v & 0x7F
        v >>= 7
        if v:
            b |= 0x80
        out += bytes([b])
    return out


def decode_i(data: bytes) -> tuple[int, int]:
    """
    Decode an EXI integer from the start of *data*.
    Returns (value, bytes_consumed).
    """
    value, mul, n = 0, 1, 0
    for b in data:
        n += 1
        value += (b & 0x7F) * mul
        if b < 0x80:
            break
        mul *= 0x80
    return value, n

# ── Frame build / parse ───────────────────────────────────────────────────────

def build(tid: int, cmd: int, payload: bytes = b'') -> bytes:
    """Encode a Spinel frame: header byte · EXI command · payload."""
    return bytes([tid]) + encode_i(cmd) + payload


def parse(pkt: bytes) -> tuple[int, int, int, bytes]:
    """
    Decode a Spinel frame.
    Returns (tid, cmd, prop_id, value).
    prop_id and value are only meaningful when cmd == RSP_PROP_VALUE_IS;
    otherwise prop_id is 0 and value is the raw payload remainder.
    """
    tid = pkt[0]
    cmd, n = decode_i(pkt[1:])
    payload = pkt[1 + n:]
    if cmd == RSP_PROP_VALUE_IS and payload:
        prop_id, m = decode_i(payload)
        return tid, cmd, prop_id, payload[m:]
    return tid, cmd, 0, payload

# ── PROP_STREAM_RAW metadata ──────────────────────────────────────────────────

def parse_stream_raw(value: bytes) -> tuple[bytes, tuple | None]:
    """
    Split a PROP_STREAM_RAW value into (frame_bytes, metadata).

    Metadata format (19 bytes):
      rssi (int8) · noise (int8) · flags (uint16)
      · t(channel uint8 · lqi uint8 · timestamp_us uint64)
      · t(recv_error EXI)

    Returns metadata as (rssi, noise, flags, (channel, lqi, ts_us), (recv_err,))
    or None if the metadata block is absent / malformed.
    """
    length = struct.unpack_from('<H', value, 0)[0]
    frame = value[2:2 + length]
    meta_bytes = value[2 + length:]

    if len(meta_bytes) < 19:
        return frame, None

    rssi    = struct.unpack_from('<b', meta_bytes, 0)[0]
    noise   = struct.unpack_from('<b', meta_bytes, 1)[0]
    flags   = struct.unpack_from('<H', meta_bytes, 2)[0]
    channel = meta_bytes[6]
    lqi     = meta_bytes[7]
    ts_us   = struct.unpack_from('<Q', meta_bytes, 8)[0]
    recv_err = meta_bytes[18] & 0x7F
    return frame, (rssi, noise, flags, (channel, lqi, ts_us), (recv_err,))
