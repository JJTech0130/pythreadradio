"""
ieee802154.py — generic IEEE 802.15.4 frame utilities.
"""

import struct

# ── Frame Control field bit masks ─────────────────────────────────────────────

FC_FRAME_TYPE_MASK   = 0x0007
FC_FRAME_TYPE_BEACON = 0x0000
FC_FRAME_TYPE_DATA   = 0x0001
FC_FRAME_TYPE_ACK    = 0x0002
FC_FRAME_TYPE_CMD    = 0x0003

FC_PAN_COMPRESSION   = 0x0040

FC_DST_ADDR_MASK     = 0x0C00
FC_DST_ADDR_NONE     = 0x0000
FC_DST_ADDR_SHORT    = 0x0800
FC_DST_ADDR_EXT      = 0x0C00

FC_SRC_ADDR_MASK     = 0xC000
FC_SRC_ADDR_NONE     = 0x0000
FC_SRC_ADDR_SHORT    = 0x8000
FC_SRC_ADDR_EXT      = 0xC000


def parse_beacon_mac_header(frame: bytes) -> tuple[dict, int] | None:
    """
    Parse the 802.15.4 MAC header and standard beacon fields from a raw frame.

    Returns (header, payload_offset) where payload_offset points to the first
    byte of the protocol-specific beacon payload (after SuperframeSpec, GTS,
    and PendingAddr fields).  Returns None if the frame is not a beacon or is
    too short to contain a valid header.

    Header dict keys:
      seq (int)               MAC sequence number
      pan_id (int)            Source PAN ID (0 if unknown)
      src_ext (bytes|None)    8-byte extended source address, if present
      src_short (int|None)    Short source address, if present
      dst_pan (int|None)      Destination PAN ID, if present
      superframe_spec (int)   Raw 16-bit Superframe Specification field:
                                bits  3:0  = Beacon Order (0xF = non-beacon-enabled)
                                bits  7:4  = Superframe Order
                                bit  14    = PAN Coordinator
                                bit  15    = Association Permitted (permit joining)
    """
    if len(frame) < 5:
        return None

    fc = struct.unpack_from('<H', frame, 0)[0]
    if (fc & FC_FRAME_TYPE_MASK) != FC_FRAME_TYPE_BEACON:
        return None

    seq             = frame[2]
    pan_compression = bool(fc & FC_PAN_COMPRESSION)
    dst_mode        = fc & FC_DST_ADDR_MASK
    src_mode        = fc & FC_SRC_ADDR_MASK

    offset = 3  # past FC(2) + Seq(1)

    dst_pan: int | None = None
    if dst_mode != FC_DST_ADDR_NONE:
        if len(frame) < offset + 2:
            return None
        dst_pan = struct.unpack_from('<H', frame, offset)[0]; offset += 2
    if   dst_mode == FC_DST_ADDR_SHORT: offset += 2
    elif dst_mode == FC_DST_ADDR_EXT:   offset += 8

    src_pan: int | None = None
    if src_mode != FC_SRC_ADDR_NONE:
        if pan_compression and dst_mode != FC_DST_ADDR_NONE:
            src_pan = dst_pan
        else:
            if len(frame) < offset + 2:
                return None
            src_pan = struct.unpack_from('<H', frame, offset)[0]; offset += 2

    src_ext:   bytes | None = None
    src_short: int   | None = None
    if src_mode == FC_SRC_ADDR_EXT:
        if len(frame) < offset + 8:
            return None
        src_ext = frame[offset:offset + 8]; offset += 8
    elif src_mode == FC_SRC_ADDR_SHORT:
        if len(frame) < offset + 2:
            return None
        src_short = struct.unpack_from('<H', frame, offset)[0]; offset += 2

    # 802.15.4 Beacon fields: SuperframeSpec(2) · GTSSpec(var) · PendingAddr(var)
    if len(frame) < offset + 4:
        return None
    superframe_spec = struct.unpack_from('<H', frame, offset)[0]
    offset += 2  # SuperframeSpec
    gts_spec  = frame[offset]; offset += 1
    gts_count = gts_spec & 0x07
    if gts_count:
        offset += 1 + gts_count * 3   # GTS Directions(1) + GTS List
    if len(frame) < offset + 1:
        return None
    pending = frame[offset]; offset += 1
    offset += (pending & 0x07) * 2 + ((pending >> 4) & 0x07) * 8

    pan_id = src_pan if src_pan is not None else (dst_pan or 0)

    return {
        'seq':             seq,
        'pan_id':          pan_id,
        'src_ext':         src_ext,
        'src_short':       src_short,
        'dst_pan':         dst_pan,
        'superframe_spec': superframe_spec,
    }, offset
