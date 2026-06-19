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

# ── Responses / async notifications (NCP → host) ─────────────────────────────

RSP_PROP_VALUE_IS       = 6  # GET reply and async property updates
CMD_PROP_VALUE_INSERTED = 7  # async: item added to array property (e.g. scan beacons)

# ── Properties ────────────────────────────────────────────────────────────────

PROP_LAST_STATUS             = 0x00

PROP_PHY_ENABLED             = 0x20
PROP_PHY_CHAN                = 0x21

PROP_MAC_15_4_LADDR          = 0x34  # 8 bytes — EUI-64 extended address
PROP_MAC_15_4_SADDR          = 0x35  # uint16 LE — short address
PROP_MAC_15_4_PANID          = 0x36  # uint16 LE — PAN ID filter (was wrongly 0x34!)

PROP_MAC_SCAN_STATE          = 0x30
PROP_MAC_SCAN_MASK           = 0x31
PROP_MAC_SCAN_PERIOD         = 0x32
PROP_MAC_SCAN_BEACON         = 0x33

PROP_MAC_RAW_STREAM_ENABLED  = 0x37
PROP_MAC_FILTER_MODE         = 0x38

PROP_STREAM_RAW              = 0x71

# PROP_MAC_FILTER_MODE values
MAC_FILTER_MODE_NORMAL       = 0
MAC_FILTER_MODE_PROMISCUOUS  = 1  # all frames with valid FCS, bypass addr/PAN filter
MAC_FILTER_MODE_MONITOR      = 2  # all frames regardless of FCS

# PROP_MAC_SCAN_STATE values
SCAN_STATE_IDLE     = 0
SCAN_STATE_BEACON   = 1
SCAN_STATE_ENERGY   = 2
SCAN_STATE_DISCOVER = 3

# PROP_MAC_SCAN_BEACON flag bits (the C flags byte in the NET struct)
_BEACON_FLAG_VERSION_SHIFT = 4
_BEACON_FLAG_NATIVE        = 1 << 3
_BEACON_FLAG_JOINABLE      = 1 << 0

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
    prop_id and value are extracted for any prop-value command
    (RSP_PROP_VALUE_IS, CMD_PROP_VALUE_INSERTED, …); otherwise prop_id is 0.
    """
    tid = pkt[0]
    cmd, n = decode_i(pkt[1:])
    payload = pkt[1 + n:]
    if cmd in (RSP_PROP_VALUE_IS, CMD_PROP_VALUE_INSERTED) and payload:
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

# ── Raw 802.15.4 scan (RCP path) ─────────────────────────────────────────────

# Beacon Request: MAC command (type 3), short broadcast dest, no src (FC = 0x0803 LE)
# 10 bytes: 8 bytes MAC + 2-byte FCS placeholder (NCP fills actual FCS on TX)
BEACON_REQUEST = bytes([0x03, 0x08, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x00, 0x00])
#                       FC lo FC hi Seq  DestPAN---   DestAddr-  CmdID FCS--

_FC_FRAME_TYPE_MASK  = 0x0007
_FC_FRAME_TYPE_BEACON = 0x0000
_FC_PAN_COMPRESSION  = 0x0040
_FC_DST_ADDR_MASK    = 0x0C00
_FC_DST_ADDR_NONE    = 0x0000
_FC_DST_ADDR_SHORT   = 0x0800
_FC_DST_ADDR_EXT     = 0x0C00
_FC_SRC_ADDR_MASK    = 0xC000
_FC_SRC_ADDR_NONE    = 0x0000
_FC_SRC_ADDR_SHORT   = 0x8000
_FC_SRC_ADDR_EXT     = 0xC000


def parse_beacon_frame(frame: bytes, channel: int, rssi: int = 0, lqi: int = 0) -> dict | None:
    """
    Parse a raw 802.15.4 Beacon frame received via PROP_STREAM_RAW.

    Thread routers respond to Beacon Requests with extended-source beacons
    (OpenThread: Mac::PrepareBeacon uses SetExtended(GetExtAddress())):

      FC(2) Seq(1) SrcPAN(2) SrcExtAddr(8)              13 bytes MAC header
      SuperframeSpec(2) GTSSpec(1+) PendingAddr(1+)       4 bytes 802.15.4 Beacon
      ProtocolId(1=0x03) Flags(1) NetworkName(16) XPanId(8)  Thread payload
      FCS(2)  — included in length by the NCP, stripped here

    Flags byte layout (from OpenThread mac_frame.hpp BeaconPayload):
      bits[7:4] = version  |  bit[3] = native  |  bit[0] = joinable

    Returns None if the frame is not a valid Thread Beacon.
    """
    if len(frame) < 15:
        return None

    fc = struct.unpack_from('<H', frame, 0)[0]
    if (fc & _FC_FRAME_TYPE_MASK) != _FC_FRAME_TYPE_BEACON:
        return None

    pan_compression = bool(fc & _FC_PAN_COMPRESSION)
    dst_mode        = fc & _FC_DST_ADDR_MASK
    src_mode        = fc & _FC_SRC_ADDR_MASK

    offset = 3  # past FC(2) + Seq(1)

    # Destination fields (absent in Thread beacons)
    dst_pan: int | None = None
    if dst_mode != _FC_DST_ADDR_NONE:
        if len(frame) < offset + 2:
            return None
        dst_pan = struct.unpack_from('<H', frame, offset)[0]; offset += 2
    if   dst_mode == _FC_DST_ADDR_SHORT: offset += 2
    elif dst_mode == _FC_DST_ADDR_EXT:   offset += 8

    # Source PAN ID — omitted only when pan_compression=1 AND a dest addr is also present
    src_pan: int | None = None
    if src_mode != _FC_SRC_ADDR_NONE:
        if pan_compression and dst_mode != _FC_DST_ADDR_NONE:
            src_pan = dst_pan  # same PAN, omitted from frame
        else:
            if len(frame) < offset + 2:
                return None
            src_pan = struct.unpack_from('<H', frame, offset)[0]; offset += 2

    # Source address
    src_ext:   bytes | None = None
    src_short: int | None   = None
    if src_mode == _FC_SRC_ADDR_EXT:
        if len(frame) < offset + 8:
            return None
        src_ext = frame[offset:offset + 8]; offset += 8
    elif src_mode == _FC_SRC_ADDR_SHORT:
        if len(frame) < offset + 2:
            return None
        src_short = struct.unpack_from('<H', frame, offset)[0]; offset += 2

    # 802.15.4 Beacon header: SuperframeSpec(2) + GTSSpec(1+) + PendingAddr(1+)
    if len(frame) < offset + 4:
        return None
    offset += 2  # SuperframeSpec
    gts_spec  = frame[offset]; offset += 1
    gts_count = gts_spec & 0x07
    if gts_count:
        offset += 1 + gts_count * 3  # GTS direction byte + GTS list
    if len(frame) < offset + 1:
        return None
    pending = frame[offset]; offset += 1
    offset += (pending & 0x07) * 2 + ((pending >> 4) & 0x07) * 8

    # Thread BeaconPayload — exclude the 2 FCS bytes the NCP appends
    payload = frame[offset:len(frame) - 2]
    if len(payload) < 2 or payload[0] != 0x03:  # Thread Protocol ID
        return None

    flags    = payload[1]
    version  = (flags >> 4) & 0x0F
    native   = bool(flags & 0x08)  # kNativeFlag  = 1 << 3
    joinable = bool(flags & 0x01)  # kJoiningFlag = 1 << 0

    pan_id = src_pan if src_pan is not None else (dst_pan or 0)

    return {
        'channel':       channel,
        'rssi':          rssi,
        'ext_addr':      src_ext.hex() if src_ext else '',
        'short_addr':    f'0x{src_short:04x}' if src_short is not None else '0xffff',
        'pan_id':        f'0x{pan_id:04x}',
        'lqi':           lqi,
        'network_name':  payload[2:18].rstrip(b'\x00').decode('utf-8', errors='replace') if len(payload) >= 18 else '',
        'ext_pan_id':    payload[18:26].hex() if len(payload) >= 26 else '',
        'version':       version,
        'joinable':      joinable,
        'native':        native,
        'steering_data': None,
    }


# ── PROP_MAC_SCAN_BEACON (NCP/MTD/FTD path — not used on RCP) ────────────────

def parse_scan_beacon(value: bytes) -> dict | None:
    """
    Parse a PROP_MAC_SCAN_BEACON value into a dict.

    Wire format (OpenThread): Cct(ESSc)t(iCUdd)
      C  channel
      c  rssi
      t(ESSc)  MAC struct:
        E  ext_addr (8 bytes, big-endian EUI-64)
        S  short_addr (uint16 LE)
        S  pan_id (uint16 LE)
        c  lqi (uint8)
      t(iCUdd)  NET struct (Thread):
        i  protocol type (3 = Thread)
        C  flags: bits[7:4]=version, bit[3]=native, bit[0]=joinable
        U  network_name (null-terminated UTF-8)
        d  ext_pan_id (uint16 LE length + bytes)
        d  steering_data (uint16 LE length + bytes)

    Returns None if the payload is too short to contain the MAC fields.
    """
    if len(value) < 4:
        return None

    offset = 0
    channel = value[offset];                                    offset += 1
    rssi    = struct.unpack_from('<b', value, offset)[0];       offset += 1

    # MAC struct
    if offset + 2 > len(value):
        return None
    mac_len = struct.unpack_from('<H', value, offset)[0];       offset += 2
    mac_end = offset + mac_len
    if mac_end > len(value) or mac_len < 13:
        return None

    ext_addr   = value[offset:offset + 8]
    short_addr = struct.unpack_from('<H', value, offset + 8)[0]
    pan_id     = struct.unpack_from('<H', value, offset + 10)[0]
    lqi        = value[offset + 12]
    offset     = mac_end

    result: dict = {
        'channel':       channel,
        'rssi':          rssi,
        'ext_addr':      ext_addr.hex(),
        'short_addr':    f'0x{short_addr:04x}',
        'pan_id':        f'0x{pan_id:04x}',
        'lqi':           lqi,
        'network_name':  None,
        'ext_pan_id':    None,
        'version':       None,
        'joinable':      False,
        'native':        False,
        'steering_data': None,
    }

    # NET struct
    if offset + 2 > len(value):
        return result
    net_len = struct.unpack_from('<H', value, offset)[0];       offset += 2
    net_end = offset + net_len
    if net_end > len(value):
        return result
    net = value[offset:net_end]

    proto, n = decode_i(net)
    if proto != 3:  # SPINEL_PROTOCOL_TYPE_THREAD
        return result
    pos = n

    # C: flags
    if pos >= len(net):
        return result
    flags = net[pos];                                           pos += 1
    result['version']  = (flags >> _BEACON_FLAG_VERSION_SHIFT) & 0xF
    result['joinable'] = bool(flags & _BEACON_FLAG_JOINABLE)
    result['native']   = bool(flags & _BEACON_FLAG_NATIVE)

    # U: null-terminated UTF-8 network name
    null = net.find(b'\x00', pos)
    if null == -1:
        result['network_name'] = net[pos:].decode('utf-8', errors='replace')
        return result
    result['network_name'] = net[pos:null].decode('utf-8', errors='replace')
    pos = null + 1

    # d: extended PAN ID
    if pos + 2 > len(net):
        return result
    xpanid_len = struct.unpack_from('<H', net, pos)[0];         pos += 2
    if pos + xpanid_len <= len(net):
        result['ext_pan_id'] = net[pos:pos + xpanid_len].hex()
        pos += xpanid_len

    # d: steering data
    if pos + 2 <= len(net):
        steering_len = struct.unpack_from('<H', net, pos)[0];   pos += 2
        if pos + steering_len <= len(net):
            result['steering_data'] = net[pos:pos + steering_len].hex()

    return result
