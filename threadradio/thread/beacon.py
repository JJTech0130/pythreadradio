"""
beacon.py — Thread 802.15.4 beacon frame parsing.
"""

import struct

from ..hardware.ieee802154 import parse_beacon_mac_header
from ..hardware import spinel

_THREAD_PROTOCOL_ID = 0x03

_FLAG_VERSION_SHIFT = 4
_FLAG_NATIVE        = 1 << 3   # kNativeFlag
_FLAG_JOINABLE      = 1 << 0   # kJoiningFlag


def parse_frame(frame: bytes, channel: int, rssi: int = 0, lqi: int = 0) -> dict | None:
    """
    Parse a raw 802.15.4 Beacon frame for Thread network info.

    Thread routers respond to Beacon Requests with extended-source beacons.
    The Thread BeaconPayload (after the 802.15.4 Beacon header) starts with
    Protocol ID 0x03, followed by flags, NetworkName(16), and ExtPanId(8).

    Flags byte: bits[7:4]=version | bit[3]=native | bit[0]=joinable

    Returns None if not a valid Thread Beacon.
    """
    result = parse_beacon_mac_header(frame)
    if result is None:
        return None
    header, offset = result

    # Thread BeaconPayload — strip 2-byte FCS appended by the NCP
    payload = frame[offset:len(frame) - 2]
    if len(payload) < 2 or payload[0] != _THREAD_PROTOCOL_ID:
        return None

    flags    = payload[1]
    version  = (flags >> _FLAG_VERSION_SHIFT) & 0x0F
    native   = bool(flags & _FLAG_NATIVE)
    joinable = bool(flags & _FLAG_JOINABLE)

    src_ext   = header['src_ext']
    src_short = header['src_short']
    pan_id    = header['pan_id']

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


def parse_scan_beacon(value: bytes) -> dict | None:
    """
    Parse a PROP_MAC_SCAN_BEACON value (NCP/MTD/FTD path — not used on RCP).

    Wire format: Cct(ESSc)t(iCUdd)
      C  channel
      c  rssi
      t(ESSc)  ext_addr(8) short_addr(u16) pan_id(u16) lqi(u8)
      t(iCUdd) protocol_type flags network_name ext_pan_id steering_data
    """
    if len(value) < 4:
        return None

    offset  = 0
    channel = value[offset];                                    offset += 1
    rssi    = struct.unpack_from('<b', value, offset)[0];       offset += 1

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

    if offset + 2 > len(value):
        return result
    net_len = struct.unpack_from('<H', value, offset)[0];       offset += 2
    net_end = offset + net_len
    if net_end > len(value):
        return result
    net = value[offset:net_end]

    proto, n = spinel.decode_i(net)
    if proto != 3:
        return result
    pos = n

    if pos >= len(net):
        return result
    flags = net[pos];                                           pos += 1
    result['version']  = (flags >> _FLAG_VERSION_SHIFT) & 0xF
    result['joinable'] = bool(flags & _FLAG_JOINABLE)
    result['native']   = bool(flags & _FLAG_NATIVE)

    null = net.find(b'\x00', pos)
    if null == -1:
        result['network_name'] = net[pos:].decode('utf-8', errors='replace')
        return result
    result['network_name'] = net[pos:null].decode('utf-8', errors='replace')
    pos = null + 1

    if pos + 2 > len(net):
        return result
    xpanid_len = struct.unpack_from('<H', net, pos)[0];         pos += 2
    if pos + xpanid_len <= len(net):
        result['ext_pan_id'] = net[pos:pos + xpanid_len].hex()
        pos += xpanid_len

    if pos + 2 <= len(net):
        steering_len = struct.unpack_from('<H', net, pos)[0];   pos += 2
        if pos + steering_len <= len(net):
            result['steering_data'] = net[pos:pos + steering_len].hex()

    return result
