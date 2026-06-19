"""
beacon.py — Zigbee 802.15.4 beacon frame parsing.

ZigBee PRO specification (docs-05-3474-21-0csg), Chapter 2 / Figure 3.51 /
Table 3.61.  See also IEEE 802.15.4 for the MAC beacon frame format.
"""

from ..hardware.ieee802154 import parse_beacon_mac_header

_ZIGBEE_PROTOCOL_ID = 0x00   # §4: MUST be 0x00; any other value → discard

# nwkStackProfile values (byte 1, low nibble)
STACK_PROFILE_ZIGBEE     = 0x01   # Zigbee 2006/2007/2012
STACK_PROFILE_ZIGBEE_PRO = 0x02   # ZigBee Pro 2007+

_STACK_PROFILE_NAMES = {
    STACK_PROFILE_ZIGBEE:     'Zigbee',
    STACK_PROFILE_ZIGBEE_PRO: 'ZigBee Pro',
}

_NWK_PAYLOAD_MIN = 15   # bytes: exactly as specified in §4

# Superframe Specification bit masks (from the MAC header)
_SF_BEACON_ORDER     = 0x000F   # bits 3:0
_SF_SUPERFRAME_ORDER = 0x00F0   # bits 7:4
_SF_PAN_COORDINATOR  = 0x4000   # bit 14
_SF_ASSOC_PERMITTED  = 0x8000   # bit 15 = permit_joining


def parse_frame(frame: bytes, channel: int, rssi: int = 0, lqi: int = 0) -> dict | None:
    """
    Parse a raw 802.15.4 Beacon frame for Zigbee network info.

    NWK beacon payload layout (ZigBee PRO spec §4, 15 bytes):

      Byte 0:     Protocol ID = 0x00
      Byte 1:     [nwkcProtocolVersion(4) high | StackProfile(4) low]
      Byte 2:     [EndDevCap(1) b7 | DeviceDepth(4) b6:3 | RouterCap(1) b2 | Reserved(2) b1:0]
      Bytes 3-10: nwkExtendedPANId, little-endian on air (reverse to get canonical BE)
      Bytes 11-13: TxOffset, little-endian (0xFFFFFF in non-beacon-enabled networks)
      Byte 14:    nwkUpdateId

    permit_joining (Association Permitted) comes from Superframe Specification
    bit 15 in the MAC beacon header, not from the NWK payload.

    Returns None if the frame is not a valid Zigbee Beacon.
    """
    result = parse_beacon_mac_header(frame)
    if result is None:
        return None
    header, offset = result

    # Zigbee NWK payload — strip 2-byte FCS appended by the NCP
    payload = frame[offset:len(frame) - 2]

    # §5 step 1: discard zero-length payloads; step 2: check Protocol ID
    if len(payload) < _NWK_PAYLOAD_MIN or payload[0] != _ZIGBEE_PROTOCOL_ID:
        return None

    # Byte 1: high nibble = nwkcProtocolVersion, low nibble = StackProfile  (§4 Table 3.61)
    stack_byte    = payload[1]
    stack_profile = stack_byte & 0x0F
    nwk_version   = (stack_byte >> 4) & 0x0F

    # Byte 2 capacity flags (§4):
    #   b1:0  Reserved
    #   b2    Router Capacity
    #   b6:3  Device Depth
    #   b7    End Device Capacity
    cap_byte            = payload[2]
    router_capacity     = bool(cap_byte & 0x04)       # bit 2
    device_depth        = (cap_byte >> 3) & 0x0F      # bits 6:3
    end_device_capacity = bool(cap_byte & 0x80)       # bit 7

    # Bytes 3-10: nwkExtendedPANId stored LE on air (§4.1 example)
    # Reverse to canonical big-endian representation used for display / dedup.
    ext_pan_id = payload[3:11][::-1]                           # LE wire → BE canonical
    tx_offset  = int.from_bytes(payload[11:14], 'little')      # 3 bytes LE
    update_id  = payload[14]

    # Superframe Specification (parsed from MAC header by parse_beacon_mac_header)
    sf = header['superframe_spec']
    beacon_order     = sf & _SF_BEACON_ORDER
    superframe_order = (sf & _SF_SUPERFRAME_ORDER) >> 4
    pan_coordinator  = bool(sf & _SF_PAN_COORDINATOR)
    permit_joining   = bool(sf & _SF_ASSOC_PERMITTED)   # §5 Table: PermitJoining = sf bit 15

    src_ext   = header['src_ext']
    src_short = header['src_short']
    pan_id    = header['pan_id']

    return {
        'channel':              channel,
        'rssi':                 rssi,
        'lqi':                  lqi,
        'pan_id':               f'0x{pan_id:04x}',
        'ext_pan_id':           ext_pan_id.hex(),          # canonical BE hex string
        'ext_addr':             src_ext.hex() if src_ext else '',
        'short_addr':           f'0x{src_short:04x}' if src_short is not None else '0xffff',
        'stack_profile':        stack_profile,
        'stack_profile_name':   _STACK_PROFILE_NAMES.get(stack_profile, f'0x{stack_profile:x}'),
        'nwk_version':          nwk_version,
        'router_capacity':      router_capacity,
        'device_depth':         device_depth,
        'end_device_capacity':  end_device_capacity,
        'permit_joining':       permit_joining,
        'beacon_order':         beacon_order,
        'superframe_order':     superframe_order,
        'pan_coordinator':      pan_coordinator,
        'tx_offset':            tx_offset,
        'update_id':            update_id,
    }
