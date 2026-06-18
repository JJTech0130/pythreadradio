"""
sniffer.py — Thread 802.15.4 sniffer that outputs raw pcap.

Pipe to Wireshark:
    sudo python -m threadradio.sniffer | wireshark -k -i -

Save to file:
    sudo python -m threadradio.sniffer -c 15 -o trace.pcap
"""

import optparse
import struct
import sys
import time

from .thread import ThreadInterface
from . import spinel

# ── PCAP ──────────────────────────────────────────────────────────────────────

_DLT_WITHFCS = 195
_DLT_TAP     = 283

_TAP_CHANNEL_TYPE, _TAP_CHANNEL_LEN = 3, 3
_TAP_RSS_TYPE,     _TAP_RSS_LEN     = 1, 4
_TAP_LQI_TYPE,     _TAP_LQI_LEN     = 10, 1
_TAP_FCS_TYPE,     _TAP_FCS_LEN     = 0, 1
_TAP_FCS_16BIT = 1
_TAP_TLVS_BASE = 12   # always: version(4) + channel TLV(8)


def _pcap_header(dlt: int) -> bytes:
    return struct.pack('<LHHLLLL', 0xA1B2C3D4, 2, 4, 0, 0, 256, dlt)


def _crc15_4(fa: bytearray) -> bytearray:
    crc = 0
    for c in fa[:-2]:
        q = (crc ^ c) & 0x0F
        crc = (crc >> 4) ^ (q * 0x1081)
        q = (crc ^ (c >> 4)) & 0x0F
        crc = (crc >> 4) ^ (q * 0x1081)
    fa[-2] = crc & 0xFF
    fa[-1] = (crc >> 8) & 0xFF
    return fa


def _pcap_frame(frame: bytes, sec: int, usec: int, dlt: int,
                rssi: bool, do_crc: bool, metadata) -> bytes:
    fa = bytearray(frame)
    tlvs_len = _TAP_TLVS_BASE

    if do_crc:
        fa = _crc15_4(fa)
        tlvs_len += 8
    if rssi and dlt == _DLT_TAP:
        tlvs_len += 16
    elif rssi and metadata:
        fa[-2] = metadata[0] & 0xFF
        fa[-1] = metadata[3][1] & 0xFF

    cap_len = len(fa) + tlvs_len if dlt == _DLT_TAP else len(fa)
    out = struct.pack('<LLLL', sec, usec, cap_len, cap_len)

    if dlt == _DLT_TAP:
        channel = metadata[3][0] if metadata else 0
        out += struct.pack('<HH',   0, tlvs_len)
        out += struct.pack('<HHHH', _TAP_CHANNEL_TYPE, _TAP_CHANNEL_LEN, channel, 0)
        if rssi and metadata:
            out += struct.pack('<HHf', _TAP_RSS_TYPE, _TAP_RSS_LEN, float(metadata[0]))
            out += struct.pack('<HHI', _TAP_LQI_TYPE, _TAP_LQI_LEN, metadata[3][1])
        if do_crc:
            out += struct.pack('<HHI', _TAP_FCS_TYPE, _TAP_FCS_LEN, _TAP_FCS_16BIT)

    return out + bytes(fa)

# ── CLI ───────────────────────────────────────────────────────────────────────


def _parse_args():
    p = optparse.OptionParser(
        usage="%prog [options]",
        description="Sniff Thread 802.15.4 frames and write pcap to stdout or a file.",
    )
    p.add_option('-c', '--channel', dest='channel', type='int', default=11,
                 help='802.15.4 channel to sniff (default: 11)')
    p.add_option('-o', '--output',  dest='output',  type='string',
                 help='write pcap to FILE instead of stdout')
    p.add_option('--no-crc', action='store_false', dest='crc', default=True,
                 help='skip FCS recalculation in each frame')
    p.add_option('--rssi', action='store_true', dest='rssi', default=False,
                 help='include RSSI/LQI metadata in pcap')
    p.add_option('--tap',  action='store_true', dest='tap',  default=False,
                 help='use IEEE 802.15.4 TAP link type (DLT 283)')
    p.add_option('--no-reset', action='store_true', dest='no_reset', default=False,
                 help='skip NCP reset on startup')
    p.add_option('--use-host-timestamp', action='store_true',
                 dest='use_host_timestamp', default=False,
                 help='use host clock instead of NCP timestamp')
    return p.parse_args(sys.argv[1:])[0]


def main():
    opts = _parse_args()

    if opts.use_host_timestamp:
        sys.stderr.write('WARNING: Using host timestamp, may be inaccurate\n')

    with ThreadInterface() as radio:
        sys.stderr.write('Initializing sniffer...\n')

        if not opts.no_reset:
            radio.reset()

        if not radio.prop_set(spinel.PROP_PHY_ENABLED, 1):
            sys.stderr.write('ERROR: failed to enable PHY\n'); return
        if not radio.prop_set(spinel.PROP_MAC_FILTER_MODE, spinel.MAC_FILTER_MODE_MONITOR):
            sys.stderr.write('ERROR: failed to set monitor mode\n'); return
        if not radio.prop_set(spinel.PROP_PHY_CHAN, opts.channel):
            sys.stderr.write('ERROR: failed to set channel\n'); return
        if not radio.prop_set(spinel.PROP_MAC_RAW_STREAM_ENABLED, 1):
            sys.stderr.write('ERROR: failed to enable raw stream\n'); return

        sys.stderr.write(f'Sniffing on channel {opts.channel}...\n')

        dlt = _DLT_TAP if opts.tap else _DLT_WITHFCS

        if opts.output:
            output = open(opts.output, 'wb')
        else:
            output = sys.stdout.buffer

        output.write(_pcap_header(dlt))
        output.flush()

        try:
            while True:
                pkt = radio.recv(timeout_ms=1000)
                if not pkt:
                    continue
                tid, _, prop_id, val = pkt
                if tid != spinel.HDR_ASYNC or prop_id != spinel.PROP_STREAM_RAW:
                    continue

                frame, metadata = spinel.parse_stream_raw(val)

                if opts.use_host_timestamp:
                    now = time.time()
                    ts_sec  = int(now)
                    ts_usec = int((now % 1) * 1_000_000)
                elif metadata:
                    ts_us   = metadata[3][2]
                    ts_sec  = ts_us // 1_000_000
                    ts_usec = ts_us % 1_000_000
                else:
                    now = time.time()
                    ts_sec  = int(now)
                    ts_usec = int((now % 1) * 1_000_000)

                output.write(_pcap_frame(frame, ts_sec, ts_usec, dlt,
                                         opts.rssi, opts.crc, metadata))
                output.flush()

        except KeyboardInterrupt:
            pass

        if opts.output:
            output.close()


if __name__ == '__main__':
    main()
