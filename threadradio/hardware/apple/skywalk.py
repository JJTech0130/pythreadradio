"""
skywalk.py — Generic Skywalk channel access via ctypes (macOS only).

Opens any Skywalk nexus channel by its IOKit protocol name (e.g. "tsi").
Returns and accepts raw bytes per slot — no framing is applied here.

Public API:
    open_channel(protocol)           -> SkywalkChannel
    close_channel(ch)
    read_slot(ch, max_len, timeout_ms)  -> bytes | None
    write_slot(ch, data, timeout_ms)    -> bool

SkywalkChannel also works as a context manager.
"""

import ctypes
import sys
from typing import TypeAlias

# ── Load libraries ─────────────────────────────────────────────────────────────

_libc  = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
_iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
_cf    = ctypes.CDLL(
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
)

# ── Constants ─────────────────────────────────────────────────────────────────

_kCFStringEncodingUTF8        = 0x08000100
_kIOMainPortDefault           = 0
_kIOServicePlane              = b"IOService"
_kIORegistryIterateRecursively = 0x00000001

_EVFILT_NW_CHANNEL_TX = -2   # (int16_t) 0xFFFE
_EVFILT_NW_CHANNEL_RX = -1   # (int16_t) 0xFFFF

_EV_ADD    = 0x0001
_EV_ENABLE = 0x0004

_CHANNEL_SYNC_TX = 0
_CHANNEL_SYNC_RX = 1

_CHANNEL_ATTR_TX_SLOTS    = 2
_CHANNEL_ATTR_RX_SLOTS    = 3
_CHANNEL_ATTR_SLOT_BUF_SIZE = 4

_CHANNEL_FIRST_TX_RING = 0
_CHANNEL_FIRST_RX_RING = 2

# ── C structures ──────────────────────────────────────────────────────────────

_uuid_array_t = ctypes.c_uint8 * 16
UuidT: TypeAlias = ctypes.Array[ctypes.c_uint8]


class _SlotProp(ctypes.Structure):
    _align_ = 8
    _fields_ = [
        ("sp_flags",    ctypes.c_uint16),
        ("sp_len",      ctypes.c_uint16),
        ("sp_idx",      ctypes.c_uint32),
        ("sp_ext_ptr",  ctypes.c_uint64),
        ("sp_buf_ptr",  ctypes.c_uint64),
        ("sp_mdata_ptr",ctypes.c_uint64),
        ("_sp_pad",     ctypes.c_uint32 * 8),
    ]


class _Kevent(ctypes.Structure):
    _fields_ = [
        ("ident",  ctypes.c_uint64),
        ("filter", ctypes.c_int16),
        ("flags",  ctypes.c_uint16),
        ("fflags", ctypes.c_uint32),
        ("data",   ctypes.c_int64),
        ("udata",  ctypes.c_void_p),
    ]


class _Timespec(ctypes.Structure):
    _fields_ = [
        ("tv_sec",  ctypes.c_long),
        ("tv_nsec", ctypes.c_long),
    ]


# ── CoreFoundation prototypes ─────────────────────────────────────────────────

_cf.CFStringCreateWithCString.restype  = ctypes.c_void_p
_cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]

_cf.CFDictionarySetValue.restype  = None
_cf.CFDictionarySetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_cf.CFRelease.restype  = None
_cf.CFRelease.argtypes = [ctypes.c_void_p]

_cf.CFStringGetCStringPtr.restype  = ctypes.c_char_p
_cf.CFStringGetCStringPtr.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

_cf.CFStringGetCString.restype  = ctypes.c_bool
_cf.CFStringGetCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int32, ctypes.c_uint32]

# ── IOKit prototypes ──────────────────────────────────────────────────────────

_iokit.IOServiceMatching.restype  = ctypes.c_void_p
_iokit.IOServiceMatching.argtypes = [ctypes.c_char_p]

_iokit.IOServiceGetMatchingService.restype  = ctypes.c_uint32
_iokit.IOServiceGetMatchingService.argtypes = [ctypes.c_uint32, ctypes.c_void_p]

_iokit.IOObjectRelease.restype  = ctypes.c_int
_iokit.IOObjectRelease.argtypes = [ctypes.c_uint32]

_iokit.IORegistryEntrySearchCFProperty.restype  = ctypes.c_void_p
_iokit.IORegistryEntrySearchCFProperty.argtypes = [
    ctypes.c_uint32, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
]

# ── libc / Skywalk prototypes ─────────────────────────────────────────────────

_libc.kqueue.restype  = ctypes.c_int
_libc.kqueue.argtypes = []

_libc.kevent.restype  = ctypes.c_int
_libc.kevent.argtypes = [
    ctypes.c_int, ctypes.POINTER(_Kevent), ctypes.c_int,
    ctypes.POINTER(_Kevent), ctypes.c_int, ctypes.POINTER(_Timespec),
]

_libc.close.restype  = ctypes.c_int
_libc.close.argtypes = [ctypes.c_int]

_libc.uuid_parse.restype  = ctypes.c_int
_libc.uuid_parse.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

_libc.os_channel_attr_create.restype  = ctypes.c_void_p
_libc.os_channel_attr_create.argtypes = []

_libc.os_channel_attr_get.restype  = ctypes.c_int
_libc.os_channel_attr_get.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_uint64)]

_libc.os_channel_attr_destroy.restype  = None
_libc.os_channel_attr_destroy.argtypes = [ctypes.c_void_p]

_libc.os_channel_read_attr.restype  = ctypes.c_int
_libc.os_channel_read_attr.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_libc.os_channel_create.restype  = ctypes.c_void_p
_libc.os_channel_create.argtypes = [ctypes.c_void_p, ctypes.c_uint16]

_libc.os_channel_get_fd.restype  = ctypes.c_int
_libc.os_channel_get_fd.argtypes = [ctypes.c_void_p]

_libc.os_channel_ring_id.restype  = ctypes.c_uint32
_libc.os_channel_ring_id.argtypes = [ctypes.c_void_p, ctypes.c_int]

_libc.os_channel_tx_ring.restype  = ctypes.c_void_p
_libc.os_channel_tx_ring.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

_libc.os_channel_rx_ring.restype  = ctypes.c_void_p
_libc.os_channel_rx_ring.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

_libc.os_channel_get_next_slot.restype  = ctypes.c_void_p
_libc.os_channel_get_next_slot.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(_SlotProp)]

_libc.os_channel_advance_slot.restype  = ctypes.c_int
_libc.os_channel_advance_slot.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_libc.os_channel_set_slot_properties.restype  = None
_libc.os_channel_set_slot_properties.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(_SlotProp)]

_libc.os_channel_sync.restype  = ctypes.c_int
_libc.os_channel_sync.argtypes = [ctypes.c_void_p, ctypes.c_int]

_libc.os_channel_destroy.restype  = None
_libc.os_channel_destroy.argtypes = [ctypes.c_void_p]

# ── Helpers ───────────────────────────────────────────────────────────────────


def _cfstr(s: str) -> int:
    ref = _cf.CFStringCreateWithCString(None, s.encode(), _kCFStringEncodingUTF8)
    if not ref:
        raise RuntimeError(f"CFStringCreateWithCString failed for {s!r}")
    return ref


def _get_nexus_uuid(protocol: str) -> UuidT:
    """
    Look up the Skywalk nexus UUID for *protocol* via IOKit.
    Searches for AppleConvergedIPCInterface with ACIPCInterfaceProtocol=protocol
    and reads its IOSkywalkNexusUUID property.
    """
    dict_ref = _iokit.IOServiceMatching(b"AppleConvergedIPCInterface")
    if not dict_ref:
        raise RuntimeError("[skywalk] IOServiceMatching failed")

    key = _cfstr("ACIPCInterfaceProtocol")
    val = _cfstr(protocol)
    _cf.CFDictionarySetValue(dict_ref, key, val)
    _cf.CFRelease(key)
    _cf.CFRelease(val)

    svc = _iokit.IOServiceGetMatchingService(_kIOMainPortDefault, dict_ref)
    if not svc:
        raise RuntimeError(f"[skywalk] no matching service for protocol '{protocol}'")

    uuid_key = _cfstr("IOSkywalkNexusUUID")
    uuid_cf = _iokit.IORegistryEntrySearchCFProperty(
        svc, _kIOServicePlane, uuid_key, None, _kIORegistryIterateRecursively
    )
    _cf.CFRelease(uuid_key)
    _iokit.IOObjectRelease(svc)

    if not uuid_cf:
        raise RuntimeError(f"[skywalk] no IOSkywalkNexusUUID for '{protocol}'")

    cstr = _cf.CFStringGetCStringPtr(uuid_cf, _kCFStringEncodingUTF8)
    if not cstr:
        buf = ctypes.create_string_buffer(64)
        _cf.CFStringGetCString(uuid_cf, buf, 64, _kCFStringEncodingUTF8)
        cstr = buf.value
    _cf.CFRelease(uuid_cf)

    print(f"[skywalk] protocol={protocol!r} uuid={cstr.decode()}", file=sys.stderr)

    uuid_out = _uuid_array_t()
    if _libc.uuid_parse(cstr, uuid_out) != 0:
        raise RuntimeError("[skywalk] uuid_parse failed")
    return uuid_out


def _kq_register(ch_fd: int, filter_val: int) -> int:
    kq = _libc.kqueue()
    if kq == -1:
        raise OSError(ctypes.get_errno(), "[skywalk] kqueue() failed")
    kev = _Kevent()
    kev.ident  = ch_fd
    kev.filter = filter_val
    kev.flags  = _EV_ADD | _EV_ENABLE
    if _libc.kevent(kq, ctypes.byref(kev), 1, None, 0, None) == -1:
        err = ctypes.get_errno()
        _libc.close(kq)
        raise OSError(err, "[skywalk] kevent register failed")
    return kq


def _kq_wait(kq: int, expected_filter: int, timeout_ms: int) -> int:
    """Returns 0 on event, 1 on timeout/error, -1 on unexpected filter."""
    ev = _Kevent()
    if timeout_ms < 0:
        ts_ptr = None
    else:
        ts = _Timespec()
        ts.tv_sec  = timeout_ms // 1000
        ts.tv_nsec = (timeout_ms % 1000) * 1_000_000
        ts_ptr = ctypes.byref(ts)

    n = _libc.kevent(kq, None, 0, ctypes.byref(ev), 1, ts_ptr)
    if n <= 0:
        return 1
    if ev.filter != expected_filter:
        print(f"[skywalk] unexpected kq filter 0x{ev.filter & 0xFFFF:x}", file=sys.stderr)
        return -1
    return 0

# ── Public API ────────────────────────────────────────────────────────────────


class SkywalkChannel:
    """Handle for an open Skywalk nexus channel. Use as a context manager."""

    __slots__ = ("channel", "write_kq", "read_kq", "tx_ring", "rx_ring", "slot_size")

    def __init__(self) -> None:
        self.channel   = None
        self.write_kq  = -1
        self.read_kq   = -1
        self.tx_ring   = None
        self.rx_ring   = None
        self.slot_size = 0

    def __enter__(self) -> "SkywalkChannel":
        return self

    def __exit__(self, *_: object) -> None:
        close_channel(self)


def open_channel(protocol: str) -> SkywalkChannel:
    """
    Open a Skywalk nexus channel for *protocol* (e.g. "tsi").
    Raises RuntimeError / OSError on failure.
    """
    ch = SkywalkChannel()

    uuid = _get_nexus_uuid(protocol)

    raw = _libc.os_channel_create(uuid, 0)
    if not raw:
        raise RuntimeError(
            f"[skywalk] os_channel_create failed for '{protocol}' "
            "(is the owning daemon still running?)"
        )
    ch.channel = ctypes.c_void_p(raw)

    attr = _libc.os_channel_attr_create()
    if attr:
        ap = ctypes.c_void_p(attr)
        if _libc.os_channel_read_attr(ch.channel, ap) == 0:
            tx_s = ctypes.c_uint64(0)
            rx_s = ctypes.c_uint64(0)
            sz   = ctypes.c_uint64(0)
            _libc.os_channel_attr_get(ap, _CHANNEL_ATTR_TX_SLOTS,    ctypes.byref(tx_s))
            _libc.os_channel_attr_get(ap, _CHANNEL_ATTR_RX_SLOTS,    ctypes.byref(rx_s))
            _libc.os_channel_attr_get(ap, _CHANNEL_ATTR_SLOT_BUF_SIZE, ctypes.byref(sz))
            ch.slot_size = sz.value
            print(
                f"[skywalk] channel open: tx_slots={tx_s.value} "
                f"rx_slots={rx_s.value} slot_buf={sz.value}",
                file=sys.stderr,
            )
        _libc.os_channel_attr_destroy(ap)

    ch_fd = _libc.os_channel_get_fd(ch.channel)
    try:
        ch.write_kq = _kq_register(ch_fd, _EVFILT_NW_CHANNEL_TX)
        ch.read_kq  = _kq_register(ch_fd, _EVFILT_NW_CHANNEL_RX)
    except OSError:
        close_channel(ch)
        raise

    tx_rid = _libc.os_channel_ring_id(ch.channel, _CHANNEL_FIRST_TX_RING)
    rx_rid = _libc.os_channel_ring_id(ch.channel, _CHANNEL_FIRST_RX_RING)
    ch.tx_ring = ctypes.c_void_p(_libc.os_channel_tx_ring(ch.channel, tx_rid))
    ch.rx_ring = ctypes.c_void_p(_libc.os_channel_rx_ring(ch.channel, rx_rid))

    print(f"[skywalk] '{protocol}' channel ready", file=sys.stderr)
    return ch


def close_channel(ch: SkywalkChannel) -> None:
    """Release all resources for *ch*."""
    if ch.read_kq != -1:
        _libc.close(ch.read_kq);  ch.read_kq  = -1
    if ch.write_kq != -1:
        _libc.close(ch.write_kq); ch.write_kq = -1
    if ch.channel:
        _libc.os_channel_destroy(ch.channel); ch.channel = None


def read_slot(ch: SkywalkChannel, max_len: int = 2048, timeout_ms: int = -1) -> bytes | None:
    """
    Read one slot from *ch*'s RX ring.
    Returns the raw bytes on success, None on timeout.
    """
    r = _kq_wait(ch.read_kq, _EVFILT_NW_CHANNEL_RX, timeout_ms)
    if r != 0:
        return None

    sp   = _SlotProp()
    slot = _libc.os_channel_get_next_slot(ch.rx_ring, None, ctypes.byref(sp))
    if not slot:
        raise RuntimeError("[skywalk] read: empty slot after kevent")

    frame_len = sp.sp_len
    if frame_len > max_len:
        _libc.os_channel_advance_slot(ch.rx_ring, ctypes.c_void_p(slot))
        _libc.os_channel_sync(ch.channel, _CHANNEL_SYNC_RX)
        raise RuntimeError(f"[skywalk] slot len {frame_len} > max_len {max_len}")

    buf = (ctypes.c_uint8 * frame_len)()
    ctypes.memmove(buf, sp.sp_buf_ptr, frame_len)
    data = bytes(buf)

    _libc.os_channel_advance_slot(ch.rx_ring, ctypes.c_void_p(slot))
    _libc.os_channel_sync(ch.channel, _CHANNEL_SYNC_RX)
    return data


def write_slot(ch: SkywalkChannel, data: bytes, timeout_ms: int = -1) -> bool:
    """
    Write *data* into one TX slot.
    Returns True on success, False on timeout.
    """
    if ch.slot_size and len(data) > ch.slot_size:
        raise RuntimeError(f"[skywalk] write: {len(data)} bytes > slot_size {ch.slot_size}")

    r = _kq_wait(ch.write_kq, _EVFILT_NW_CHANNEL_TX, timeout_ms)
    if r != 0:
        return False

    sp   = _SlotProp()
    slot = _libc.os_channel_get_next_slot(ch.tx_ring, None, ctypes.byref(sp))
    if not slot:
        # Hack: just sleep for 100ms and try again
        import time
        print("[skywalk] ran out of slots, waiting 100ms!")
        time.sleep(0.1)
        return write_slot(ch, data, timeout_ms)

    ctypes.memmove(sp.sp_buf_ptr, data, len(data))
    sp.sp_len = len(data)
    _libc.os_channel_set_slot_properties(ch.tx_ring, ctypes.c_void_p(slot), ctypes.byref(sp))
    _libc.os_channel_advance_slot(ch.tx_ring, ctypes.c_void_p(slot))
    _libc.os_channel_sync(ch.channel, _CHANNEL_SYNC_TX)
    return True
