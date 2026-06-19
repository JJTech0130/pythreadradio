"""
scan.py — Thread network scanner CLI.

Usage:
    sudo threadscan
    sudo threadscan -c 15
    sudo threadscan --period 50 --json
    sudo threadscan --continuous
    sudo threadscan --timeout 60
"""

import argparse
import json
import sys
import time

from ..hardware.apple import AppleRadio
from ..thread import scanner


_TABLE_HEADER = (f"| {'J'} | {'Network Name':<16} | {'Extended PAN':<16} | {'PAN ID':<6} "
                 f"| {'MAC Address':<16} | {'Ch':>2} | {'dBm':>4} | {'LQI':>3} |")
_TABLE_SEP = "+" + "+".join("-" * (len(col) + 2) for col in [
    "-", "----------------", "----------------", "------",
    "----------------", "--", "----", "---",
]) + "+"


def _format_row(n: dict) -> str:
    j      = "J" if n.get("joinable") else " "
    name   = (n.get("network_name") or "")[:16]
    xpanid = (n.get("ext_pan_id") or "")[:16]
    panid  = (n.get("pan_id") or "")
    mac    = (n.get("ext_addr") or "")[:16]
    ch     = n.get("channel", 0)
    rssi   = n.get("rssi", 0)
    lqi    = n.get("lqi", 0)
    return (f"| {j} | {name:<16} | {xpanid:<16} | {panid:<6} "
            f"| {mac:<16} | {ch:>2} | {rssi:>4} | {lqi:>3} |")


def _print_table(networks: list[dict]) -> None:
    if not networks:
        print("No Thread networks found.")
        return
    print(_TABLE_HEADER)
    print(_TABLE_SEP)
    for n in networks:
        print(_format_row(n))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="threadscan",
        description="Scan for Thread networks via the TSI Spinel interface.",
    )
    parser.add_argument(
        "-c", "--channel", type=int, metavar="CH",
        help="Scan a single channel (11-26). Default: all Thread channels.",
    )
    parser.add_argument(
        "--period", type=int, default=300, metavar="MS",
        help="Dwell time per channel in milliseconds (default: 300).",
    )
    parser.add_argument(
        "--timeout", type=float, default=None, metavar="SEC",
        help="Keep scanning for this many seconds, accumulating results across passes.",
    )
    parser.add_argument(
        "--continuous", action="store_true",
        help="Scan repeatedly until Ctrl+C, accumulating new networks as found.",
    )
    parser.add_argument(
        "--no-reset", action="store_true",
        help="Skip NCP reset on startup.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON. In continuous/timeout mode: "
             "one JSON object per line as networks are found, then "
             "a final array on exit.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Print every Spinel TX/RX frame to stderr.",
    )
    args = parser.parse_args()

    channels  = [args.channel] if args.channel is not None else list(range(11, 27))
    looping   = args.continuous or args.timeout is not None
    deadline  = (time.monotonic() + args.timeout) if args.timeout else None

    ch_desc = (str(channels[0]) if len(channels) == 1
               else f"{channels[0]}-{channels[-1]}")
    mode_desc = ("continuous" if args.continuous
                 else f"timeout {args.timeout}s" if args.timeout
                 else "single pass")
    print(f"Scanning channels {ch_desc} ({args.period} ms/ch, {mode_desc})…",
          file=sys.stderr)

    all_nets: list[dict] = []

    with AppleRadio(debug=args.debug) as radio:
        if not args.no_reset:
            radio.reset()
        try:
            if looping:
                if not args.json:
                    print(_TABLE_HEADER)
                    print(_TABLE_SEP)
                for net in scanner.scan_iter(radio, channels=channels,
                                             period_ms=args.period,
                                             deadline=deadline):
                    all_nets.append(net)
                    if args.json:
                        print(json.dumps(net), flush=True)
                    else:
                        print(_format_row(net), flush=True)
            else:
                all_nets = scanner.scan(radio, channels=channels, period_ms=args.period)
        except KeyboardInterrupt:
            print("\nStopped.", file=sys.stderr)

    if args.json:
        print(json.dumps(all_nets, indent=2))
    elif not looping:
        _print_table(all_nets)
