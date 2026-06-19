"""
scan.py — Thread network scanner CLI.

Usage:
    sudo threadscan
    sudo threadscan -c 15
    sudo threadscan --period 50 --json
"""

import argparse
import json
import sys

from ..hardware.apple import AppleRadio
from ..thread import scanner


def _print_table(networks: list[dict]) -> None:
    if not networks:
        print("No Thread networks found.")
        return

    header = f"| {'J'} | {'Network Name':<16} | {'Extended PAN':<16} | {'PAN '} | {'MAC Address':<16} | {'Ch':>2} | {'dBm':>4} | {'LQI':>3} |"
    sep    = "+" + "+".join("-" * (len(col) + 2) for col in [
        "-", "----------------", "----------------", "----", "----------------", "--", "----", "---"
    ]) + "+"
    print(header)
    print(sep)
    for n in networks:
        j      = "J" if n.get("joinable") else " "
        name   = (n.get("network_name") or "")[:16]
        xpanid = (n.get("ext_pan_id") or "")[:16]
        panid  = (n.get("pan_id") or "")
        mac    = (n.get("ext_addr") or "")[:16]
        ch     = n.get("channel", 0)
        rssi   = n.get("rssi", 0)
        lqi    = n.get("lqi", 0)
        print(f"| {j} | {name:<16} | {xpanid:<16} | {panid:<4} | {mac:<16} | {ch:>2} | {rssi:>4} | {lqi:>3} |")


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
        "--period", type=int, default=30, metavar="MS",
        help="Dwell time per channel in milliseconds (default: 30).",
    )
    parser.add_argument(
        "--timeout", type=float, default=None, metavar="SEC",
        help="Hard timeout in seconds (default: auto based on channels × period).",
    )
    parser.add_argument(
        "--no-reset", action="store_true",
        help="Skip NCP reset on startup.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON instead of a table.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Print every Spinel TX/RX frame to stderr.",
    )
    args = parser.parse_args()

    channels = [args.channel] if args.channel is not None else list(range(11, 27))

    print(f"Scanning channel{'s' if len(channels) > 1 else ''} "
          f"{channels[0] if len(channels) == 1 else f'{channels[0]}-{channels[-1]}'} "
          f"({args.period} ms/ch)…", file=sys.stderr)

    with AppleRadio(debug=args.debug) as radio:
        if not args.no_reset:
            radio.reset()
        networks = scanner.scan(radio, channels=channels, period_ms=args.period)

    if args.json:
        print(json.dumps(networks, indent=2))
    else:
        _print_table(networks)
