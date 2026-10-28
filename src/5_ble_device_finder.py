"""
Project 5: Bluetooth Low Energy (BLE) Device Finder & Distance Estimator
Install: pip install bleak
Run:     python 5_ble_device_finder.py [--time 10] [--n 2.5] [--loop]

Distance model (log-distance):
    d = 10 ** ((TxPower_1m - RSSI) / (10 * n))
TxPower_1m is the advertised calibrated power if present, else -59 dBm.
n is the path-loss exponent (2.0 free space, 2.5-4.0 indoors).
RSSI-based distance is only a rough estimate (+/- several metres).
"""
import argparse
import asyncio

from bleak import BleakScanner

DEFAULT_TX_1M = -59


def estimate_distance(rssi, tx_1m, n):
    return 10 ** ((tx_1m - rssi) / (10 * n))


def proximity(d):
    return "Immediate" if d < 1 else "Near" if d < 4 else "Far" if d < 10 else "Very far"


def describe(adv):
    info = []
    if adv.manufacturer_data:
        ids = ", ".join(f"0x{k:04X}" for k in adv.manufacturer_data)
        info.append(f"mfr:{ids}")
    if adv.service_uuids:
        info.append(f"{len(adv.service_uuids)} service(s)")
    return " ".join(info) or "-"


async def scan_once(duration, n):
    found = await BleakScanner.discover(timeout=duration, return_adv=True)
    rows = []
    for addr, (dev, adv) in found.items():
        tx = adv.tx_power if adv.tx_power is not None else DEFAULT_TX_1M
        d = estimate_distance(adv.rssi, tx, n)
        rows.append((dev.name or adv.local_name or "<unknown>", addr,
                     adv.rssi, tx, d, describe(adv)))
    rows.sort(key=lambda r: r[2], reverse=True)   # strongest signal first
    return rows


def print_rows(rows):
    print(f"\n{'Name':<24}{'Address':<40}{'RSSI':>6}{'Tx@1m':>7}{'Dist(m)':>9}  "
          f"{'Zone':<10}Info")
    print("-" * 118)
    for name, addr, rssi, tx, d, info in rows:
        print(f"{name[:23]:<24}{addr:<40}{rssi:>6}{tx:>7}{d:>9.2f}  "
              f"{proximity(d):<10}{info}")
    print(f"\n{len(rows)} device(s) found.")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--time", type=float, default=8, help="scan seconds")
    ap.add_argument("--n", type=float, default=2.5, help="path-loss exponent")
    ap.add_argument("--loop", action="store_true", help="scan continuously")
    args = ap.parse_args()

    while True:
        print(f"Scanning for {args.time}s ...")
        print_rows(await scan_once(args.time, args.n))
        if not args.loop:
            break


if __name__ == "__main__":
    asyncio.run(main())
