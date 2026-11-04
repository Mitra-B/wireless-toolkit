"""
Project 6: Bluetooth Security Assessment Tool
Install: pip install bleak tabulate
Run:     python 6_bluetooth_security_assessment.py                 (scan + assess)
         python 6_bluetooth_security_assessment.py --duration 90   (better privacy check)
         python 6_bluetooth_security_assessment.py --demo          (no Bluetooth needed)
         python 6_bluetooth_security_assessment.py --audit AA:BB:CC:DD:EE:FF
         python 6_bluetooth_security_assessment.py --json out.json --csv out.csv

What it does
  1. PASSIVE SCAN: listens to BLE advertisements for --duration seconds and
     collects everything each device broadcasts (name, services, manufacturer
     data, signal strength, how long its address stays the same).
  2. RISK ASSESSMENT: applies privacy/security heuristics and gives each device
     a 0-100 risk score with plain-language findings and recommendations.
  3. OPTIONAL GATT AUDIT (--audit ADDRESS): connects to ONE device you own and
     READS (never writes) its services to see what is exposed without pairing.

Ethics: Passive scanning only reads public broadcasts. The --audit mode
connects to a device, so only use it on hardware you own or are authorised to
test. This tool does not crack, sniff, spoof or attack anything.
Scores are heuristics for awareness, not proof of a vulnerability.
"""
import argparse
import asyncio
import csv
import json
import re
import time
from dataclasses import dataclass, field

from tabulate import tabulate

# ---------------------------------------------------------------- knowledge
COMPANIES = {0x004C: "Apple", 0x0006: "Microsoft", 0x0075: "Samsung",
             0x00E0: "Google", 0x0087: "Garmin", 0x0157: "Xiaomi/Huami",
             0x02E5: "Espressif (ESP32)", 0x0059: "Nordic Semiconductor"}

# 16-bit service UUID -> (label, category)
SERVICES = {
    0x180D: ("Heart Rate", "health"), 0x1808: ("Glucose", "health"),
    0x1810: ("Blood Pressure", "health"), 0x1809: ("Health Thermometer", "health"),
    0x181D: ("Weight Scale", "health"), 0x1822: ("Pulse Oximeter", "health"),
    0x1812: ("HID (keyboard/mouse)", "hid"),
    0x1804: ("Tx Power", "info"), 0x180F: ("Battery", "info"),
    0x180A: ("Device Information", "info"),
    0xFEED: ("Tile tracker", "tracker"), 0xFD5A: ("Samsung SmartTag", "tracker"),
    0xFE2C: ("Google Fast Pair", "pairing"), 0xFD44: ("Apple Find My network", "tracker"),
}
NORDIC_UART = "6e400001-b5a3-f393-a9a2-"
DEV_BOARD_NAMES = re.compile(r"^(HC-0\d|ESP32|ESP_|BLE[-_ ]?\w*|Arduino|nRF\d*|BT0\d|JDY-\d+|"
                             r"MLT-BT05|HMSoft|CC254\d)", re.I)
PERSONAL_NAME = re.compile(r"[A-Za-z]+['’]s\s|\b(iPhone|iPad|MacBook|Galaxy|Pixel|"
                           r"Watch|AirPods|Buds)\b", re.I)
POSSESSIVE = re.compile(r"[A-Za-z]+['’]s\s", re.I)


def short_uuid(u):
    u = u.lower()
    if u.endswith("-0000-1000-8000-00805f9b34fb") and u.startswith("0000"):
        return int(u[4:8], 16)
    return None


@dataclass
class Dev:
    address: str
    name: str = ""
    rssi: list = field(default_factory=list)
    first: float = 0.0
    last: float = 0.0
    mfr: dict = field(default_factory=dict)        # company_id -> bytes
    uuids: set = field(default_factory=set)
    svc_data: set = field(default_factory=set)
    tx_power: int | None = None
    findings: list = field(default_factory=list)   # (points, severity, text)
    score: int = 0
    rating: str = "LOW"

    @property
    def avg_rssi(self):
        return sum(self.rssi) / len(self.rssi) if self.rssi else -100

    @property
    def span(self):
        return self.last - self.first

    @property
    def vendor(self):
        for cid in self.mfr:
            return COMPANIES.get(cid, f"0x{cid:04X}")
        return "-"


# ------------------------------------------------------------- assessment
def assess(d: Dev):
    f = d.findings = []
    cats = set()
    for u in d.uuids | {f"0000{s:04x}-0000-1000-8000-00805f9b34fb" for s in d.svc_data
                        if isinstance(s, int)}:
        s16 = short_uuid(u) if isinstance(u, str) else None
        if s16 in SERVICES:
            cats.add((SERVICES[s16][1], SERVICES[s16][0]))
        if isinstance(u, str) and u.lower().startswith(NORDIC_UART):
            cats.add(("serial", "Nordic UART (serial-over-BLE)"))

    # Apple continuity payload types
    apple = d.mfr.get(0x004C)
    if apple:
        t = apple[0]
        if t == 0x12:
            cats.add(("tracker", "Apple Find My accessory (AirTag-style)"))
        elif t == 0x07:
            cats.add(("pairing", "Apple proximity pairing (AirPods-style)"))

    for cat, label in sorted(cats):
        if cat == "tracker":
            f.append((20, "MEDIUM", f"Tracking tag detected: {label}. If this is not yours "
                      "and keeps appearing near you, check your phone's unknown-tracker alerts."))
        elif cat == "health":
            f.append((25, "HIGH", f"Advertises health service ({label}). Health data should "
                      "only be exposed after encrypted, authenticated pairing."))
        elif cat == "hid":
            f.append((20, "MEDIUM", "Advertises HID (keyboard/mouse). Confirm it uses "
                      "encrypted pairing (LE Secure Connections) and is not left discoverable."))
        elif cat == "serial":
            f.append((12, "MEDIUM", f"{label}: common on IoT/dev hardware, often without "
                      "authentication. Verify access is protected."))
        elif cat == "pairing":
            f.append((5, "LOW", f"Pairing broadcast ({label}): device is advertising that "
                      "it can be paired nearby."))

    if d.name:
        if POSSESSIVE.search(d.name + " "):
            f.append((15, "MEDIUM", f"Device name '{d.name}' appears to reveal the owner's "
                      "name. Rename it to something generic."))
        elif PERSONAL_NAME.search(d.name):
            f.append((5, "LOW", f"Default/model name '{d.name}' reveals the device type "
                      "to anyone nearby."))
        if DEV_BOARD_NAMES.match(d.name):
            f.append((10, "MEDIUM", f"Name '{d.name}' looks like a dev board / default module "
                      "name; factory settings are often left unchanged."))

    if d.span >= 60:
        f.append((15, "MEDIUM", f"Same address observed for {d.span:.0f}s without changing. "
                  "A rotating private address would resist tracking."))
    elif d.span < 60:
        pass

    if d.avg_rssi > -50:
        f.append((0, "INFO", f"Very strong signal ({d.avg_rssi:.0f} dBm): device is physically "
                  "very close."))
    if not d.name and not d.mfr and not d.uuids:
        f.append((3, "INFO", "Advertises no identifying data (anonymous device)."))

    d.score = min(100, sum(p for p, _, _ in f))
    d.rating = "HIGH" if d.score >= 50 else "MEDIUM" if d.score >= 20 else "LOW"
    return d


# ------------------------------------------------------------------- scan
async def scan(duration):
    from bleak import BleakScanner
    devs = {}

    def cb(device, adv):
        now = time.time()
        d = devs.get(device.address)
        if d is None:
            d = devs[device.address] = Dev(device.address, first=now)
        d.last = now
        d.rssi.append(adv.rssi)
        d.name = adv.local_name or device.name or d.name
        d.mfr.update(adv.manufacturer_data or {})
        d.uuids.update(u.lower() for u in (adv.service_uuids or []))
        d.svc_data.update(u.lower() for u in (adv.service_data or {}))
        if adv.tx_power is not None:
            d.tx_power = adv.tx_power

    print(f"Scanning for {duration}s (passive) ...")
    async with BleakScanner(detection_callback=cb):
        await asyncio.sleep(duration)
    return list(devs.values())


# ------------------------------------------------------------ GATT audit
async def audit(address, timeout=15):
    """Read-only enumeration of one device you own. Never writes."""
    from bleak import BleakClient
    res = {"address": address, "connected": False, "services": [],
           "readable_without_pairing": 0, "writable_chars": 0, "findings": []}
    try:
        async with BleakClient(address, timeout=timeout) as c:
            res["connected"] = True
            res["findings"].append("Device accepted a connection from an unpaired "
                                   "client (anyone nearby can connect).")
            for svc in c.services:
                s = {"uuid": svc.uuid, "chars": []}
                for ch in svc.characteristics:
                    info = {"uuid": ch.uuid, "props": list(ch.properties), "value": None}
                    if "write" in ch.properties or "write-without-response" in ch.properties:
                        res["writable_chars"] += 1
                    if "read" in ch.properties:
                        try:
                            v = await c.read_gatt_char(ch)
                            res["readable_without_pairing"] += 1
                            info["value"] = bytes(v).decode("utf-8", "replace")[:40] \
                                if v and all(32 <= b < 127 for b in v) else bytes(v).hex()[:40]
                        except Exception as e:
                            info["value"] = f"<read refused: {type(e).__name__}>"
                    s["chars"].append(info)
                res["services"].append(s)
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
        return res

    if res["readable_without_pairing"]:
        res["findings"].append(f"{res['readable_without_pairing']} characteristic(s) readable "
                               "without pairing. Check none expose sensitive data.")
    if res["writable_chars"]:
        res["findings"].append(f"{res['writable_chars']} writable characteristic(s) found. "
                               "Not tested (tool never writes); verify they require "
                               "encrypted/authenticated pairing.")
    for s in res["services"]:
        for ch in s["chars"]:
            if ch["uuid"].startswith(("00002a24", "00002a26", "00002a28")) and ch["value"]:
                res["findings"].append(f"Device Information exposed: {ch['value']} "
                                       "(model/firmware aids fingerprinting).")
    return res


# ----------------------------------------------------------------- output
def demo_devices():
    t = time.time()
    mk = lambda **k: Dev(first=t - k.pop("span", 5), last=t, **k)
    return [
        mk(address="AA:11:22:33:44:01", name="Rahul's iPhone", rssi=[-48, -50], span=90,
           mfr={0x004C: b"\x10\x05"}),
        mk(address="AA:11:22:33:44:02", name="HC-05", rssi=[-70], span=20,
           uuids={"6e400001-b5a3-f393-a9a2-de4f5a9c6c4c"}),
        mk(address="AA:11:22:33:44:03", name="Mi Band 6", rssi=[-62], span=70,
           uuids={"0000180d-0000-1000-8000-00805f9b34fb"}, mfr={0x0157: b"\x01"}),
        mk(address="AA:11:22:33:44:04", name="", rssi=[-80], span=30,
           mfr={0x004C: b"\x12\x19\x00"}),
        mk(address="AA:11:22:33:44:05", name="BT Keyboard", rssi=[-55], span=15,
           uuids={"00001812-0000-1000-8000-00805f9b34fb"}),
        mk(address="AA:11:22:33:44:06", name="", rssi=[-90], span=5),
    ]


def report(devs, args):
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    devs.sort(key=lambda d: (order[d.rating], -d.score))
    print("\n=== Bluetooth Security Assessment ===\n")
    print(tabulate([[d.name or "<unnamed>", d.address, d.vendor, f"{d.avg_rssi:.0f}",
                     f"{d.span:.0f}s", d.score, d.rating] for d in devs],
                   headers=["Name", "Address", "Vendor", "RSSI", "Seen", "Score", "Risk"],
                   tablefmt="grid"))
    print("\n--- Findings ---")
    for d in devs:
        real = [x for x in d.findings if x[1] != "INFO" or True]
        if not real:
            continue
        print(f"\n[{d.rating}] {d.name or '<unnamed>'} ({d.address}) score {d.score}")
        for pts, sev, text in real:
            print(f"   - ({sev}) {text}")
    high = sum(d.rating == "HIGH" for d in devs)
    med = sum(d.rating == "MEDIUM" for d in devs)
    print(f"\nSummary: {len(devs)} devices | {high} high | {med} medium | "
          f"{len(devs) - high - med} low")
    if not args.demo and args.duration < 60:
        print("Tip: use --duration 90 so the tool can check whether addresses rotate.")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([{"name": d.name, "address": d.address, "vendor": d.vendor,
                        "rssi": round(d.avg_rssi), "seen_s": round(d.span), "score": d.score,
                        "rating": d.rating, "findings": [t for _, _, t in d.findings]}
                       for d in devs], fh, indent=2)
        print(f"Saved {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["name", "address", "vendor", "rssi", "seen_s", "score", "rating",
                        "findings"])
            for d in devs:
                w.writerow([d.name, d.address, d.vendor, round(d.avg_rssi), round(d.span),
                            d.score, d.rating, " | ".join(t for _, _, t in d.findings)])
        print(f"Saved {args.csv}")


def report_audit(r):
    print(f"\n=== GATT Audit: {r['address']} ===")
    if r.get("error"):
        print(f"Could not complete audit: {r['error']}")
        return
    for s in r["services"]:
        print(f"\nService {s['uuid']}")
        for ch in s["chars"]:
            print(f"   {ch['uuid']}  {','.join(ch['props']):<28} {ch['value'] or ''}")
    print("\n--- Findings ---")
    for x in r["findings"] or ["No issues detected."]:
        print(f" - {x}")


async def main():
    ap = argparse.ArgumentParser(description="Bluetooth security assessment (passive)")
    ap.add_argument("--duration", type=float, default=20, help="scan seconds (default 20)")
    ap.add_argument("--demo", action="store_true", help="use sample data, no Bluetooth")
    ap.add_argument("--audit", metavar="ADDRESS", help="read-only GATT audit of YOUR device")
    ap.add_argument("--json", help="save report as JSON")
    ap.add_argument("--csv", help="save report as CSV")
    args = ap.parse_args()

    if args.audit:
        ok = input(f"Audit connects to {args.audit}. Do you own it or have permission? "
                   "[y/N]: ").strip().lower()
        if ok != "y":
            print("Cancelled.")
            return
        report_audit(await audit(args.audit))
        return

    devs = demo_devices() if args.demo else await scan(args.duration)
    if not devs:
        print("No Bluetooth LE devices found.")
        return
    report([assess(d) for d in devs], args)


if __name__ == "__main__":
    asyncio.run(main())
