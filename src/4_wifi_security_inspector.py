"""
Project 4: Wireless Network Security & Protocol Inspector
Install: pip install pywifi tabulate
Run:     python 4_wifi_security_inspector.py [--csv report.csv]

Passive scan only: reads the beacon/probe info your adapter already receives.
Only audit networks you own or are authorised to assess.

Note: pywifi exposes AKM types up to WPA2-PSK. WPA3 (SAE) and Enterprise
(802.1X) are often reported as UNKNOWN, so those are flagged as
"Unknown/newer suite (possibly WPA3 or Enterprise)" rather than guessed.
"""
import argparse
import csv
import time

import pywifi
from pywifi import const
from tabulate import tabulate

AKM_NAMES = {
    const.AKM_TYPE_NONE: "Open",
    const.AKM_TYPE_WPA: "WPA-Enterprise",
    const.AKM_TYPE_WPAPSK: "WPA-PSK",
    const.AKM_TYPE_WPA2: "WPA2-Enterprise",
    const.AKM_TYPE_WPA2PSK: "WPA2-PSK",
    const.AKM_TYPE_UNKNOWN: "Unknown/newer (WPA3 or Enterprise?)",
}
CIPHER_NAMES = {
    const.CIPHER_TYPE_NONE: "None",
    const.CIPHER_TYPE_WEP: "WEP",
    const.CIPHER_TYPE_TKIP: "TKIP",
    const.CIPHER_TYPE_CCMP: "CCMP/AES",
    const.CIPHER_TYPE_UNKNOWN: "Unknown",
}


def as_list(x):
    """pywifi gives a list on some platforms and a single int on others
    (e.g. Windows). Normalise to a list."""
    if x is None:
        return []
    if isinstance(x, (list, tuple, set)):
        return list(x)
    return [x]


def band_of(freq):
    f = freq // 1000 if freq > 100000 else freq
    return "2.4 GHz" if f < 3000 else "5 GHz" if f < 5900 else "6 GHz"


def assess(akms, ciphers, ssid):
    """Return (rating, list_of_findings)."""
    findings = []
    akms = set(akms) or {const.AKM_TYPE_NONE}
    ciphers = set(ciphers)

    if akms == {const.AKM_TYPE_NONE}:
        if const.CIPHER_TYPE_WEP in ciphers:
            findings.append("WEP encryption - trivially crackable")
            return "CRITICAL", findings
        findings.append("Open network - traffic is unencrypted")
        return "HIGH RISK", findings

    if const.CIPHER_TYPE_WEP in ciphers:
        findings.append("WEP cipher in use - obsolete and broken")
        return "CRITICAL", findings

    rating = "GOOD"
    if const.AKM_TYPE_WPA in akms or const.AKM_TYPE_WPAPSK in akms:
        findings.append("Legacy WPA (v1) advertised - upgrade to WPA2/WPA3")
        rating = "WEAK"
    if const.CIPHER_TYPE_TKIP in ciphers:
        findings.append("TKIP cipher enabled - deprecated, prefer CCMP/AES")
        rating = "WEAK" if rating == "GOOD" else rating
    if (const.AKM_TYPE_WPA2PSK in akms and
            const.CIPHER_TYPE_CCMP in ciphers and not findings):
        findings.append("WPA2-PSK/AES - acceptable; WPA3 preferred")
        rating = "MODERATE"
    if const.AKM_TYPE_UNKNOWN in akms:
        findings.append("Newer suite (likely WPA3/Enterprise) - verify manually")
        rating = "GOOD" if not findings[:-1] else rating
    if not ssid:
        findings.append("Hidden SSID - gives no real security benefit")
    return rating, findings or ["No issues detected"]


def scan(wait=4):
    iface = pywifi.PyWiFi().interfaces()[0]
    iface.scan()
    time.sleep(wait)
    seen, rows = set(), []
    for r in iface.scan_results():
        key = (r.bssid, r.ssid)
        if key in seen:
            continue
        seen.add(key)
        akms = as_list(r.akm)
        ciphers = as_list(r.cipher)
        rating, findings = assess(akms, ciphers, r.ssid)
        rows.append({
            "SSID": r.ssid or "<hidden>",
            "BSSID": r.bssid,
            "Band": band_of(r.freq),
            "RSSI": r.signal,
            "Auth": ", ".join(sorted({AKM_NAMES.get(a, str(a)) for a in akms}))
                    or "Open",
            "Cipher": ", ".join(sorted({CIPHER_NAMES.get(c, str(c)) for c in ciphers}))
                      or "None",
            "Rating": rating,
            "Findings": "; ".join(findings),
        })
    order = {"CRITICAL": 0, "HIGH RISK": 1, "WEAK": 2, "MODERATE": 3, "GOOD": 4}
    return sorted(rows, key=lambda x: order[x["Rating"]])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="Also save the report to a CSV file")
    args = ap.parse_args()

    rows = scan()
    if not rows:
        print("No networks found.")
        return
    print("\n=== Wireless Security Audit Report ===\n")
    print(tabulate([[r[k] for k in ("SSID", "Band", "RSSI", "Auth", "Cipher", "Rating")]
                    for r in rows],
                   headers=["SSID", "Band", "RSSI", "Auth", "Cipher", "Rating"],
                   tablefmt="grid"))
    print("\n--- Findings ---")
    for r in rows:
        if r["Rating"] in ("CRITICAL", "HIGH RISK", "WEAK"):
            print(f"[{r['Rating']}] {r['SSID']} ({r['BSSID']}): {r['Findings']}")
    bad = sum(r["Rating"] in ("CRITICAL", "HIGH RISK", "WEAK") for r in rows)
    print(f"\nSummary: {len(rows)} networks, {bad} with weak/no security.")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        print(f"Saved report to {args.csv}")


if __name__ == "__main__":
    main()
