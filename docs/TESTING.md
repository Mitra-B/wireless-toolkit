# Testing Guide

## Tool 3: Path loss simulator (deterministic)

| Test | Command | Expected |
|------|---------|----------|
| Free space | `python src/3_path_loss_simulator.py --env free_space --tx 20` | Very long ranges (hundreds of metres to over 1 km). 2.4 GHz reaches farthest. |
| Open office | `--env open_office --tx 20` | Much shorter ranges than free space. |
| Heavy walls | `--env indoor_nlos --obstacles concrete` | Ranges of roughly 10 to 30 m. |
| Multiple walls | `--obstacles brick drywall glass` | Range shorter than with a single wall. |
| Low power | `--tx 10` | All ranges shrink compared with 20 dBm. |
| Antenna gain | `--gt 5 --gr 2` | Ranges increase. |
| Custom exponent | `--n 3.0` | Overrides `--env`. |
| Interactive | `--interactive`, then `20`, `indoor_nlos`, `concrete drywall`, `-82` | Table and chart. |

**Invariants:** higher frequency gives shorter range, and more obstacles give shorter range.

## Tool 1: Channel analyzer

- Run it; the charts refresh every few seconds.
- Compare the recommended channel with your own router's channel.
- Turn on a phone hotspot nearby and confirm one channel's bar rises.

## Tool 2: Link quality tracker

1. Stand next to the router and click **Mark Location** with name "Router".
2. Repeat in a far room and the farthest corner.
3. Expected: "Router" has the strongest RSSI; locations below -75 dBm show `DEAD ZONE`.
4. Leaving the name blank gives `Spot 1`, `Spot 2`, and so on.

## Tool 4: Security inspector

- Run it and check the table prints.
- Run with `--csv report.csv` and confirm the file is created.
- Enable a phone hotspot with "Open" security; it should rate `HIGH RISK`.

## Tool 5: BLE finder

- Turn on Bluetooth on the laptop and a phone (screen on).
- Scan with the phone beside the laptop, then about 5 m away. RSSI should drop and the estimated distance should grow.
- Try `--n 2.0` and `--n 4.0` to see the distance estimate change.

## Known issues

- `BleakBluetoothNotAvailableError` means Bluetooth is turned off.
- `IndexError` on `interfaces()[0]` means no Wi-Fi adapter was found (or you are in a VM).
- WPA3 / Enterprise networks may show as "Unknown/newer" because of `pywifi` limits.
