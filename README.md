# Smart Wireless Network Management System

A collection of six Python tools for wireless network analysis, monitoring, simulation and security assessment. The platform covers Wi-Fi channel congestion, live link quality, path-loss modelling, Wi-Fi security inspection, Bluetooth Low Energy (BLE) device discovery and BLE security assessment.

Built as a Wireless Technologies mini-project. Each tool is a self-contained Python script in `src/`.

## Tools

| # | Script | What it does | Needs hardware? |
|---|--------|--------------|-----------------|
| 1 | `1_wifi_channel_analyzer.py` | Scans nearby access points, scores congestion on every 2.4 GHz and 5 GHz channel, plots live bar charts and recommends the best channel. | Wi-Fi adapter |
| 2 | `2_wifi_link_quality_tracker.py` | CustomTkinter dashboard plotting live RSSI, gateway ping latency and packet loss. Mark locations while walking to find dead zones. | Wi-Fi adapter |
| 3 | `3_path_loss_simulator.py` | Log-distance path loss model for 2.4 / 5 / 6 GHz with obstacle losses. Graphs signal decay and computes maximum coverage radius. | No |
| 4 | `4_wifi_security_inspector.py` | Passive scan of nearby networks. Rates their encryption (Open, WEP, WPA, WPA2, TKIP vs AES) and prints an audit report. | Wi-Fi adapter |
| 5 | `5_ble_device_finder.py` | Discovers nearby BLE devices and estimates distance from RSSI. | Bluetooth adapter |
| 6 | `6_bluetooth_security_assessment.py` | Scans nearby Bluetooth Low Energy devices, examines advertising information and available GATT services and characteristics, and identifies potential security concerns based on observable device properties. | Bluetooth adapter |

## Quick Start

```bash
git clone https://github.com/Mitra-B/wireless-toolkit.git
cd wireless-toolkit
pip install -r requirements.txt
python src/3_path_loss_simulator.py --interactive
```

On Windows use `py` instead of `python` if `python` is not recognized. On Linux the Wi-Fi scanners (1, 2, 4) usually need `sudo`, and you may need `--break-system-packages` with pip.

## Usage

```bash
python src/1_wifi_channel_analyzer.py
python src/2_wifi_link_quality_tracker.py
python src/3_path_loss_simulator.py --tx 20 --env indoor_nlos --obstacles concrete drywall
python src/4_wifi_security_inspector.py --csv report.csv
python src/5_ble_device_finder.py --time 10 --loop
python src/6_bluetooth_security_assessment.py
```

## Path Loss Simulator Options

| Option | Meaning | Default |
|--------|---------|---------|
| `--tx` | Transmit power (dBm) | 20 |
| `--env` | `free_space`, `open_office`, `indoor_los`, `indoor_nlos`, `dense_indoor` | `open_office` |
| `--n` | Custom path-loss exponent (overrides `--env`) | - |
| `--obstacles` | Any of `none drywall glass wood brick concrete` | none |
| `--sensitivity` | Receiver sensitivity (dBm) | -82 |
| `--gt`, `--gr` | Tx / Rx antenna gain (dBi) | 0 |
| `--interactive` | Prompt for inputs | off |

## BLE Finder Options

`--time` scan seconds (default 8), `--n` path-loss exponent (default 2.5), `--loop` scan continuously.

## Bluetooth Security Assessment

The Bluetooth Security Assessment module performs a passive discovery of nearby BLE devices and examines available device information.

- Discovers nearby BLE devices.
- Inspects available advertising data.
- Discovers GATT services and characteristics where supported.
- Examines characteristic properties and permissions.
- Highlights potential security concerns based on the information available.

The assessment is limited to information exposed by discoverable BLE devices and accessible GATT services. It is not a complete Bluetooth penetration test.

## Theory

**Log-distance path loss** (tools 3 and 5):

```text
PL(d) = PL(d0) + 10 * n * log10(d / d0) + sum(obstacle losses)    [dB]
Pr(d) = Ptx + Gtx + Grx - PL(d)
```

- `PL(d0)` is free-space path loss at the 1 m reference distance.
- `n` is the path-loss exponent: about 2 in free space and 2.5 to 4 indoors.
- Maximum range is the distance where `Pr(d)` falls to the receiver sensitivity.

**BLE distance estimate:** `d = 10 ** ((TxPower_1m - RSSI) / (10 * n))`

**Channel congestion** (tool 1): 2.4 GHz channels are 5 MHz apart but about 20 MHz wide, so channels within 4 of each other overlap. Each access point adds interference to every overlapping channel, weighted by its signal strength. Only channels 1, 6 and 11 are recommended because they do not overlap.

## Platform Notes and Limitations

- **Windows:** `pywifi` works but may report WPA3 / Enterprise networks as "Unknown". `netsh` only gives signal as a percentage, so tool 2 converts it to approximate dBm. Bluetooth must be turned on for tools 5 and 6.
- **Linux:** Needs root for `pywifi`. Tool 2 needs the `iw` package.
- **macOS:** Recent versions removed the `airport` tool, so tools 1, 2 and 4 may return no data. Tools 3 and 5 work.
- **Virtual machines:** Cannot scan Wi-Fi. Run on the host.
- RSSI-based distances are rough estimates. Walls, furniture and people change real signals.
- BLE security findings depend on the advertising data and GATT information exposed by the device.

## Testing

See [docs/TESTING.md](docs/TESTING.md) for test cases and expected results.

## Ethics

Tools 4 and 6 are intended for passive inspection and authorised assessment only. Only audit networks and Bluetooth devices you own or have permission to assess.

## License

MIT. See [LICENSE](LICENSE).