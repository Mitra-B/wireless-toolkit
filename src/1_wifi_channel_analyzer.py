"""
Project 1: Real-Time Wi-Fi Spectrum & Channel Congestion Analyzer
Install: pip install matplotlib pywifi
Run:     python 1_wifi_channel_analyzer.py
(Needs a Wi-Fi adapter; on Linux run with sudo or proper permissions.)
"""
import time
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import pywifi

NON_OVERLAP_24 = [1, 6, 11]
CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116,
              120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]


def freq_to_channel(freq):
    """pywifi reports freq in kHz on most platforms; handle MHz too."""
    if freq > 100000:
        freq //= 1000
    if freq == 2484:
        return 14, "2.4"
    if 2400 <= freq < 2500:
        return (freq - 2407) // 5, "2.4"
    if 4900 <= freq < 5900:
        return (freq - 5000) // 5, "5"
    return None, None


def scan(iface, wait=3):
    iface.scan()
    time.sleep(wait)
    aps = []
    for r in iface.scan_results():
        ch, band = freq_to_channel(r.freq)
        if ch is None:
            continue
        aps.append({"ssid": r.ssid or "<hidden>", "channel": ch,
                    "band": band, "rssi": r.signal})
    return aps


def rssi_weight(rssi):
    """Map RSSI (-100..-30 dBm) to a 0..1 interference weight."""
    return max(0.0, min(1.0, (rssi + 100) / 70))


def congestion_24(aps):
    """2.4 GHz channels are 5 MHz apart but 20 MHz wide -> channels within
    +/-4 overlap. Score each channel by weighted interference."""
    scores = {c: 0.0 for c in CHANNELS_24}
    for ap in aps:
        if ap["band"] != "2.4":
            continue
        for c in CHANNELS_24:
            sep = abs(c - ap["channel"])
            if sep < 5:
                overlap = 1 - sep / 5          # 1.0 co-channel, 0.2 at sep 4
                scores[c] += rssi_weight(ap["rssi"]) * overlap
    return scores


def congestion_5(aps):
    scores = {c: 0.0 for c in CHANNELS_5}
    for ap in aps:
        if ap["band"] == "5" and ap["channel"] in scores:
            scores[ap["channel"]] += rssi_weight(ap["rssi"])
    return scores


def recommend(s24, s5):
    best24 = min(NON_OVERLAP_24, key=lambda c: s24[c])
    best5 = min(s5, key=lambda c: s5[c])
    return best24, best5


def colors(scores, threshold):
    return ["#d9534f" if v >= threshold else "#f0ad4e" if v >= threshold / 2
            else "#5cb85c" for v in scores.values()]


def main():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 8))

    def update(_):
        aps = scan(iface)
        s24, s5 = congestion_24(aps), congestion_5(aps)
        b24, b5 = recommend(s24, s5)

        ax1.clear()
        ax1.bar(s24.keys(), s24.values(), color=colors(s24, 2.0))
        ax1.set_xticks(CHANNELS_24)
        ax1.set_title(f"2.4 GHz congestion  |  Recommended channel: {b24}")
        ax1.set_ylabel("Weighted interference")

        ax2.clear()
        ax2.bar([str(c) for c in s5], list(s5.values()), color=colors(s5, 1.5))
        ax2.set_title(f"5 GHz congestion  |  Recommended channel: {b5}")
        ax2.set_ylabel("Weighted interference")
        ax2.tick_params(axis="x", rotation=60)

        print(f"\n{len(aps)} APs found. Best 2.4 GHz: ch {b24}, best 5 GHz: ch {b5}")
        fig.tight_layout()

    _ = animation.FuncAnimation(fig, update, interval=6000, cache_frame_data=False)
    plt.show()


if __name__ == "__main__":
    main()
