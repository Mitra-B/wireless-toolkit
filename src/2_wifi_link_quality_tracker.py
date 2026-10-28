"""
Project 2: Live Wi-Fi Signal Heatmapper & Link Quality Tracker
Install: pip install customtkinter matplotlib
Run:     python 2_wifi_link_quality_tracker.py
Walk around with your laptop, press "Mark Location" at each spot, and
review the per-location signal summary to find dead zones.
"""
import platform
import re
import subprocess
import threading
import time
from collections import deque

import customtkinter as ctk
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

SYSTEM = platform.system()
DEAD_ZONE_DBM = -75
HISTORY = 120


def get_rssi():
    """Return current RSSI in dBm, or None."""
    try:
        if SYSTEM == "Windows":
            out = subprocess.check_output(["netsh", "wlan", "show", "interfaces"],
                                          text=True, errors="ignore")
            m = re.search(r"Signal\s*:\s*(\d+)%", out)
            if m:  # convert % quality to approximate dBm
                return int(m.group(1)) / 2 - 100
        elif SYSTEM == "Linux":
            out = subprocess.check_output(["iw", "dev"], text=True)
            iface = re.search(r"Interface\s+(\S+)", out).group(1)
            out = subprocess.check_output(["iw", "dev", iface, "link"], text=True)
            m = re.search(r"signal:\s*(-?\d+)", out)
            if m:
                return int(m.group(1))
        elif SYSTEM == "Darwin":
            airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
                       "Versions/Current/Resources/airport")
            out = subprocess.check_output([airport, "-I"], text=True)
            m = re.search(r"agrCtlRSSI:\s*(-?\d+)", out)
            if m:
                return int(m.group(1))
    except Exception:
        pass
    return None


def get_gateway():
    try:
        if SYSTEM == "Windows":
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            m = re.search(r"Default Gateway[ .]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
        elif SYSTEM == "Linux":
            out = subprocess.check_output(["ip", "route"], text=True)
            m = re.search(r"default via (\S+)", out)
        else:
            out = subprocess.check_output(["route", "-n", "get", "default"], text=True)
            m = re.search(r"gateway:\s*(\S+)", out)
        return m.group(1) if m else "8.8.8.8"
    except Exception:
        return "8.8.8.8"


def ping(host, count=3):
    """Return (avg latency ms or None, loss %)."""
    flag = "-n" if SYSTEM == "Windows" else "-c"
    try:
        out = subprocess.run(["ping", flag, str(count), host], capture_output=True,
                             text=True, timeout=10).stdout
    except Exception:
        return None, 100.0
    loss = re.search(r"(\d+(?:\.\d+)?)%", out)
    loss = float(loss.group(1)) if loss else 100.0
    lat = re.findall(r"time[=<]\s*([\d.]+)", out)
    avg = sum(map(float, lat)) / len(lat) if lat else None
    return avg, loss


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Wi-Fi Link Quality Tracker")
        self.geometry("1000x720")
        self.gateway = get_gateway()
        self.rssi = deque(maxlen=HISTORY)
        self.lat = deque(maxlen=HISTORY)
        self.loss = deque(maxlen=HISTORY)
        self.marks = []          # (label, avg_rssi)
        self.running = True

        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=10)
        self.lbl = ctk.CTkLabel(top, text="Starting...", font=("Arial", 18))
        self.lbl.pack(side="left", padx=10)
        self.entry = ctk.CTkEntry(top, placeholder_text="Location name", width=160)
        self.entry.pack(side="right", padx=5)
        ctk.CTkButton(top, text="Mark Location", command=self.mark).pack(side="right")

        self.fig = Figure(figsize=(9, 5.5))
        self.ax1 = self.fig.add_subplot(211)
        self.ax2 = self.fig.add_subplot(212)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10)

        self.log = ctk.CTkTextbox(self, height=120)
        self.log.pack(fill="x", padx=10, pady=10)

        threading.Thread(target=self.poll, daemon=True).start()
        self.after(1000, self.redraw)
        self.protocol("WM_DELETE_WINDOW", self.close)

    def poll(self):
        while self.running:
            r = get_rssi()
            l, p = ping(self.gateway)
            self.rssi.append(r if r is not None else float("nan"))
            self.lat.append(l if l is not None else float("nan"))
            self.loss.append(p)
            time.sleep(1)

    def mark(self):
        vals = [v for v in list(self.rssi)[-5:] if v == v]
        if not vals:
            return
        avg = sum(vals) / len(vals)
        name = self.entry.get() or f"Spot {len(self.marks) + 1}"
        status = "DEAD ZONE" if avg < DEAD_ZONE_DBM else "OK"
        self.marks.append((name, avg))
        self.log.insert("end", f"{name}: {avg:.0f} dBm  [{status}]\n")
        self.log.see("end")

    def redraw(self):
        if self.rssi:
            r = self.rssi[-1]
            self.lbl.configure(text=f"RSSI {r:.0f} dBm | Ping "
                               f"{self.lat[-1]:.0f} ms | Loss {self.loss[-1]:.0f}%"
                               f" | GW {self.gateway}")
        self.ax1.clear()
        self.ax1.plot(list(self.rssi), color="tab:blue")
        self.ax1.axhline(DEAD_ZONE_DBM, color="red", ls="--", label="Dead-zone threshold")
        self.ax1.set_ylabel("RSSI (dBm)")
        self.ax1.set_ylim(-100, -20)
        self.ax1.legend(loc="lower left")
        self.ax2.clear()
        self.ax2.plot(list(self.lat), color="tab:orange", label="Latency (ms)")
        self.ax2.plot(list(self.loss), color="tab:red", label="Loss (%)")
        self.ax2.legend(loc="upper left")
        self.fig.tight_layout()
        self.canvas.draw_idle()
        if self.running:
            self.after(1000, self.redraw)

    def close(self):
        self.running = False
        self.destroy()


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    App().mainloop()
