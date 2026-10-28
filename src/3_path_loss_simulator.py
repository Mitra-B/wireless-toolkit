"""
Project 3: Log-Distance Path Loss & Wireless Coverage Simulator
Install: pip install numpy matplotlib
Run:     python 3_path_loss_simulator.py
         python 3_path_loss_simulator.py --tx 20 --obstacles concrete drywall
         python 3_path_loss_simulator.py --interactive

Model:
  PL(d) = PL(d0) + 10 * n * log10(d / d0) + sum(obstacle losses)   [dB]
  PL(d0) = free-space path loss at d0 = 1 m = 20log10(f_MHz) - 28.0
  Pr(d)  = Ptx + Gtx + Grx - PL(d)
"""
import argparse
import numpy as np
import matplotlib.pyplot as plt

D0 = 1.0  # reference distance in metres

# Approximate per-obstacle attenuation (dB) by band - typical literature values
OBSTACLES = {
    "none":     {2.4: 0.0,  5.0: 0.0,  6.0: 0.0},
    "drywall":  {2.4: 3.0,  5.0: 4.0,  6.0: 5.0},
    "glass":    {2.4: 2.0,  5.0: 3.0,  6.0: 4.0},
    "wood":     {2.4: 4.0,  5.0: 6.0,  6.0: 7.0},
    "brick":    {2.4: 8.0,  5.0: 11.0, 6.0: 13.0},
    "concrete": {2.4: 12.0, 5.0: 17.0, 6.0: 20.0},
}

# Path loss exponents for common environments
ENVIRONMENTS = {"free_space": 2.0, "open_office": 2.5, "indoor_los": 1.8,
                "indoor_nlos": 3.5, "dense_indoor": 4.0}

BAND_MHZ = {2.4: 2437, 5.0: 5500, 6.0: 6000}


def fspl_d0(freq_mhz):
    """Free-space path loss at 1 m (dB)."""
    return 20 * np.log10(freq_mhz) + 20 * np.log10(D0 / 1000.0) + 32.44


def path_loss(d, band, n, obstacles):
    extra = sum(OBSTACLES[o][band] for o in obstacles)
    d = np.maximum(d, D0)
    return fspl_d0(BAND_MHZ[band]) + 10 * n * np.log10(d / D0) + extra


def rx_power(d, tx_dbm, band, n, obstacles, gt=0.0, gr=0.0):
    return tx_dbm + gt + gr - path_loss(d, band, n, obstacles)


def max_radius(tx_dbm, band, n, obstacles, sensitivity, gt=0.0, gr=0.0):
    """Closed-form distance where Pr == sensitivity."""
    extra = sum(OBSTACLES[o][band] for o in obstacles)
    budget = tx_dbm + gt + gr - sensitivity - fspl_d0(BAND_MHZ[band]) - extra
    return D0 * 10 ** (budget / (10 * n))


def simulate(tx, n, obstacles, sensitivity, gt, gr, max_d=100):
    d = np.linspace(1, max_d, 500)
    plt.figure(figsize=(10, 6))
    print(f"\nTx={tx} dBm  n={n}  obstacles={obstacles}  sensitivity={sensitivity} dBm")
    print(f"{'Band':<8}{'Path loss @10m':>16}{'Pr @10m':>10}{'Max radius':>14}")
    for band, color in zip(BAND_MHZ, ["tab:blue", "tab:green", "tab:red"]):
        pr = rx_power(d, tx, band, n, obstacles, gt, gr)
        r = max_radius(tx, band, n, obstacles, sensitivity, gt, gr)
        plt.plot(d, pr, color=color, label=f"{band} GHz (range {r:.1f} m)")
        plt.axvline(r, color=color, ls=":", alpha=0.6)
        print(f"{band:<8}{path_loss(10, band, n, obstacles):>13.1f} dB"
              f"{rx_power(10, tx, band, n, obstacles, gt, gr):>7.1f} dBm{r:>11.1f} m")
    plt.axhline(sensitivity, color="k", ls="--", label=f"Sensitivity {sensitivity} dBm")
    plt.xlabel("Distance (m)")
    plt.ylabel("Received power (dBm)")
    plt.title("Log-Distance Path Loss - Signal Decay by Band")
    plt.ylim(sensitivity - 20, tx)
    plt.grid(alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.show()


def pick(prompt, options):
    print(f"{prompt} {list(options)}")
    return input("> ").strip()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tx", type=float, default=20, help="Tx power in dBm")
    p.add_argument("--n", type=float, default=None, help="Path loss exponent")
    p.add_argument("--env", default="open_office", choices=ENVIRONMENTS)
    p.add_argument("--obstacles", nargs="*", default=[], choices=list(OBSTACLES))
    p.add_argument("--sensitivity", type=float, default=-82, help="Rx sensitivity dBm")
    p.add_argument("--gt", type=float, default=0.0, help="Tx antenna gain dBi")
    p.add_argument("--gr", type=float, default=0.0, help="Rx antenna gain dBi")
    p.add_argument("--interactive", action="store_true")
    a = p.parse_args()

    if a.interactive:
        a.tx = float(input("Tx power (dBm) [20]: ") or 20)
        a.env = pick("Environment", ENVIRONMENTS) or "open_office"
        a.obstacles = input(f"Obstacles (space separated) {list(OBSTACLES)}: ").split()
        a.sensitivity = float(input("Rx sensitivity (dBm) [-82]: ") or -82)

    n = a.n if a.n is not None else ENVIRONMENTS[a.env]
    simulate(a.tx, n, a.obstacles, a.sensitivity, a.gt, a.gr)


if __name__ == "__main__":
    main()
