#!/usr/bin/env python3
import subprocess
import re
from pathlib import Path

# Use a headless backend (important for VMs/servers with no GUI)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# -------------------- CONFIG --------------------
PIN_PATH = str(Path.home() / "Documents/pin-3.30-98830-g1d7b601b3-gcc-linux/pin")
PINTOOL_SO = "project.so"               # change if needed
CC1_BIN = "./cc1"                       # assumes you run in the folder with cc1
CC1_ARG = "expr.i"
TIME_BIN = "/usr/bin/time"
THRESHOLD_KNOB = "-prof_threshold"      # correct knob name
PROF_TIMES = [4, 2, 1, 8]
THRESHOLDS = [0, 20, 60, 80, "default95", 100]  # "default95" => omit knob (95%)
OUT_IMG = "performance_all_in_one.png"
TITLE = "Performance vs. de-virtualization threshold (pintool shows real − create_tc)"
# ------------------------------------------------

REAL_RE = re.compile(r"^real\s+([0-9]+(?:\.[0-9]+)?)$", re.M)
CREATE_TC_RE = re.compile(r"create_tc\s+took:\s*([0-9]+(?:\.[0-9]+)?)\s*seconds", re.I)

def run_and_parse(cmd_list):
    """
    Run /usr/bin/time -p <cmd>.
    Returns:
      real_s (float), create_tc_s (float), full_stderr (str), full_stdout (str)
    """
    full_cmd = [TIME_BIN, "-p"] + cmd_list
    proc = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Parse real time from /usr/bin/time output (on stderr)
    m_real = REAL_RE.search(proc.stderr)
    if not m_real:
        raise RuntimeError(
            f"Failed to parse 'real' time.\nCMD: {' '.join(full_cmd)}\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}"
        )
    real_s = float(m_real.group(1))

    # Parse create_tc time if present in the same stderr stream
    # (use the last match if multiple lines appear)
    create_matches = CREATE_TC_RE.findall(proc.stderr)
    create_tc_s = float(create_matches[-1]) if create_matches else 0.0

    return real_s, create_tc_s, proc.stderr, proc.stdout

def baseline_time():
    real_s, _, _, _ = run_and_parse([CC1_BIN, CC1_ARG])
    return real_s

def run_with_pintool(prof_time, threshold):
    cmd = [
        PIN_PATH, "-t", PINTOOL_SO,
        "-create_tc2",
        "-prof_time", str(prof_time),
    ]
    if threshold != "default95":
        cmd += [THRESHOLD_KNOB, str(threshold)]
    cmd += ["--", CC1_BIN, CC1_ARG]

    real_s, ctc_s, _, _ = run_and_parse(cmd)
    adjusted = max(real_s - ctc_s, 0.0)  # guard against tiny negatives
    return real_s, ctc_s, adjusted

def main():
    here = Path.cwd()
    print("Measuring baseline (no pintool)...")
    base = baseline_time()
    print(f"Baseline real time: {base:.3f}s")

    # Collect data for each prof_time
    # Store adjusted times (real - create_tc) for pintool lines
    results = {}  # prof_time -> (x_thresholds, y_adjusted_times)
    for pt in PROF_TIMES:
        print(f"\n=== prof_time={pt} ===")
        xs, ys_adj = [], []
        for thr in THRESHOLDS:
            label_thr = 95 if thr == "default95" else int(thr)
            disp = f"default(95, omit {THRESHOLD_KNOB})" if thr == "default95" else str(label_thr)
            print(f"  threshold={disp} ...", end="", flush=True)

            real_s, ctc_s, adj_s = run_with_pintool(pt, thr)
            print(f" real={real_s:.3f}s, create_tc={ctc_s:.3f}s, adj={adj_s:.3f}s")

            xs.append(label_thr)
            ys_adj.append(adj_s)

        # keep them sorted by X just in case
        xs, ys_adj = zip(*sorted(zip(xs, ys_adj), key=lambda p: p[0]))
        results[pt] = (list(xs), list(ys_adj))

    # ---------- Plot all on ONE figure ----------
    plt.figure(figsize=(9, 6))

    # Baseline flat line across the union of all X points (0..100)
    all_xs = sorted(set(x for pt in results for x in results[pt][0]))
    if not all_xs:
        all_xs = [0, 20, 40, 60, 80, 100]
    plt.plot(all_xs, [base] * len(all_xs), linestyle="--", linewidth=2, label="Baseline (no pintool, real)")

    # Plot each prof_time curve (adjusted times)
    for pt in sorted(results.keys()):
        xs, ys = results[pt]
        plt.plot(xs, ys, marker="o", linewidth=2, label=f"pintool (prof_time={pt}s, real − create_tc)")

    plt.xlabel("De-virtualization threshold (%)")
    plt.ylabel("Time (seconds)")
    plt.title(TITLE)
    plt.grid(True, which="both", linestyle=":")
    plt.xticks([0, 20, 60, 80, 95, 100])
    plt.legend()
    plt.tight_layout()
    plt.savefig(here / OUT_IMG, dpi=200)
    print(f"\nSaved: {OUT_IMG}")

if __name__ == "__main__":
    main()

