#!/usr/bin/env python3
import os
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, FormatStrFormatter, NullFormatter

ORDER = ["baseline","ML-KEM-768","X-Wing","HQC-3"]
COLOR = {"baseline": "#52514e", "ML-KEM-768": "#2a78d6", "X-Wing": "#eb6834", "HQC-3": "#1baf7a"}
INK, MUTED, GRID, AXIS = "#0b0b0b", "#52514e", "#e1e0d9", "#c3c2b7"
REC_OVERHEAD = 27
BASELINE_AUTH = 293 + 71

plt.rcParams.update({
  "font.size": 9, "axes.edgecolor": AXIS, "axes.labelcolor": MUTED,
  "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False,
  "axes.spines.right": False, "axes.grid": True, "axes.axisbelow": True, "grid.color": GRID,
  "grid.linewidth": 0.6, "savefig.dpi": 300, "savefig.bbox": "tight",
})

def load(path):
  df = pd.read_csv(path)
  return df[df["warmup"] == 0]

def med(df, config, role, col):
  return df[(df["config"] == config) & (df["role"] == role)][col].median()

def log_axis(axis):
  axis.set_major_locator(LogLocator(subs=(1, 2, 5)))
  axis.set_major_formatter(FormatStrFormatter("%g"))
  axis.set_minor_formatter(NullFormatter())

def latency(profiles, col, ylabel, out):
  fig, axes = plt.subplots(1, len(profiles), figsize=(3.2 * len(profiles), 3.0), squeeze=False)
  for ax, (name, df) in  zip(axes[0], profiles):
    pub = df[df["role"] == "publisher"]
    rng = np.random.default_rng(0)
    for i, c in enumerate(ORDER, start=1):
      v = pub[pub["config"] == c][col]/1e6
      x = i + rng.uniform(-0.15, 0.15, len(v))
      ax.scatter(x, v, s=12, color=COLOR[c], alpha=0.7, linewidths=0, zorder=2)
      ax.hlines(v.median(), i - 0.3, i + 0.3, color=INK, linewidth=1.5, zorder=3)
    ax.set_yscale("log")
    log_axis(ax.yaxis)
    ax.set_xticks(range(1, len(ORDER) + 1), ORDER, rotation=20)
    ax.set_title(name, color=INK)
    ax.grid(axis="x", visible=False)
  axes[0][0].set_ylabel(ylabel)
  fig.savefig(out)
  plt.close(fig)

def cpu(df, out):
  fig, ax = plt.subplots(figsize=(5.5, 2.4))
  y = list (range(len(ORDER)))
  for role, face in (("gateway",INK), ("publisher","white")):
    x = [med(df, c, role, "cpu_ns")/1e6 for c in ORDER]
    ax.scatter(x, y, s=45, facecolor=face, edgecolor=INK, label=role, zorder=3)
  ax.set_xscale("log")
  log_axis(ax.xaxis)
  ax.set_yticks(y, ORDER)
  ax.invert_yaxis()
  ax.grid(axis="y", visible=False)
  ax.set_xlabel("CPU time per handshake, median (ms, log scale)")
  ax.legend(frameon=False, ncol=2, loc="lower left", bbox_to_anchor=(0, 1))
  fig.savefig(out)
  plt.close(fig)
  
def handshake_bytes(df, out):
  auth, rest = [], []
  for c in ORDER:
    total = med(df, c, "gateway", "bytes_total") + med(df, c, "publisher", "bytes_total")
    if c == "baseline":
      a = BASELINE_AUTH
    else:
      a = (med(df, c, "gateway", "bytes_server_auth") - REC_OVERHEAD + med(df, c, "publisher", "bytes_client_auth") - REC_OVERHEAD)
    auth.append(a)
    rest.append(total - a)
  fig, ax = plt.subplots(figsize=(5.5, 2.4))
  y = list(range(len(ORDER)))
  ax.barh(y, auth, height=0.6, color=MUTED, edgecolor="white", label="authentication data")
  ax.barh(y, rest, left=auth,height=0.6, color=AXIS, edgecolor="white", label="rest of handshake")
  for i in y:
    total = auth[i] + rest[i]
    ax.text(total, i, f"  {total:,.0f} B ({100 * auth[i]/total:.0f}% auth)", va="center", color=INK)
  ax.set_xlim(0, 1.35 * max(a + r for a, r in zip(auth, rest)))
  ax.set_yticks(y, ORDER)
  ax.invert_yaxis()
  ax.grid(axis="y", visible=False)
  ax.set_xlabel("handshake bytes, both directions")
  ax.legend(frameon=False, ncol=2, loc="lower left", bbox_to_anchor=(0, 1))
  fig.savefig(out)
  plt.close(fig)

def ablation(name, df, out):
  fig, ax = plt.subplots(figsize=(5.5, 2.2))
  kems = [c for c in ORDER if c!= "baseline"]
  y = list(range(len(kems)))
  with_ed = [med(df, c, "publisher", "puback_ns")/1e6 for c in kems]
  without = [med(df, c + "-noed", "publisher", "puback_ns")/1e6 for c in kems]
  ax.hlines(y, with_ed, without, color=AXIS, linewidth=2, zorder=1)
  ax.scatter(with_ed, y, s=45, color=INK, label="early data", zorder=3)
  ax.scatter(without, y, s=45, facecolor="white", edgecolor=INK, label="no early data", zorder=3)
  for i in y:
    ax.text(without[i], i, f" +{without[i] - with_ed[i]:.0f} ms", va="center", color=INK)
  base = med(df, "baseline", "publisher", "puback_ns")/1e6
  ax.axvline(base, color=MUTED, linestyle="--", linewidth=1, zorder=0)
  ax.text(base, -0.85, " baseline", color=MUTED, va="top")
  ax.set_xlim(0.95 * min(with_ed + [base]), 1.12 * max(without))
  ax.set_yticks(y, kems)
  ax.set_ylim(len(kems) - 0.5, -0.9)
  ax.grid(axis="y", visible=False)
  ax.set_xlabel(f"connect to PUBACK, median (ms), {name}")
  ax.legend(frameon=False, ncol=2, loc="lower left", bbox_to_anchor=(0, 1))
  fig.savefig(out)
  plt.close(fig)

def main():
  if len(sys.argv) < 3:
    sys.exit("usage: plots.py <out_dir> <profile>=<raw.csv> [<profile>=<raw.csv> ...]")
  out = sys.argv[1]
  os.makedirs(out, exist_ok=True)
  profiles = []
  for arg in sys.argv[2:]:
    if "=" not in arg:
      sys.exit(f"expected <profile>=<raw.csv>, got: {arg}")
    name, path = arg.split("=", 1)
    profiles.append((name, load(path)))
  latency(profiles, "client_ready_ns", "client ready (ms, log scale)", os.path.join(out, "client_ready.png"))
  latency(profiles, "puback_ns", "connect to PUBACK (ms, log scale)", os.path.join(out, "puback.png"))
  cpu(profiles[0][1], os.path.join(out, "cpu.png"))
  handshake_bytes(profiles[0][1], os.path.join(out, "bytes.png"))
  for name, df in profiles:
    if df["config"].str.endswith("-noed").any():
      ablation(name, df, os.path.join(out, f"ablation_{name}.png"))
  print(f"figures written to {out}")

if __name__ == "__main__":
  main()
