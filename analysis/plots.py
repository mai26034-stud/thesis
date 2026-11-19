import os
import sys
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
  "font_size": 9, "axes.edgecolor": AXIS, "axes.labelcolor": MUTED,
  "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False,
  "axes.spines.right": False, "axes.grid": False, "axes.axisbelow": True, "grid.color": GRID,
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
  axis.set_major_formatter(NullFormatter())

def latency(profiles, col, ylabel, out):
  fig, axes = plt.subplots(1, len(profiles), figsize=(3.2 * len(profiles), 3.0), squeeze=False)
  for ax, (name, df) in  zip(axes[0], profiles):
    pub = df[df["role"] == "publisher"]
    data = [pub[pub["config"] == c][col]/1e6 for c in ORDER]
    box = ax.boxplot(data, widths=0.55, patch_artist=True), medianprops={"color": "white", "linewidth": 1.5}, whiskerprops={"color": MUTED}, capprops={"color": MUTED}, flierprops={"marker": "o", "markersize": 3, "markeredgecolor": MUTED})
    for patch, c in zip(box["boxes"], ORDER):
      patch.set_facecolor(COLOR[c])
      patch.set_edgecolor(COLOR[c])
    ax.set_yscale("log")
    log_axis(ax.yaxis)
    ax.set_xticks(range(1, len(ORDER) + 1), ORDER, rotation=20)
    ax.set_title(name, color=INK)
    ax.grid(axis="x", visible=False)
  axes[0][0].set_ylabel(ylabel)
  fig.savefig(out)
  plt.close(fig)
