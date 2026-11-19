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
