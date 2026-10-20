import pandas as pd
import numpy as np

df1 = pd.read_csv("../src/results.csv")
df2 = pd.read_csv("../src/baseline.csv")
df = pd.concat([df1, df2], ignore_index=True)
time_cols = ["eph_keypair_ns", "eph_encaps_ns", "eph_decaps_ns", "cred_verify_ns", "auth_encaps_ns", "auth_decaps_ns", "key_schedule_ns", "total_ns"]

def ci95(s):
    n = len(s)
    if n < 2:
        return 0.0
    return 1.96 * s.std(ddof=1)/np.sqrt(n)

med = df.groupby(["config", "role"])[time_cols].median()
mean = df.groupby(["config", "role"])[time_cols].mean()
ci = df.groupby(["config", "role"])[time_cols].agg(ci95)
byts = df.groupby(["config", "role"])[["bytes_total", "bytes_client_auth", "bytes_server_auth"]].median()

pd.set_option("display.width", 250)
pd.set_option("display.max_columns", 50)

print("===== MEDIAN (ns) =====")
print(med)
print("\n===== MEAN (ns) =====")
print(mean)
print("\n===== 95% CI half-width (ns) =====")
print(ci)
print("\n===== BYTES (ns) =====")
print(byts)
