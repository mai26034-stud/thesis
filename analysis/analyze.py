import sys
import pandas as pd
import numpy as np
from scipy import stats
import base64

if len(sys.argv) > 1:
    df = pd.read_csv(sys.argv[1])
    df = df[df["warmup"] == 0]
else:
    df1 = pd.read_csv("../src/results.csv")
    df2 = pd.read_csv("../src/baseline.csv")
    df = pd.concat([df1,df2], ignore_index=True)
time_cols = ["eph_keypair_ns", "eph_encaps_ns", "eph_decaps_ns", "cred_verify_ns", "auth_encaps_ns", "auth_decaps_ns", "key_schedule_ns", "total_ns", "client_ready_ns", "puback_ns", "cpu_ns"]

AUTHKEM_RECORD_OVERHEAD = 5 + 1 + 16 + 5
ECDSA_P256_SIG = 71
SERVER_CERT = "../certs/server-cert.pem"

def der_len_from_pem(path):
    with open(path) as f:
        b64 = "".join(line.strip() for line in f if not line.startswith("-----"))
    return len(base64.b64decode(b64))

def ci95(s):
    n = len(s)
    if n < 2:
        return 0.0
    return stats.t.ppf(0.975, n - 1) * s.std(ddof=1)/np.sqrt(n)

med = df.groupby(["config", "role"])[time_cols].median()
mean = df.groupby(["config", "role"])[time_cols].mean()
ci = df.groupby(["config", "role"])[time_cols].agg(ci95)
byts = df.groupby(["config", "role"])[["bytes_total", "bytes_client_auth", "bytes_server_auth"]].median()

pd.set_option("display.width", 250)
pd.set_option("display.max_columns", 50)

print("===== SAMPLES (n) =====")
print(df.groupby(["config","role"]).size())
print()
print("===== MEDIAN (ns) =====")
print(med)
print("\n===== MEAN (ns) =====")
print(mean)
print("\n===== 95% CI half-width (ns) =====")
print(ci)
print("\n===== BYTES =====")
print(byts)
mem = df.groupby(["config","role"])["max_rss_kb"].max()
print("\n===== PEAK MEMORY (KB) =====")
print(mem)

side = df["role"].map({"client": "client", "publisher": "client", "server": "server", "gateway": "server"})
b = df.assign(side=side).groupby(["config", "side"])[["bytes_total","bytes_client_auth","bytes_server_auth"]].median()
cert_der = der_len_from_pem(SERVER_CERT)

rows = []
for cfg in sorted(df["config"].unique()):
    try:
        c_tot = b.loc[(cfg,"client"),"bytes_total"]
        s_tot = b.loc[(cfg,"server"),"bytes_total"]
    except KeyError:
        continue
    if cfg == "baseline":
        auth = cert_der + ECDSA_P256_SIG
        source = "computed"
    else:
        c_auth = b.loc[(cfg,"client"),"bytes_client_auth"] - AUTHKEM_RECORD_OVERHEAD
        s_auth = b.loc[(cfg,"server"),"bytes_server_auth"] - AUTHKEM_RECORD_OVERHEAD
        auth = c_auth + s_auth
        source = "measured"
    total =c_tot + s_tot
    rows.append({"config": cfg, "handshake_bytes": total, "auth_bytes": auth, "auth_share_pct": round(100.0 * auth/total, 1), "source": source})
print("\n===== AUTHENTICATION BYTES =====")
print(pd.DataFrame(rows).set_index("config"))
