#!/usr/bin/env bash

set -u -o pipefail

ROUNDS=${ROUNDS:-10}
WARMUP=${WARMUP:-2}
PER_ROUND=${PER_ROUND:-10}
PORT=${PORT:-19500}
LABEL=${1:-$(date +%Y%m%d-%H%M%S)}

cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
BIN="$ROOT/src"
OUT="$ROOT/results/$LABEL"
CONFIGS=("ML-KEM-768" "HQC-3" "X-Wing" "baseline")
TOTAL=$((WARMUP + PER_ROUND))

for b in gateway publisher gateway_baseline publisher_baseline; do
     if [ ! -x "$BIN/$b" ]; then
          echo "missing $BIN/$b (run make)" >&2
          exit 1
     fi
done
if [ ! -f "$ROOT/keys/ca.pub" ]; then
     echo "missing keys (run src/provision keys)" >&2
     exit
fi
     if ! ss -ltn | grep -q ":1883 " >&2
     exit 1
fi

mkdir -p "$OUT"
{
     echo "date: $(date -Is)"
     echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo n/a"
     echo "host: $(uname -a)"
     echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
     echo "rounds=$ROUNDS warmup=$WARMUP per_round=$PER_ROUND port=$PORT"
} > "$OUT/meta.txt"

wait_port(){
     for _ in $(seq 50); do
         if ss -ltn | grep -q ":$PORT "; then
               return 0
          fi
          sleep 0.1
     done
     return 1
}

tag(){
     awk -F, -v r="$1" -v w="$WARMUP" 'NR > 1 { print r "," ($3 <= w ? 1 : 0) "," $0 }' "$2"
}

HEADER_DONE=0
FAILURES=0
GW_CSV="$OUT/.gateway.csv"
PUB_CSV="$OUT/.publisher.csv"
