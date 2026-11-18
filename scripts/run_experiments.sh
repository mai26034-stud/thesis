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
     exit 1
fi
if ! ss -ltn | grep -q ":1883 "; then
     echo "mosquitto is not listening on port 1883" >&2
     exit 1
fi

mkdir -p "$OUT"
{
     echo "date: $(date -Is)"
     echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo n/a)"
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

for round in $(seq 1 "$ROUNDS"); do
     for cfg in $(shuf -e "${CONFIGS[@]}"); do
          if [ "$cfg" = "baseline" ]; then
               "$BIN/gateway_baseline" "$PORT" "$ROOT/certs" "$TOTAL" > "$GW_CSV" 2>> "$OUT/errors.log" &
          else
               "$BIN/gateway" "$cfg" "$PORT" "$ROOT/keys" "$TOTAL" > "$GW_CSV" 2>> "$OUT/errors.log" &
          fi
          gw_pid=$!
          if ! wait_port; then
               echo "round $round $cfg: gateway did not start" >> "$OUT/errors.log"
               kill "$gw_pid" 2>/dev/null
               wait "$gw_pid" 2>/dev/null
               FAILURES=$((FAILURES + 1))
               continue
          fi
          if [ "$cfg" = "baseline" ]; then
               "$BIN/publisher_baseline" 127.0.0.1 "$PORT" "$ROOT/certs/ca-cert.pem" "$TOTAL" > "$PUB_CSV" 2>> "$OUT/errors.log"
          else
               "$BIN/publisher" "$cfg" 127.0.0.1 "$PORT" "$ROOT/keys/ca.pub" "$TOTAL" > "$PUB_CSV" 2>> "$OUT/errors.log"
          fi
          pub_rc=$?
          if [ "$pub_rc" -ne 0 ]; then
               kill "$gw_pid" 2>/dev/null
          fi
          wait "$gw_pid"
          gw_rc=$?
          if [ "$pub_rc" -ne 0 ] || [ "$gw_rc" -ne 0 ]; then
               echo "round $round $cfg: publisher=$pub_rc gateway=$gw_rc" >> "$OUT/errors.log"
               FAILURES=$((FAILURES + 1))
          fi
          if [ "$HEADER_DONE" -eq 0 ] && [ -s "$PUB_CSV" ]; then
               echo "round,warmup,$(head -1 "$PUB_CSV")" > "$OUT/raw.csv"
               HEADER_DONE=1
          fi
          tag "$round" "$PUB_CSV" >> "$OUT/raw.csv"
          tag "$round" "$GW_CSV" >> "$OUT/raw.csv"
          echo "round $round/$ROUNDS: $cfg done"
     done
done
rm -f "$GW_CSV" "$PUB_CSV"
echo "results: $OUT/raw.csv (failures: $FAILURES)"
if [ "$FAILURES" -gt 0 ]; then
     exit 1
fi
exit 0
