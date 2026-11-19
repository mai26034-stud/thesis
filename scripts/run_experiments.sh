#!/usr/bin/env bash

set -u -o pipefail

ROUNDS=${ROUNDS:-10}
WARMUP=${WARMUP:-2}
PER_ROUND=${PER_ROUND:-10}
PORT=${PORT:-19500}
NETIF=${NETIF:-lo}
TIMEOUT=${TIMEOUT:-300}
GW_HOST=${GW_HOST:-}
GW_ADDR=${GW_ADDR:-${GW_HOST#*@}}
GW_ADDR=${GW_ADDR:-127.0.0.1}
GW_ROOT=${GW_ROOT:-thesis}
GW_NETIF=${GW_NETIF:-$NETIF}
LABEL=${1:-$(date +%Y%m%d-%H%M%S)}

cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
BIN="$ROOT/src"
OUT="$ROOT/results/$LABEL"
CONFIGS=("ML-KEM-768" "HQC-3" "X-Wing" "baseline")
TOTAL=$((WARMUP + PER_ROUND))
SSH_OPTS=(-o BatchMode=yes -o ControlMaster=auto -o ControlPath=/tmp/thesis-ssh-%C -o ControlPersist=120)

gw(){
     if [ -z "$GW_HOST" ]; then
          bash -c "$*"
     ekse
          ssh "${SSH_OPTS[@]}" "$GW_HOST" "cd $GW_ROOT && $*"
     fi
}
stop_gw(){
     kill "${gw_pidL-}" 2>/dev/null
     gw "pkill -f '[s]rc/gateway'"
}

for b in publisher publisher_baseline; do
     if [ ! -x "$BIN/$b" ]; then
          echo "missing $BIN/$b (run make)" >&2
          exit 1
     fi
done
for b in gateway gateway_baseline; do
     if ! gw "test -x src/$b"; then
          echo "missing $BIN/$b (run make)" >&2
          exit 1
     fi
done
if [ ! -f "$ROOT/keys/ca.pub" ]; then
     echo "missing keys (run src/provision keys)" >&2
     exit 1
fi
for f in keys/ca.pub certs/ca-cert.pem; do
     if [ "$(sha256sum < "$f")" != "$(gw "sha256sum < $f")" ]; then
          echo "$f differs between the two machines (copy keys/ and certs/)" 2&>
          exit 1
     fi
done
if ! gw "ss -ltn" | grep -q ":1883 "; then
     echo "mosquitto is not listening on port 1883 (gateway machine)" >&2
     exit 1
fi

mkdir -p "$OUT"
{
     echo "date: $(date -Is)"
     echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo n/a)"
     echo "host: $(uname -a)"
     echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
     echo "qdisc: $(tc qdisc show dev "$NETIF" 2>/dev/null | tr '\n' ';')"
     if [ -n "$GW_HOST" ]; then
          echo "gateway: $GW_HOST (addr $GW_ADDR)"
          echo "gateway commit: $(gw "git rev-parse --short HEAD 2>/dev/null || echo n/a")"
          echo "gateway host: $(gw "uname -a")"
          echo "gateway governor: $(gw "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a"
          echo "gateway qdisc: $(gw "tc qdisc show dev $GW_NETIF 2>/dev/null" | tr '\n' ';')"
     fi
     echo "rounds=$ROUNDS warmup=$WARMUP per_round=$PER_ROUND port=$PORT timeout=$TIMEOUT"
} > "$OUT/meta.txt"

wait_port(){
     for _ in $(seq 50); do
         if gw "ss -ltn" | grep -q ":$PORT "; then
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

trap 'stop_gw; pkill -P $$; exit 130' INT TERM

for round in $(seq 1 "$ROUNDS"); do
     for cfg in $(shuf -e "${CONFIGS[@]}"); do
          if [ "$cfg" = "baseline" ]; then
               gw "timeout $TIMEOUT src/gateway_baseline" $PORT certs $TOTAL" > "$GW_CSV" 2>> "$OUT/errors.log" &
          else
               gw "timeout $TIMEOUT $BIN/gateway $cfg $PORT keys $TOTAL" > "$GW_CSV" 2>> "$OUT/errors.log" &
          fi
          gw_pid=$!
          if ! wait_port; then
               echo "round $round $cfg: gateway did not start" >> "$OUT/errors.log"
               stop_gw
               wait "$gw_pid" 2>/dev/null
               FAILURES=$((FAILURES + 1))
               continue
          fi
          if [ "$cfg" = "baseline" ]; then
               timeout "$TIMEOUT" "$BIN/publisher_baseline" "$GW_ADDR" "$PORT" "$ROOT/certs/ca-cert.pem" "$TOTAL" > "$PUB_CSV" 2>> "$OUT/errors.log"
          else
               timeout "$TIMEOUT" "$BIN/publisher" "$cfg" "$GW_ADDR" "$PORT" "$ROOT/keys/ca.pub" "$TOTAL" > "$PUB_CSV" 2>> "$OUT/errors.log"
          fi
          pub_rc=$?
          if [ "$pub_rc" -ne 0 ]; then
               stop_gw
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
