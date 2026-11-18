#!/usr/bin/env bash
set -u -o pipefail

PORT=${PORT:-19500}
if [ "$#" -ne 2 ]; then
     echo "usage: $0 <interface> <off|wifi|cellular|constrained>" >&2
     exit 1
fi
IF="$1"
PROFILE="$2"

case "$PROFILE" in
     off)
          tc qdisc del dev "$IF" root 2>/dev/null
          tc qdisc show dev "$IF"
          exit 0
          ;;
     wifi)        ARGS="delay 5ms loss 0.1%" ;;
     cellular)    ARGS="delay 25ms loss 0.5% rate 5mbit" ;;
     constrained) ARGS="delay 100ms loss 1% rate 250kbit" ;;
     *)
          echo "unknown profile: $PROFILE" >&2
          exit 1
          ;;
esac

fail(){
     echo "tc failed: $1 (run with sudo; check that sch_netem is available)" >&2
     tc qdisc del dev "$IF" root 2>/dev/null
     exit 1
}

tc qdisc del dev "$IF" root 2>/dev/null
tc qdisc add dev "$IF" root handle 1: prio bands 4 || fail "prio"
tc qdisc add dev "$IF" parent 1:4 handle 40: netem $ARGS || fail "netem"
tc filter add dev "$IF" parent 1: protocol ip prio 1 u32 match ip dport "$PORT" 0xffff flowid 1:4 || fail "filter dport"
tc filter add dev "$IF" parent 1: protocol ip prio 1 u32 match ip dport "$PORT" 0xffff flowid 1:4 || fail "filter sport"

tc qdisc show dev "$IF"
tc filter show dev "$IF"
