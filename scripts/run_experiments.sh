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

