#!/usr/bin/env bash
# Day 2: ping on C2,C4,C6,C7,C8,C10 plus extra inner-traffic types on C1 and C8.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAIL=0
for cfg in C2 C4 C6 C7 C8 C10; do
  echo "======== ${cfg} ping ========"
  if ! bash "$ROOT/testbed/run.sh" "$cfg" ping; then
    echo "FAILED ${cfg} ping" >&2
    FAIL=1
  fi
done
for kind in web voip bulk email; do
  echo "======== C1 ${kind} ========"
  if ! bash "$ROOT/testbed/run.sh" C1 "$kind"; then
    echo "FAILED C1 ${kind}" >&2
    FAIL=1
  fi
done
for kind in web voip; do
  echo "======== C8 ${kind} ========"
  if ! bash "$ROOT/testbed/run.sh" C8 "$kind"; then
    echo "FAILED C8 ${kind}" >&2
    FAIL=1
  fi
done
python3 "$ROOT/testbed/labels.py"
exit "$FAIL"
