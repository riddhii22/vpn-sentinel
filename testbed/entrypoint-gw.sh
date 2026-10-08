#!/bin/sh
set -eu

ROLE=${ROLE:-gw}

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -F FORWARD 2>/dev/null || true

CHARON=/usr/lib/ipsec/charon
if [ ! -x "$CHARON" ]; then
  echo "charon not found at $CHARON" >&2
  exit 1
fi

"$CHARON" &
CHARON_PID=$!

i=0
while [ "$i" -lt 40 ]; do
  if swanctl --stats >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 0.25
done

swanctl --load-all || swanctl --load-all

echo "$ROLE charon ready"
wait "$CHARON_PID"
