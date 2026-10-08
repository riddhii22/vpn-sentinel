#!/bin/sh
set -eu

if [ "${CLIENT_ROLE:-}" = "a" ]; then
  ip route replace 10.2.0.0/24 via 10.1.0.1
elif [ "${CLIENT_ROLE:-}" = "b" ]; then
  ip route replace 10.1.0.0/24 via 10.2.0.1
  python3 /usr/local/bin/client_sinks.py &
fi

exec sleep infinity
