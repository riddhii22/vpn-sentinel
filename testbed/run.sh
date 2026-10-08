#!/usr/bin/env bash
# Bring up one lab config, generate inner traffic, write dataset/<id>/<traffic>.pcap
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${1:-${CONFIG:-C1}}"
TRAFFIC="${2:-${TRAFFIC:-ping}}"
KEEP="${KEEP:-0}"
OUT_DIR="$ROOT/dataset/${CONFIG}"
PCAP_NAME="${TRAFFIC}.pcap"
PCAP="$OUT_DIR/${PCAP_NAME}"
META="$OUT_DIR/${TRAFFIC}.metadata.json"
FILTER="udp port 500 or udp port 4500 or proto 50 or proto 51"

case "$TRAFFIC" in
  ping|web|voip|bulk|email) ;;
  *)
    echo "unknown TRAFFIC=$TRAFFIC (ping|web|voip|bulk|email)" >&2
    exit 1
    ;;
esac

DOCKER_CMD=(docker)
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
  else
    echo "docker is not installed or not running. Install Docker Engine + Compose, then retry." >&2
    exit 1
  fi
fi

COMPOSE=("${DOCKER_CMD[@]}" compose -f "$ROOT/testbed/docker-compose.yml")

relax_bridge_nf() {
  for key in bridge-nf-call-iptables bridge-nf-call-ip6tables; do
    path="/proc/sys/net/bridge/${key}"
    if [ -w "$path" ]; then
      echo 0 >"$path" || true
    elif command -v sudo >/dev/null 2>&1; then
      sudo sysctl -w "net.bridge.${key}=0" >/dev/null 2>&1 || true
    fi
  done
}

cd "$ROOT"
python3 "$ROOT/testbed/render.py" "$CONFIG" --traffic "$TRAFFIC" --pcap-name "$PCAP_NAME" --metadata "$META"
if [ "$TRAFFIC" = "ping" ]; then
  cp -f "$META" "$OUT_DIR/metadata.json"
fi
relax_bridge_nf

mkdir -p "$OUT_DIR"
rm -f "$PCAP"

"${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --build

# Capture IKE as well as ESP: start tcpdump before initiate.
"${COMPOSE[@]}" exec -d capture sh -c "rm -f /dataset/${CONFIG}/${PCAP_NAME}; tcpdump -i any -U -n -w /dataset/${CONFIG}/${PCAP_NAME} ${FILTER}"
sleep 1

echo "waiting for CHILD SA (ESP)..."
ok=0
"${COMPOSE[@]}" exec -T gw-a swanctl --initiate --child child >/tmp/vpn-sentinel-ike.log 2>&1 || true
for _ in $(seq 1 40); do
  if "${COMPOSE[@]}" exec -T gw-a swanctl --list-sas 2>/dev/null | grep -Eqi 'INSTALLED'; then
    ok=1
    break
  fi
  sleep 1
  "${COMPOSE[@]}" exec -T gw-a swanctl --initiate --child child >/dev/null 2>&1 || true
done
if [ "$ok" -ne 1 ]; then
  echo "CHILD SA did not install. swanctl --list-sas:" >&2
  "${COMPOSE[@]}" exec -T gw-a swanctl --list-sas || true
  cat /tmp/vpn-sentinel-ike.log >&2 || true
  "${COMPOSE[@]}" exec -T capture pkill -INT tcpdump >/dev/null 2>&1 || true
  "${COMPOSE[@]}" logs gw-a gw-b | tail -n 120 >&2
  if [ "$KEEP" != "1" ]; then
    "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  exit 2
fi

PEER="$(python3 -c "import yaml; from pathlib import Path; m=yaml.safe_load(Path('$ROOT/testbed/matrix.yaml').read_text()); r={**(m.get('defaults') or {}), **m['configs']['$CONFIG']}; print(r.get('ping_target','10.2.0.10'))")"
FROM="$(python3 -c "import yaml; from pathlib import Path; m=yaml.safe_load(Path('$ROOT/testbed/matrix.yaml').read_text()); r={**(m.get('defaults') or {}), **m['configs']['$CONFIG']}; print(r.get('ping_from','client-a'))")"

echo "traffic ${TRAFFIC} from ${FROM} -> ${PEER}"
set +e
case "$TRAFFIC" in
  ping)
    "${COMPOSE[@]}" exec -T "$FROM" ping -c 8 -W 2 "$PEER"
    TRAFFIC_RC=$?
    ;;
  web|voip|bulk|email)
    "${COMPOSE[@]}" exec -T "$FROM" python3 /usr/local/bin/client_send.py "$TRAFFIC" --host "$PEER"
    TRAFFIC_RC=$?
    ;;
esac
set -e

sleep 2
"${COMPOSE[@]}" exec -T capture pkill -INT tcpdump >/dev/null 2>&1 || true
sleep 1

if [ ! -s "$PCAP" ]; then
  echo "PCAP missing or empty: $PCAP" >&2
  TRAFFIC_RC=3
fi

python3 - "$PCAP" <<'PY' || true
import sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    from scapy.all import ESP, IP, IPv6, UDP, rdpcap
except Exception as exc:
    print("scapy not available, skip pcap summary:", exc)
    sys.exit(0)
pkts = rdpcap(str(path))
esp = sum(
    1
    for p in pkts
    if p.haslayer(ESP)
    or (p.haslayer(IP) and p[IP].proto == 50)
    or (p.haslayer(IPv6) and p[IPv6].nh == 50)
)
ike = 0
for p in pkts:
    if p.haslayer(UDP) and (p[UDP].sport in (500, 4500) or p[UDP].dport in (500, 4500)):
        ike += 1
print(f"pcap packets={len(pkts)} ike_udp={ike} esp={esp}")
if len(pkts) == 0:
    sys.exit(4)
PY

python3 "$ROOT/testbed/labels.py"

echo "wrote $PCAP"
echo "wrote $META"
"${COMPOSE[@]}" exec -T gw-a swanctl --list-sas || true

if [ "$KEEP" != "1" ]; then
  "${COMPOSE[@]}" down --remove-orphans
fi

if [ "${TRAFFIC_RC:-0}" -ne 0 ]; then
  echo "warning: traffic ${TRAFFIC} exited ${TRAFFIC_RC} (PCAP may still be useful if ESP is present)" >&2
fi
exit 0
