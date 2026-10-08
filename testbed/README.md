# strongSwan lab testbed (Day 1)

Two gateways (`gw-a`, `gw-b`), one client behind each, tcpdump in the `gw-a` network namespace.

```text
client-a (10.1.0.10)
    |
  left net 10.1.0.0/24
    |
  gw-a (10.1.0.1 / 10.10.0.10) ---- transit 10.10.0.0/24 ---- gw-b (10.10.0.20 / 10.2.0.1)
                                                                  |
                                                            right net 10.2.0.0/24
                                                                  |
                                                           client-b (10.2.0.10)
```

## Commands

```bash
make testbed CONFIG=C1
make testbed CONFIG=C8 TRAFFIC=ping
make testbed CONFIG=C1 TRAFFIC=web    # also: voip, bulk, email
make testbed-day2                     # ping on C2,C4,C6,C7,C8,C10 + extra types on C1/C8
KEEP=1 make testbed CONFIG=C1
make testbed-down
make labels
```

Each run writes `dataset/<CONFIG>/<traffic>.pcap` and `<traffic>.metadata.json`. `dataset/labels.csv` is rebuilt after each run.

## Kernel / Docker notes (lab honesty)

- Gateways are **privileged** and use a **dummy PSK** (`vpn-sentinel-lab-psk-not-a-secret`). Nothing is published on host ports.
- Some lab kernels reject XFRM ESP (`Protocol not supported`). This compose enables strongSwan **kernel-libipsec** (userspace ESP via TUN). Packets on the wire are still IKE + ESP, usually **UDP 4500** (NAT-T) rather than IP proto 50.
- If containers cannot ping each other, `run.sh` tries `net.bridge.bridge-nf-call-iptables=0` (Docker bridge netfilter dropping veth traffic).
- **C5 and C6:** spec asks for **transport**. This lab uses a **subnet tunnel** (`requested_mode: transport`, `mode: tunnel`). C6 ESP has **no DH group** (PFS off).
- **C7, C8, C10:** deliberately weak (SHA-1, DH 2, 3DES, and/or IKEv1).
- **C9 IPv6:** still disabled (stretch).

Inner traffic types (encrypted inside ESP): `ping`, `web`, `voip` (160-byte UDP / 20 ms), `bulk` (TCP), `email` (lab SMTP on 2525). Labels are ground truth from the generator, not from ML.

## Day 3 (dashboard, not Wireshark)

ESP-ANOM is size/timing vs bundled IKE samples. Lab ping PCAPs are **not** expected to look like `esp_weird.pcap`. YOUR TURN: Demo IKEv1 (no ESP-ANOM) then Demo: unusual ESP (ESP-ANOM, 0 points).

