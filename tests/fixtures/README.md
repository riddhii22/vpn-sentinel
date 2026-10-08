# Lab / test captures

These files are **generated** by `build_lab_pcaps.py` for unit tests. They are not production VPN traffic.

| File | Purpose |
| --- | --- |
| `lab_ikev1_des_dh2.pcap` | IKEv1 SA advertising DES-CBC and DH group 2 |
| `lab_ah.pcap` | Single AH packet |
| `lab_natt_esp.pcap` | ESP inside UDP/4500 (NAT-T) |

Day 3 ESP-ANOM demo capture is `samples/esp_weird.pcap` (synthetic), not these fixtures.
