# Lab dataset

Ground-truth captures from `make testbed`. Lab traffic only.

| Path | Meaning |
| --- | --- |
| `C*/ping.pcap` | ICMP through the tunnel |
| `C*/web.pcap` | HTTP to client-b:8080 |
| `C*/voip.pcap` | UDP 5004, ~20 ms, 160-byte payload |
| `C*/bulk.pcap` | TCP bulk to client-b:9100 |
| `C*/email.pcap` | Lab SMTP-like session to :2525 |
| `C*/<traffic>.metadata.json` | Config + traffic_type labels |
| `labels.csv` | Index of every capture |

Do not invent extra classes (no WhatsApp). ESP payloads stay encrypted.
