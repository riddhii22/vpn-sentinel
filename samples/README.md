# Bundled captures

| File | What it is | Expected analyzer |
| --- | --- | --- |
| `IKEv1.pcap` | Public IKEv1 + ESP | IKE-001, score 30. No ESP-ANOM. |
| `IKEv2.pcap` | Public IKEv2 + ESP | IKE-002, score 0. No ESP-ANOM. |
| `esp_weird.pcap` | Synthetic oversized ESP (no IKE). Not a real VPN. | ESP-ANOM, score 0. |

ESP-ANOM compares **size and timing** to the IKE samples. It does not decrypt and does not name web/voip/bulk.