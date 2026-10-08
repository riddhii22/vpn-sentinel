# T-API-01 evidence

## Tests

`pytest tests -v` — 11 passed (2026-09-09).

| Case | Result |
| --- | --- |
| Empty upload | 400 |
| Non-PCAP | 400 |
| PCAP header, 0 packets | 400 |
| `../../etc/passwd.pcap` | 200, `file_name=passwd.pcap` |
| Oversize (limit patched to 64 bytes) | 413 |
| CORS `*` + credentials | not combined |
| IKEv1 sample | IKE-001 score 30 |
| IKEv2 sample | IKE-002 score 0 |
| `/health` | 200 |

## Commands

```
python3 -m pytest tests -v
```
