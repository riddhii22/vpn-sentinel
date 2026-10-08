# Requirements traceability

Status: **Implemented** | **Working but limited** | **Prepared** | **Planned**

`REQUIREMENTS.md` meaning is not changed by this table.

| Requirement | Status | Notes |
| --- | --- | --- |
| TB-01–TB-09 testbed | Planned | No StrongSwan lab in this repo |
| CAP-01–CAP-02 IKE/ESP capture | Implemented | Via PCAP upload, not live sniff |
| CAP-03 store PCAP | Working but limited | Upload analyzed in memory; samples in `samples/` |
| CAP-04 features | Implemented | Size, timing, SPI presence, IKE fields |
| CAP-05 empty/fail | Implemented | 4xx, no silent empty report |
| CAP-06 live sniff | Planned | |
| AI-01 IKE version | Implemented | Parsed, not ML |
| AI-02–AI-04 crypto/DH | Working but limited | Cleartext SA only |
| AI-05 tunnel vs transport | Working but limited | `not_detected` on shipped samples |
| AI-06 inner traffic class | Prepared | Features + interface; **no model** |
| AI-07 confidence | Prepared | `null` until a model exists |
| AI-08 model artifacts | Planned | No weights to persist |
| SEC-01–SEC-05 policy | Implemented | YAML; some fields not_detected |
| SEC-06 risk 0–100 | Implemented | Additive |
| SEC-07 threat matrix | Implemented | |
| OUT-01 dashboard | Implemented | React, real API |
| OUT-02 empty/loading/error | Implemented | |
| OUT-03 report | Implemented | HTML + JSON download |
| OUT-04 mobile | Implemented | Responsive CSS |
| OUT-05 upload / samples | Implemented | |
| DEL-01 runnable prototype | Implemented | Local Python + Vite |
| DEL-02 trained model | Not implemented | Honest unavailable |
| DEL-03–DEL-05 docs/dashboard/report | Implemented | |
| DEL-06 labeled dataset | Prepared | `data/` empty on purpose |
| NFR-05 no prod secrets | Implemented | |
| NFR-06 live sniff off | Implemented | Off |
| TECH-UTF8 / CORS | Implemented | `*` without credentials |
