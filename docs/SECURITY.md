# Prototype security notes

This is a **lab analyzer**, not a production SOC appliance.

## Mitigations in this build

- 20 MB upload cap; PCAP magic-byte check; empty/malformed → 400
- Temporary files deleted after parse; filename is `Path.name` only
- CORS `*` **without** credentials
- HTML report uses `html.escape`
- No pickle/joblib model load
- Evidence lists capped (findings slice + `evidence_index` max 80)
- No production secrets in the repo. The strongSwan lab uses a dummy PSK (`vpn-sentinel-lab-psk-not-a-secret`) documented as lab-only.
- Testbed compose publishes **no** host ports. Gateways are `privileged` only so Linux XFRM/IPsec can install SAs. Do not expose that compose file to an untrusted network.

## Residual risks

- CORS `*` is fine for a local demo; do not put this on the public internet as-is
- A huge-but-legal PCAP under 20 MB can still use CPU/RAM (Scapy)
- Demo sample endpoints are static files in the UI (lab captures)
- Analysts can upload captures from networks they should not inspect — operators must stay in-policy (lab only)

Do not claim the application is completely secure.
