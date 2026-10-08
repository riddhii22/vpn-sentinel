# T-PHASE-2 — IPsec analysis engine

**Status:** Phase 2 assessment engine — distinct IKEv1 vs IKEv2 findings/scores on shipped samples.

`POST /analyze` on `samples/IKEv1.pcap` → IKE-001, score **30**.  
`POST /analyze` on `samples/IKEv2.pcap` → IKE-002, score **0**.  
Lifetime 28800s detected on IKEv1; PFS/mode stay not_detected.
