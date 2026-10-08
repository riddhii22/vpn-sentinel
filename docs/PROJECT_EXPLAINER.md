# Project explainer (team)

This is the **working product**, not a slide. Do not claim extra features.

## 2-minute architecture (learn this)

A **PCAP** is a saved recording of packets. You upload it. FastAPI checks it is a real capture and not too large. Scapy reads each packet **once**.

Then four independent jobs run:

1. **Packet / IKE / IPsec analysis** — headers only. “This capture used IKEv1.” That is reading a version byte, not AI.
2. **Traffic features** — sizes and timing. Still not a prediction.
3. **Security rules** — YAML (`policies/rules.yaml`). If IKEv1 is present, raise IKE-001 and add 30 points.
4. **Risk engine** — `min(100, sum of finding points)`. Explainable. Not CVSS. Not ML.

The React dashboard **displays** that JSON. It does not score the VPN itself.

**AI/ML:** the interface exists. Classification is **unavailable** because we do not have a labeled training set. sklearn is installed and unused.

Analogy: we read the **envelope** (IKE labels, sizes, times), not the **letter** (ESP payload).

## Pipeline

```text
PCAP → validation → packet analyzer
          ├─ IKE/IPsec facts → YAML rules → findings → risk + evidence
          └─ traffic features → ML interface (no model)
                 → JSON → dashboard + HTML/JSON report
```

## Implemented now

Upload, validation, IKE/ESP/AH/NAT-T observation, cleartext SA algorithms, YAML findings, additive score, threat matrix, evidence, recommendations, traffic metadata, honest ML-unavailable, dashboard, report download.

## Working but limited

Algorithms/PFS/mode/lifetime only when the SA is **cleartext**. Sample Quick Mode is encrypted → `Not detected from available capture`.

## Planned

VPN testbed, labeled inner-traffic captures, trained classifier with hold-out metrics, live sniff, PPT score formula (conflicts with REQUIREMENTS.md).
