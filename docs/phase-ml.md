# Traffic intelligence (this phase)

## Teaching: five different things

| Concept | What it is | Who computes it | Changes the risk score? |
| --- | --- | --- | --- |
| **Packet analysis** | Read headers from the PCAP (IKE version, ESP count, packet lengths) | `app/analyzer/` | No. Facts only. |
| **Security rules** | If a fact matches policy (e.g. IKEv1 present → IKE-001) | `policies/rules.yaml` + `rules.py` | Findings carry points. |
| **Risk scoring** | Add those points, clamp 0–100 | `app/risk/` | This **is** the VPN Sentinel score. |
| **Traffic features** | Size, timing, bursts, windows — still metadata | `app/analyzer/traffic.py` | **No.** |
| **Machine learning** | A model trained on labeled examples that outputs a class + confidence | `app/ml/` | **Not used.** Unavailable. |

A judge-friendly sentence:

> The AI does not read encrypted content. It would use packet size and timing. Today there is no trained model, so VPN risk still comes only from security rules.

## Pipeline (kept separate)

```text
PCAP
 ↓
Packet Analyzer          (headers, IKE, IPsec)
 ↓
Observable Traffic Features   (sizes, timing, windows)
 ↓
 ┌───────────────────────┐
 │                       │
Security Rules        ML/Anomaly (interface only)
 │                       │
 └──────────┬────────────┘
            ↓
      Analysis Results
```

The ML box must **not** set `risk.score`.

## Working now

Observable features from the real PCAP: packet count, min/avg/max/std size, inter-arrival, packets/second, bursts (<1 ms), 0.5 s windows (packets/bytes/avg size/IAT/burst flag), first-pair A↔B counts, protocol distribution. `decrypts_payload` is always false.

API: `traffic_analysis.features` plus `model_available: false`.

Approximate analyze time on the bundled samples (parse already done in the timed `analyze_packets` call): **~15 ms** (IKEv1, 309 packets) and **~12 ms** (IKEv2, 197 packets) on this VM. Time-window lists are capped at **40** windows (0.5 s each) so long captures stay cheap.

## Prepared for ML

- `app/ml/dataset.py` — `data/{normal,attack,traffic,processed}/`
- `app/ml/preprocess.py` — deterministic feature vector
- `app/ml/model.py` — load/predict interface that **does not** deserialize pickle/joblib
- UI section **Traffic intelligence** (secondary to findings)

## Actual ML implemented

**Phase 3:** IsolationForest on **ESP flow** features (size mean/variance, IAT mean/variance, duration, byte volume). Fitted on bundled sample ESP flows. Synthetic weird metadata scores below the **typical** lab flow. **Does not** set `risk.score`. **Does not** name inner traffic.

**Day 3 / Phase 4:** finding **ESP-ANOM** (`origin: ml_anomaly`, score 0) when a flow’s scaled vector is farther from that sample cloud than 1.5× the farthest training flow. Demo capture: `samples/esp_weird.pcap`.

**Not implemented:** web/video/voice classes, pickle load of untrusted models.

## Future

Labeled dataset from a VPN testbed (web vs video vs voice inner traffic), documented train/test split, then a lightweight sklearn classifier with hold-out metrics. Risk score stays rule-based unless a later phase explicitly changes it.
