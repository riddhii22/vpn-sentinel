# Day 3 / Phase 4 — ESP-ANOM on the report

IsolationForest on ESP **size and timing** already existed (Phase 3). Day 3 only **shows** an outlier as finding **ESP-ANOM**.

## What fires

A capture is flagged when at least one ESP flow’s scaled feature vector is farther from the bundled-sample cloud (IKEv1.pcap + IKEv2.pcap flows) than **1.5×** the farthest training flow.

That rule is used instead of IsolationForest `predict() == -1` alone: with ~11 training flows, `predict` also labels some of the training samples as outliers.

## Honesty

| Claim | True? |
| --- | --- |
| Payloads decrypted | **No** |
| Web / voip / bulk class | **No** |
| Changes VPN risk score | **No** (`score: 0`) |
| Mixed into ENC-001 | **No** (`origin: ml_anomaly`) |
| Random Forest traffic-type model | **Not built** (15 labelled lab rows are too few) |

## Demo

`samples/esp_weird.pcap` is synthetic oversized ESP (not a VPN handshake). Dashboard: **Demo: unusual ESP**. Bundled IKEv1/IKEv2 demos must **not** raise ESP-ANOM.
