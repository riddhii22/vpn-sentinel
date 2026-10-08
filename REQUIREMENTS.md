# Requirements Specification

**Problem ID:** 26160  
**Title:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework  
**Organization:** NTRO — Blockchain & Cybersecurity  
**Document type:** Software Requirements Specification (prototype)  
**Status:** Draft for prototype development

---

## 1. Purpose

IPsec VPNs are widely deployed, but their security depends on configuration choices: cipher suites, key-exchange method, tunnel vs transport mode, Perfect Forward Secrecy (PFS), key lifetimes, and related parameters. Misconfigurations are common and are typically found only through expert, manual packet analysis.

This project shall produce a working prototype that:

1. Operates an IPsec VPN **testbed** with controlled configuration variants.
2. **Captures** IKE handshake traffic and ESP/AH packets.
3. Uses **AI/ML** to identify protocol parameters and (without decryption) infer inner traffic type from size/timing patterns.
4. Performs a **security assessment** of the observed configuration.
5. Produces a **report** (risk score, threat matrix, AI confidence) and a **dashboard** for operators.

---

## 2. Goals and non-goals

### 2.1 Goals

- Demonstrate end-to-end capture → analysis → assessment → report for representative IPsec setups.
- Train and evaluate a model on a documented dataset generated from the testbed (and/or labeled captures).
- Present results in a dashboard with risk scoring, threat grouping, and prediction confidence.
- Ship documentation sufficient for a reviewer to run the prototype and understand limits.

### 2.2 Non-goals (prototype scope)

- Production-grade VPN gateway product or replacement for commercial VPN analyzers (e.g. full Wireshark/IPsec expert systems).
- Decrypting ESP payloads or recovering session keys (inner traffic type is inferred from **metadata only**).
- Attacking live third-party networks, unauthorized capture, or offensive use against systems the operator does not control.
- Full IKEv1/IKEv2 feature coverage of every RFC extension, vendor proprietary payload, or NAT-T edge case beyond what the testbed can generate.
- Real-time 100 Gbps inline inspection; lab-scale capture and batch/near-real-time analysis is sufficient.

---

## 3. Users and use cases

| Actor | Description |
| --- | --- |
| Security analyst | Reviews captures, protocol IDs, risk scores, and reports. |
| Lab operator | Runs testbed scenarios, collects PCAPs, labels traffic classes. |
| Reviewer / evaluator | Replays documented scenarios and checks deliverables. |

**Primary use case:** Operator starts (or loads) a testbed scenario → traffic is captured → analyzer identifies IKE/ESP parameters and inner traffic class → security engine scores the config → dashboard and exportable report are produced.

**Secondary use case:** Analyst uploads an existing PCAP (from the same lab environment) and obtains the same pipeline output.

---

## 4. Functional requirements

### 4.1 VPN testbed

The system **shall** provide a controllable IPsec testbed that can establish connections under documented settings.

| ID | Requirement | Priority |
| --- | --- | --- |
| TB-01 | Establish IPsec connections in **Tunnel** and **Transport** mode. | Must |
| TB-02 | Support encryption variants including **AES-128** and **AES-256** (and document any additional algorithms used, e.g. 3DES or ChaCha20, if present). | Must |
| TB-03 | Support multiple **Diffie–Hellman / key-exchange groups** (at least two distinct groups; document which, e.g. DH14 vs DH19/20). | Must |
| TB-04 | Toggle **Perfect Forward Secrecy (PFS)** on and off for Child SAs where the stack allows. | Must |
| TB-05 | Support **IPv4** and **IPv6** underlay (or inner) addressing as feasible on the lab stack; if one family cannot be run, document the gap. | Must |
| TB-06 | Generate distinguishable **inner traffic types**: web (HTTP/HTTPS-like bursts), video (steady larger packets), and voice (small periodic packets). Additional types (e.g. bulk file transfer) are optional. | Must |
| TB-07 | Record the exact configuration used for each run (mode, ciphers, DH group, PFS, lifetimes, addressing, traffic profile) as metadata next to the capture. | Must |
| TB-08 | Isolate testbed traffic so captures are attributable to the intended scenario (containers, namespaces, or VMs). | Should |
| TB-09 | Provide a single command or script to run a **scenario matrix** (subset of combinations) and emit labeled captures. | Should |

**Implementation note:** StrongSwan, Libreswan, or equivalent open-source IPsec is acceptable. Exact stack must be documented.

### 4.2 Traffic capture

| ID | Requirement | Priority |
| --- | --- | --- |
| CAP-01 | Capture **IKE** (UDP/500, and UDP/4500 if NAT-T is used) including SA proposal and negotiation. | Must |
| CAP-02 | Capture **ESP** and/or **AH** packets for the established SA. | Must |
| CAP-03 | Store captures in **PCAP/PCAPNG** with scenario ID and timestamp. | Must |
| CAP-04 | Extract features without requiring payload decryption: packet length, inter-arrival time, direction, SPI (if present), IKE payload types, proposal transforms, lifetimes advertised in IKE. | Must |
| CAP-05 | Handle empty capture / failed handshake with a clear error state (no silent empty report). | Must |
| CAP-06 | Optional live sniff on a named interface; file upload of PCAP is required for the dashboard path. | Should |

### 4.3 AI-based protocol identification

Predictions **shall** be produced from captured traffic (and derived features), not from reading the testbed config file at inference time (config is ground truth for training/eval only).

| ID | Requirement | Priority |
| --- | --- | --- |
| AI-01 | Detect **IKE version** (IKEv1 vs IKEv2) when IKE is present. | Must |
| AI-02 | Identify **encryption algorithm** used or proposed (at minimum AES-128 vs AES-256 when distinguishable from IKE proposals / transform attributes). | Must |
| AI-03 | Identify **authentication / integrity** algorithm when advertised in IKE (e.g. SHA-256 vs SHA-1 HMAC, AES-GCM AEAD). | Must |
| AI-04 | Identify **key-exchange method / DH group**. | Must |
| AI-05 | Classify **Tunnel vs Transport** mode. | Must |
| AI-06 | Classify **inner traffic type** (web / video / voice, plus `unknown`) **without decrypting** ESP, using patterns such as packet size distribution and timing. | Must |
| AI-07 | Output a **confidence score** (0–100 or 0–1) per prediction and an overall analysis confidence. | Must |
| AI-08 | Persist model artifacts (weights/pipeline) and a documented train/test split. | Must |
| AI-09 | If IKE is missing and only ESP is present, still attempt mode/traffic-type inference and mark IKE-derived fields as unavailable (low confidence). | Should |

**Model notes (prototype):** Classical ML (random forest / gradient boosting on hand-crafted features) is acceptable if accuracy is reported; a small neural model is optional. Hybrid is allowed: parse IKE with a protocol dissector where unambiguous, and use ML for traffic-type and ambiguous/ESP-only cases. The report **must** state which fields are parsed vs predicted.

### 4.4 Security assessment

The assessment engine **shall** evaluate observed (parsed or predicted) parameters against a documented policy baseline.

| ID | Requirement | Priority |
| --- | --- | --- |
| SEC-01 | Rate **cipher strength** (e.g. AES-256 vs AES-128 vs legacy/weak). | Must |
| SEC-02 | Detect whether **PFS** is enabled for the Child SA / rekey path when evidence exists. | Must |
| SEC-03 | Assess **key / SA lifetime** (too long, missing, or reasonable) when present in IKE. | Must |
| SEC-04 | Assess **replay protection** (e.g. ESN / sequence number window evidence, or config/IKE flags if observable; otherwise document limitation). | Must |
| SEC-05 | Flag weak DH groups, IKEv1 if still used, null/weak integrity, and transport mode on untrusted networks as policy findings (severity per §6). | Must |
| SEC-06 | Produce an overall **risk score** (0–100, higher = riskier) with a short rationale list. | Must |
| SEC-07 | Produce a **threat matrix** grouping findings by severity: Critical / High / Medium / Low / Info. | Must |

### 4.5 Output: dashboard and report

| ID | Requirement | Priority |
| --- | --- | --- |
| OUT-01 | Web **dashboard** showing: scenario/capture identity, identified protocol parameters, inner traffic class, risk score, threat matrix, and AI confidence. | Must |
| OUT-02 | Empty, loading, and error states for no capture, parse failure, and model failure. | Must |
| OUT-03 | Exportable **report** (HTML and/or PDF/Markdown) including risk score, threat matrix, predictions, confidences, and timestamp. | Must |
| OUT-04 | Usable on desktop and a reasonable mobile viewport (read-only review). | Should |
| OUT-05 | Allow selecting a completed testbed run or uploading a PCAP to re-analyze. | Should |

### 4.6 Dataset, model, and documentation deliverables

| ID | Requirement | Priority |
| --- | --- | --- |
| DEL-01 | **Working prototype** runnable from documented commands. | Must |
| DEL-02 | **AI model** files plus training script and metrics (accuracy/F1 per task). | Must |
| DEL-03 | **Dashboard** as specified in §4.5. | Must |
| DEL-04 | **Report** generator as specified in §4.5. | Must |
| DEL-05 | **Documentation**: architecture, how to run testbed, how to train, how to interpret scores, known limitations, ethical use (lab only). | Must |
| DEL-06 | **Dataset** used to train/test: PCAPs or feature tables, labels, license/provenance, and train/test split. Synthetic lab data is expected. | Must |

---

## 5. Data and feature requirements

### 5.1 Ground-truth labels (per capture / flow)

- IKE version  
- Encryption algorithm  
- Integrity / auth algorithm (or AEAD combined mode)  
- DH / key-exchange group  
- Tunnel vs Transport  
- PFS on/off  
- SA lifetime (if configured)  
- IPv4 vs IPv6  
- Inner traffic class: `web` | `video` | `voice` | `unknown`  
- Scenario ID and generation timestamp  

### 5.2 Features for ML (non-decrypting)

Examples the pipeline should extract where available:

- Packet length histogram / mean / std / percentiles (inbound vs outbound)  
- Inter-arrival time statistics  
- Packets per second, burstiness  
- IKE exchange type, number of proposals, transform IDs (when parsed)  
- ESP vs AH presence, UDP encapsulation  
- Directional byte ratio  

Payload bytes of ESP **shall not** be used as plaintext features.

### 5.3 Dataset quality

- Minimum viable set: enough labeled runs to train/test the traffic-type classifier and report hold-out metrics (target: **≥ 30 captures** covering all required axes; more is better).  
- No leakage: test captures must not be identical copies of train captures.  
- Include at least one **failed/partial IKE** sample for error-path testing.

---

## 6. Security scoring policy (baseline)

The prototype **shall** implement a transparent, documented scoring policy. Suggested default (tunable):

| Finding | Typical severity | Notes |
| --- | --- | --- |
| Null encryption, MD5, DES/3DES-only | Critical | Weak/legacy crypto |
| IKEv1 only (no IKEv2) | High | Legacy handshake |
| Weak DH group (e.g. ≤ 1024-bit MODP) | High | Logjam-class risk |
| PFS disabled | High | Past session keys more valuable if long-term key leaks |
| AES-128 vs AES-256 | Medium / Info | Context-dependent; still record |
| Very long SA lifetime | Medium | Increases exposure window |
| Transport mode | Medium | Inner IP headers exposed vs tunnel |
| Replay protection not evidenced | Medium | If cannot be confirmed, lower confidence Info |
| AES-256, IKEv2, strong DH, PFS on | Info / Low risk | Healthy baseline |

**Risk score:** start from 0; add weighted points per finding; clamp to 0–100. Dashboard must show contributing findings.

---

## 7. Non-functional requirements

| ID | Requirement |
| --- | --- |
| NFR-01 | Prototype runs on a Linux lab host (containers acceptable). |
| NFR-02 | Analysis of a lab-sized PCAP (minutes of traffic, not multi-GB) completes in interactive time (order of seconds to a few minutes). |
| NFR-03 | Scoring rules and model versions are recorded in each report. |
| NFR-04 | No requirement for cloud GPUs; CPU training of a small model is acceptable. |
| NFR-05 | Secrets: no production VPN PSKs in the repo; testbed uses documented lab-only PSKs. |
| NFR-06 | Capture and analysis **only** on operator-controlled lab networks. |

---

## 8. System context (logical)

```
[Testbed: IPsec peers + traffic generators]
        → PCAP + scenario metadata
        → Feature extractor / IKE parser
        → ML models (protocol + traffic class)
        → Security assessment engine
        → Dashboard + exported report
```

---

## 9. Interface requirements

- **CLI:** run scenario, capture, analyze, train, export report.  
- **Web UI:** view latest/selected analysis, threat matrix, confidence, download report.  
- **Artifacts:** `models/`, `datasets/` (features + labels; PCAPs if size allows or documented generation script), `reports/`.

---

## 10. Acceptance criteria (prototype)

The prototype is acceptable if a reviewer can:

1. Run documented testbed scenarios covering Tunnel/Transport, AES-128/256, ≥2 DH groups, PFS on/off, and web/video/voice traffic.  
2. Obtain a capture and an analysis where IKE-derived fields match ground truth for those lab scenarios (parsed or predicted).  
3. See inner traffic class predicted **without decryption**, with reported accuracy on a held-out set.  
4. Open a dashboard showing risk score, threat matrix, and confidence.  
5. Export a report containing the same information.  
6. Read documentation describing dataset, model, limitations, and how scores are computed.

---

## 11. Out of scope / constraints reminder

- Do not decrypt user VPN traffic or claim plaintext recovery.  
- Traffic-type identification is **statistical/heuristic** and will be imperfect, especially for mixed or tunneled-over-HTTPS inner flows; confidence must reflect that.  
- Replay-protection assessment may be limited if only ciphertext ESP is visible; the report must not invent unobservable facts.

---

## 12. Traceability to problem statement

| Problem statement item | Requirements |
| --- | --- |
| Testbed: Tunnel/Transport, AES-128/256, DH groups, PFS, IPv4/IPv6, web/video/voice | TB-01–TB-06 |
| Capture IKE and ESP/AH | CAP-01–CAP-03 |
| Identify IKE version, enc/auth, key exchange | AI-01–AI-04 |
| Tunnel vs Transport | AI-05 |
| Inner traffic type without decrypting | AI-06 |
| Cipher strength, PFS, key lifetime, replay protection | SEC-01–SEC-04 |
| Risk score, threat matrix, AI confidence | SEC-06–SEC-07, AI-07, OUT-01–OUT-03 |
| Prototype, model, dashboard, report, docs, dataset | DEL-01–DEL-06 |

---

## 13. Glossary

| Term | Meaning |
| --- | --- |
| IKE | Internet Key Exchange (IKEv1/IKEv2), negotiates IPsec SAs |
| ESP | Encapsulating Security Payload — encrypted (and optionally authenticated) packets |
| AH | Authentication Header — integrity without encryption |
| PFS | Perfect Forward Secrecy — new DH per (child) rekey so stolen long-term keys do not decrypt past sessions |
| SPI | Security Parameter Index in ESP/AH |
| Threat matrix | Findings grouped by severity for the assessed session/config |
