# VPN Sentinel

Lab prototype for **SIH 2026 PS 26160** (team **ENTROPY**): an IPsec VPN **security assessment** tool.

You upload a packet capture (PCAP). The analyzer reads **IKE and IPsec headers**, applies a YAML security policy, and produces an explainable **0–100 risk score**. Encrypted ESP payloads are **never decrypted**.

**What you are actually finishing:** [docs/PORTFOLIO_SRS.md](docs/PORTFOLIO_SRS.md) (20-hour BCA/MCA portfolio scope). **Full SIH map (not the 10-day plan):** [REQUIREMENTS.md](REQUIREMENTS.md).

## 1. What it is

VPN Sentinel is a local prototype: PCAP → analysis → findings → risk → dashboard → HTML/JSON report.

## 2. Problem statement

NTRO PS 26160 asks for an AI-powered IPsec VPN protocol analyzer and security assessment framework. Misconfigured VPNs (old IKE, weak ciphers, weak DH) are common and hard to spot without packet expertise.

## 3. Why VPN security matters

A VPN looks “secure” while still using IKEv1, DES, or a tiny DH group. Those choices weaken the handshake even if the traffic is encrypted.

## 4. Architecture

```text
PCAP → validation → packet analyzer
         ├─ IKE/IPsec facts → YAML rules → findings → risk + evidence
         └─ ESP size/timing → IsolationForest → ESP-ANOM (score 0)
                → JSON → dashboard + report
```

The UI does **not** compute scores. IsolationForest does **not** set the VPN risk score. There is **no** web/voip/bulk classifier.

## 5. Technology stack

**Implemented:** Python, FastAPI, Scapy, PyYAML, React + Vite + TypeScript.

**Not used:** Node/Express analysis backend, MongoDB, Kubernetes, a trained web/voip/bulk classifier.

sklearn **IsolationForest** scores ESP metadata. `python -m app.ml.train` still does **not** fit a traffic-type model.

## 6. How PCAP analysis works

Scapy reads the file once. ISAKMP **version** (0x10 vs 0x20) decides IKEv1 vs IKEv2. ESP/AH/UDP 500/4500 are counted. Cleartext SA transforms yield encryption, hash, DH, lifetime when present. Filename is ignored.

## 7. Security engine

`policies/rules.yaml` lists `when` conditions (e.g. `ikev1_present`). `app/analyzer/rules.py` only checks **facts**. Edit YAML to add a rule; add a `when` predicate in Python if you need a new fact type.

## 8. Risk scoring

**VPN Sentinel Risk Score** = `min(100, sum of finding.score)`.

| Band | Score |
| --- | --- |
| critical | 80–100 |
| high | 60–79 |
| moderate | 30–59 (UI label MEDIUM) |
| low | 0–29 |

IKEv1 finding severity is **critical** (30 points) so overall band is **moderate**. That is intentional.

PPT formula `100 − (Critical×25 + Warning×10)` is **not** used (conflicts with REQUIREMENTS.md). See `docs/conflicts-ppt-requirements-repo.md`.

## 9. Traffic intelligence

Sizes, timing, bursts, 0.5 s windows, direction A↔B, protocol mix, bytes/s. Metadata only.

## 10. ML component

**IMPLEMENTED:** IsolationForest on ESP **size/timing** (Phase 3) and finding **ESP-ANOM** (Day 3 / Phase 4) when a flow is an outlier versus bundled samples. Score **0**. Origin **ml_anomaly**.

**NOT IMPLEMENTED:** a web/voip/bulk Random Forest. Fifteen labelled lab rows are not enough for hold-out accuracy. `GET /ml/status` still says traffic-type prediction is unavailable. No fake confidence.

## 11. Dashboard

React app at http://127.0.0.1:43123 — security analysis layout with a 4-card metric row (packets, score, penalty findings, handshake protocol), handshake viewer, parameter badges, parser stream, findings + evidence, threat matrix, recommendations, traffic charts, and report download. Values come from `POST /analyze`. Demos: IKEv1.pcap, IKEv2.pcap, unusual ESP.

## 12. Report generation

Each analysis includes `report.html` and `report.json` (escaped HTML). Download from the UI.

## 13. Installation

```bash
python3 -m pip install -r requirements.txt
cd frontend && npm install && cd ..
```

## 14. Running backend

```bash
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 48291
```

## 15. Running frontend

```bash
cd frontend && npm run dev
```

Windows (one window, recommended): `run_laptop.bat` — see [docs/LAPTOP.md](docs/LAPTOP.md).

Two-window Vite demo: `run_demo.bat` or `run_demo.ps1`.

## 16. Demo steps

See `docs/DEMO_RUNBOOK.md`. Short version: Demo IKEv1 → 30/100 MEDIUM → Demo IKEv2 → 0/100 LOW → Demo unusual ESP → ESP-ANOM (0 points).

## 17. Sample PCAPs

| File | Role |
| --- | --- |
| `samples/IKEv1.pcap` | Real IKEv1 + ESP |
| `samples/IKEv2.pcap` | Real IKEv2 + ESP |
| `samples/esp_weird.pcap` | Synthetic oversized ESP (Day 3 ESP-ANOM demo) |
| `tests/fixtures/*.pcap` | Controlled lab packets (DES, AH, NAT-T) |

## 18. Limitations (W-01–W-07)

PFS, tunnel/transport, replay: **Not detected** on the shipped Wireshark samples (Quick Mode / IKE_AUTH encrypted). No live sniff. Inner-traffic **labels** come from the lab generator (`dataset/labels.csv`), not from decrypting ESP.

| ID | Out of this freeze |
| --- | --- |
| W-01 | Full VPN matrix (every mode × cipher × DH × PFS × IPv4/IPv6 × traffic type). Lab covers a subset; C5/C6 are not true transport; C9 IPv6 is off. |
| W-02 | Packet Tracer as the packet source. |
| W-03 | Live capture, attacking other networks, decrypting ESP. |
| W-04 | A neural net that “reads” IKE. Version and ciphers come from **parsers**. |
| W-05 | Web/video/voice classification with an accuracy number. |
| W-06 | Hosting, login, database, Kubernetes. |
| W-07 | Completing every line of SIH PS 26160. Honest share of the full PS is about **45%**. |

**Resume line:** IPsec VPN security analyzer: RFC-oriented IKEv1/IKEv2 parsing from PCAPs, rule-based crypto findings, IsolationForest anomaly detection on encrypted ESP flow metadata, explainable risk score, and a dashboard. Encrypted payloads are not decrypted. A full VPN lab and multi-class traffic-type classification were scoped out.

Viva script: [docs/VIVA.md](docs/VIVA.md). Demo: [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md).

## Lab testbed (Day 1–2)

Docker Compose lab with two strongSwan gateways, two clients, and tcpdump on the transit link:

```bash
make testbed CONFIG=C1
make testbed CONFIG=C8 TRAFFIC=ping
make testbed-day2
```

Writes `dataset/<CONFIG>/<traffic>.pcap` plus metadata and `dataset/labels.csv`. Details: [testbed/README.md](testbed/README.md). Needs Docker Engine. Dummy PSK, privileged gateways, **kernel-libipsec** / UDP 4500 on kernels without XFRM ESP. **C5/C6 are not true transport.** C9 IPv6 is not built.

## Day 3 (ESP-ANOM)

Finding **ESP-ANOM** is IsolationForest **telemetry**, not a cipher grade. Demo: IKEv1/IKEv2 must **not** raise it. **Demo: unusual ESP** (`samples/esp_weird.pcap`) must raise it. Risk scores stay **30** and **0** on the two IKE demos. See [docs/phase4.md](docs/phase4.md).

## Day 4 (freeze polish)

No Streamlit (React is the UI). No Random Forest. Copy and docs only: evidence “1 packet”, resume line, demo runbook includes unusual ESP.

## Day 5 (freeze)

**No new features.** Optional unlisted 2–4 minute screen recording of the demo runbook. After freeze, only fix “will not start.” See [docs/day5.md](docs/day5.md).

## 19. Future work (after freeze, not this repo sprint)

Hold-out RF metrics on a larger run-wise split, live sniff, PPT score formula. Interactive teaching site is a **later** phase.

### Status key

| | |
| --- | --- |
| **IMPLEMENTED** | Upload, analyze, YAML policy, additive risk, matrix, evidence, recs, traffic features, dashboard, reports, `/health` `/rules` `/ml/status` |
| **PARTIALLY IMPLEMENTED** | SA algorithms / lifetime only when cleartext; mode/PFS/replay usually not_detected |
| **PLANNED** | Trained inner-traffic classifier with run-wise hold-out, live sniff, PPT score formula |
