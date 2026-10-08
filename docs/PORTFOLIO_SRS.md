# VPN Sentinel — Portfolio requirements (BCA / MCA interview)

**Document type:** Student project SRS (scoped)  
**Time box:** 10 days × 2 hours/day = **20 hours total**  
**Audience:** You (builder), a viva panel, MCA interviewers  
**Related but different:** `REQUIREMENTS.md` is the **full SIH PS 26160** map. This file is the **contract you will actually finish**. Do not implement `REQUIREMENTS.md` in 20 hours.

---

## 1. Purpose

IPsec VPNs can look “secure” while still using an old handshake (IKEv1) or a weak cipher. An analyst normally opens Wireshark by hand.

**VPN Sentinel** is a **local tool**: upload a packet capture (`.pcap`) → the tool reads **visible IKE/IPsec headers** (it does **not** decrypt ESP) → it lists **findings** and a **0–100 risk score** → a **dashboard** and a **short report**.

This is a **strong BCA major-style project** if it runs, is honest, and you can explain the parser. It is **not** a complete SIH product and must not be described as one.

---

## 2. Interview goal (definition of “good enough”)

After 20 hours of remaining work, a stranger can:

1. Clone or copy the project and run backend + frontend from the README.  
2. Click **Demo IKEv1** and **Demo IKEv2** (or upload those samples) and see **different** findings/scores.  
3. Hear you explain, without notes: **why IKEv1 and IKEv2 need two parsers**, and **why ESP payload is never read**.  
4. Hear you explain the **AI piece in one minute**: IsolationForest on ESP **size/timing**, **not** “this packet is YouTube,” **not** “AI decoded IKE.”  
5. Read a README that states **what was scoped out** (full VPN lab, traffic-type classification).

If those five are true, the project is **portfolio-ready**. Extra features after that are optional, not required.

---

## 3. Time budget (do not exceed)

| Block | Hours | Phase |
| --- | --- | --- |
| Wireshark notes on two samples | 2 | 0 |
| Two RFC parsers + match samples | 6 | 1 |
| Rule-based findings + score | 3 | 2 |
| ESP features + IsolationForest + one finding | 4 | 3–4 |
| Dashboard/report if broken | 1 | 5 |
| README + limitations + resume line | 2 | 5 |
| Demo video + viva practice | 2 | 5 |

Buffer is **inside** these hours (if something slips, cut video length, not parsers or AI labels).

**Do not start** a Docker VPN matrix, IPv6 lab, or a trained web/video/voice **classifier**. The AI in this SRS is **binary anomaly on metadata only**.

---

## 4. In scope (MUST)

| ID | Requirement |
| --- | --- |
| M-01 | Offline **PCAP upload** only (no live sniff). |
| M-02 | Detect **IKEv1 vs IKEv2** from the ISAKMP **version** field, not the filename. |
| M-03 | Count **UDP 500, UDP 4500, ESP, AH**. |
| M-04 | **Two parsers:** IKEv1 SA attributes (RFC 2409) and IKEv2 transform substructure (RFC 7296 §3.3). No shared `0x80 0x01` hunt for both. |
| M-05 | Extract when **cleartext**: encryption, integrity/auth, DH group. If encrypted → **not detected**, never guess. |
| M-06 | **Rule-based** findings (e.g. IKEv1 present, DES/3DES, weak DH) with severity, score, recommendation. |
| M-07 | **Risk score** = min(100, sum of finding scores), with a named band (low / moderate / high / critical). |
| M-08 | **Dashboard** (existing layout): metrics, findings, handshake list, report download. No login, no extra pages. |
| M-09 | **HTML or PDF report** with a short executive summary + technical findings. |
| M-10 | **README**: how to run, architecture in a few lines, sample pcaps, **limitations**. |
| M-11 | At least **two** sample captures: one IKEv1, one IKEv2. |
| M-12 | **AI (honest):** IsolationForest on ESP **flow metadata** (size, timing, duration, volume). Dashboard/report show an **anomaly score**. Copy must say this is **not** inner-traffic classification and **not** IKE parsing. |

---

## 5. Should (only if MUST including M-12 is done)

| ID | Requirement |
| --- | --- |
| S-01 | Anomalous flow adds a **separate** finding id (not mixed into “weak AES”). Risk score can change; README says this is **traffic-shape**, not cipher grade. |
| S-02 | `samples/README`: one table of what each pcap is. |
| S-03 | Unlisted 2–4 minute demo video. |

Tunnel vs transport and PFS: **only** if the bytes are visible in the sample. Otherwise keep **not detected**. Do not invent them to look complete.

---

## 6. Out of scope (WON’T — say this in viva)

| ID | Not in this project |
| --- | --- |
| W-01 | Full VPN testbed (all modes × ciphers × DH × PFS × IPv4/IPv6 × traffic types). |
| W-02 | Packet Tracer as the packet source. |
| W-03 | Live capture, attacking other networks, decrypting ESP. |
| W-04 | Neural net / “AI” to read IKE fields (parsing is the correct method). |
| W-05 | Multi-class inner traffic (web / video / voice) with a real accuracy number. |
| W-06 | Hosting, login, database, Kubernetes. |
| W-07 | Matching every line of SIH PS 26160. |

---

## 7. Users and use case

**User:** You in a demo, or an interviewer watching the laptop.

**Use case:** Load `IKEv1.pcap` → see protocol finding and score → load `IKEv2.pcap` → see contrast → load unusual ESP → ESP-ANOM at 0 points → open report → answer “did you decrypt?” with **no**.

---

## 8. Non-functional (keep light)

- Runs on **one laptop** (Windows is fine): Python backend + Node frontend.  
- Analysis of the **shipped samples** finishes in **seconds**, not minutes.  
- No secrets required.  
- Code you cannot explain in a viva **does not ship**.

---

## 9. PS 26160 vs this SRS (honesty table)

| PS ask | This 20-hour project |
| --- | --- |
| VPN lab, many configs | **Out.** Public/lab sample pcaps only. |
| Capture pipeline | **Upload** of IKE/ESP/AH. |
| “AI” protocol ID | **Parser + rules**, not ML. The name “AI-based” is earned by **M-12**, not by pretending IKE is classified by a net. |
| Predict traffic inside ESP | **Out** as web/video/voice. **In** as “this ESP flow looks unusual.” |
| Security assessment | **Yes**, on visible crypto/protocol facts. |
| Reports, score, matrix | **Yes** (matrix can be grouping of findings). |
| AI confidence | **Anomaly / decision score from IsolationForest**, labeled. No fake 97% “YouTube.” |
| Dashboard, video, docs, dataset | Dashboard + docs + two pcaps; video if S-03. |

**Resume / MCA one-liner (use this wording):**

> IPsec VPN security analyzer: RFC-oriented IKEv1/IKEv2 parsing from PCAPs, rule-based crypto findings, IsolationForest anomaly detection on encrypted ESP flow metadata, explainable risk score, and a dashboard. Encrypted payloads are not decrypted. A full VPN lab and multi-class traffic-type classification were scoped out.

---

## 10. Phases (do not skip ahead)

**Do not start a phase until the previous Definition of done is true.**  
**This document does not authorize implementation until you name the phase** (e.g. “start Phase 0”).

### How “AI-based” is allowed (and how it is not)

| Allowed (Phase 3–4) | Not allowed (name still would be dishonest) |
| --- | --- |
| IsolationForest on **packet size, inter-arrival time, duration, bytes** of ESP flows | Calling IKE version/cipher “AI” |
| Score = how **unusual** the **shape** of encrypted traffic is | Saying the model **read** ESP payload |
| Interview line: “encryption hides bytes; size and timing still leak” | Web vs video vs voice **classes** with accuracy |

Keep the project title **AI-Powered IPsec VPN Security Analyzer** only if Phase 3–4 ship. If you skip them, drop “AI-Powered” on the resume.

### Phase 0 — Ground truth (Day 1, 2h) — **chat only, no parser code**

- Open IKEv1 and IKEv2 sample pcaps in Wireshark.  
- Note encryption / DH / integrity names on a **cleartext** SA.  
- **Done when:** those notes exist. You paste them before Phase 1 code.

### Phase 1 — Two parsers (Days 2–3, 6h) — **small diffs, line-by-line review**

- `parse_ikev1_sa` (RFC 2409 attributes).  
- `parse_ikev2_sa` (RFC 7296 §3.3 transforms).  
- **Done when:** printed values match your Wireshark notes; IKEv2 does not depend on a shared `0x80 0x01` encryption hunt.

### Phase 2 — Assessment engine (Day 4 + part of 5, 3h) — **chat / medium**

- Findings for IKEv1, IKEv2, weak cipher, weak DH **only if seen**.  
- Risk = min(100, sum of scores).  
- **Done when:** `/analyze` on both samples returns **different** finding lists.  
- Mode/PFS stay `not detected` unless Wireshark shows them in cleartext.

### Phase 3 — AI features + IsolationForest (Days 6–7, ~3h) — **chat for features, then sklearn glue**

- Group ESP by flow (IPs + SPI; ESP has no TCP ports).  
- Features you must be able to recite: size mean/variance, IAT mean/variance, duration, byte volume.  
- Fit IsolationForest on “normal” flows from **your samples**; test on a **synthetic weird** flow (huge packets or odd timing).  
- **Done when:** you can say why payload inspection is impossible, and the weird flow scores more anomalous.

### Phase 4 — Show AI on the report (rest of Day 7, ~1h) — **agent OK**

- New finding type **ESP-ANOM** (or similar), **origin: ml_anomaly**, not mixed with ENC-001.  
- Dashboard shows score + one sentence of limitation.  
- **Done when:** weird pcap changes findings (and score if S-01); normal samples do not pretend to be “video.”

### Phase 5 — Package and freeze (Days 8–10, ~5h) — **you own README wording**

- Report still works; no new pages.  
- README: architecture, run steps, AI paragraph, W-01–W-07.  
- Optional short demo video.  
- **Done when:** 10-minute local demo; GitHub/zip; **stop**.

| Day | Phase | 2-hour session |
| --- | --- | --- |
| 1 | 0 | Wireshark notes. |
| 2–3 | 1 | Two parsers vs notes. |
| 4 | 2 | Findings + score. |
| 5 | 2 then 3 | `/analyze` + dashboard; start ESP features if Phase 2 is done. |
| 6 | 3 | IsolationForest + sanity pcap. |
| 7 | 4 | Wire anomaly into findings UI. |
| 8 | 5 | README + limitations + resume line. |
| 9 | 5 | Demo video + viva: parsers + “AI is anomaly not YouTube.” |
| 10 | 5 | Freeze. No new features. |

If time slips: keep **Phases 0–2 + a visible AI panel that says unavailable** only as emergency — then the title should **not** say AI-Powered. Prefer cutting the **video**, not Phase 3, if the name must stay.

---

## 11. Acceptance checklist (tick before freeze)

- [x] IKEv1 sample: version IKEv1; score/findings make sense.  
- [x] IKEv2 sample: version IKEv2; **not** using IKEv1-only `0x80 0x01` as the only encoder.  
- [x] Encrypted fields show **not detected**, not a random algorithm.  
- [x] IsolationForest (or equivalent) runs on ESP metadata; UI does **not** call it traffic-type prediction.  
- [x] README lists W-01–W-07 in plain language.  
- [ ] You can demo in **10 minutes** without Wi-Fi (local run). *(needs the project on the laptop)*  
- [x] No sentence in README or PPT says the full PS is complete.

---

## 12. Change control

If something is not in **MUST** or **Should**, it is **rejected** during the 10 days. After freeze, do not reopen the project during NIMCET prep unless a demo is completely broken (will not start).

**Implementation starts only when you say the phase name**, e.g. `start Phase 0`.
