# PPT ↔ REQUIREMENTS.md ↔ repository (do not silently “fix”)

SIH PPT = product **vision** (architecture, names, stack proposal, judge story).  
`REQUIREMENTS.md` = **Must/Should** for PS 26160.  
GitHub `vpn-sentinel` = **current code**.

We build a **working SIH prototype**, not a slide diagram.

## Conflicts (flagged)

| ID | PPT | REQUIREMENTS.md | Repo (now) | Practical choice |
| --- | --- | --- | --- | --- |
| S1 | Node + Express + WS + Mongo + React + K8s | Files + API + dashboard; no DB required | FastAPI only | **Keep FastAPI as the engine/API for the prototype.** Add a React UI later if it helps judges. Skip Express/Mongo/K8s until they are needed. |
| S2 | IsolationForest = “the AI” | Traffic class web/video/voice **Must** (AI-06) | Features extracted; **no trained model** | **Do not train on 2 unlabeled PCAPs.** IsolationForest later only with evaluable data |
| S3 | Risk `100 − (C×25 + W×10)` | Additive 0–100, 5-level matrix | Sum of 30/20 scores | **Do not change weights in Phase 1.** POL task later; PPT formula vs REQ table stays a conflict |
| S4 | IKEv1 Critical | §6 IKEv1 High | severity critical, score 30 | Leave code; document mismatch |
| S5 | Continuous live WS | Lab-scale; live sniff Should | Upload only | PCAP-first; live later, lab-only |
| S6 | React dashboard | Dashboard Must | React + Vite | **Keep React dashboard** wired to FastAPI |

## Not a conflict

Packet inspection without decrypting ESP; PCAP demos; IKEv1 + weak crypto flags; Scapy; team name VPN Sentinel / ENTROPY.
