# Demo runbook (SIH presentation)

You do **not** decrypt traffic. You upload a **PCAP** and the tool reports what it can **see** in IKE/IPsec.

## Setup (once)

```bash
python3 -m pip install -r requirements.txt
cd frontend && npm install && cd ..
```

## Start backend

```bash
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 48291
```

Check http://127.0.0.1:48291/health → `{"status":"ok"}`.

## Start frontend

```bash
cd frontend
npm run dev
```

## Open the app

**http://127.0.0.1:43123**

Keep both terminals running. The UI proxies `/api` to the backend.

Windows shortcuts: `run_demo.bat` / `run_demo.ps1`.

Single-port (after `cd frontend && npm run build`):

```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 43123
```

Then open **http://127.0.0.1:43123** (UI and API together).

## Demo script (~2 minutes)

1. Open **VPN Sentinel**. Point at the glossary (VPN, IPsec, IKE, ESP).
2. Click **Demo: IKEv1.pcap**.
3. Risk **30/100 MEDIUM**. Say: “IKE version is IKEv1 — we read the ISAKMP version byte, not the filename.”
4. “IKEv1 is a **critical finding** (30 points). The overall band is moderate until more penalties stack.”
5. Open the finding. Show **evidence** (packet number, IPs).
6. Show **PFS** and **Mode** as **Not detected** (Quick Mode encrypted).
7. Scroll to **Traffic intelligence**. Sizes/timing are real. **Traffic-type classification is unavailable.** IsolationForest scores ESP metadata; **ESP-ANOM** stays off on this sample.
8. **Download HTML report**. Open it — same score and findings.
9. Click **Demo: IKEv2.pcap**. Score **0 / LOW**. Compare table if both runs are in memory.
10. Click **Demo: unusual ESP**. Finding **ESP-ANOM** (ML tag, **0 points**). Risk stays **0**. Evidence summary is **1 packet** (flow metadata, not a decrypted payload). Say: “this is size/timing vs the lab cloud, not YouTube, not a weak cipher.”
11. Optional: upload a `.txt` file → clean error, no fake success.

## What not to claim

- We do **not** decrypt ESP.
- We do **not** have a trained traffic-class model.
- The score is **VPN Sentinel Risk Score** (rules), not an AI score and not CVSS.
- We did **not** finish the full SIH problem statement.
