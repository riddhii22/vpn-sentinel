# Laptop setup (Windows)

The dashboard runs **on this PC**, not at a cloud `127.0.0.1`. You need a copy of the repo plus Python and Node.

Browse (private; change visibility on that page):  
https://cursor.com/codebase/riddhi-srivastav/unspecified-task

## A — Recommended: Windows, no WSL

### 1. Install

- **Python 3.11 or 3.12** from https://www.python.org/downloads/  
  Tick **Add python.exe to PATH**.
- **Node.js LTS** from https://nodejs.org/

New Command Prompt:

```bat
python --version
npm --version
```

### 2. Get the code

**Easiest:** In Cursor Desktop, open this project (the same chat/codebase). Use **File → Open Folder** on the cloned directory.

**Or WSL + Origin** (Origin CLI is **not** PowerShell). Only if Ubuntu actually opens `riddh@…:~$`:

```bash
# Run in WSL (Origin CLI is not available in PowerShell)
# Install the Origin CLI
curl -fsSL https://downloads.cursor.com/origin/install.sh | sh

# Sign in (also sets up git credentials)
origin auth login

# Clone the repository
origin repo clone riddhi-srivastav/unspecified-task
```

If `origin` is not found:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Origin CLI docs: https://cursor.com/docs/origin/cli

Copy the folder to something like `C:\Users\riddh\vpn-sentinel` if you cloned inside WSL (`\\wsl$\Ubuntu\home\…`).

### 3. Run (one window)

Double-click **`run_laptop.bat`** in the project folder, **or**:

```bat
cd C:\Users\riddh\vpn-sentinel
python -m pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
python -m uvicorn app.main:app --host 127.0.0.1 --port 43123
```

Browser: **http://127.0.0.1:43123**

Keep the black window open. First run can take several minutes (`pip` + `npm`).

### 4. Check

1. Demo: IKEv1.pcap → score **30**
2. Demo: IKEv2.pcap → score **0**
3. Demo: unusual ESP → **ESP-ANOM**, **0** points

## B — Do not use PowerShell for Origin

`curl … | sh` and `origin auth login` fail in `PS C:\Users\riddh>`. That is expected. Use **Ubuntu/WSL** for Origin, or skip Origin and use Cursor/Git as in A.

## If WSL Ubuntu still says invalid certificate

Skip WSL. Path A does not need it.

## Npcap

Not required to **read** the shipped PCAPs. Only needed if you later sniff a live interface (out of scope).
