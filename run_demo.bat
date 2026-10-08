@echo off
setlocal
cd /d "%~dp0"
echo Starting VPN Sentinel API on 127.0.0.1:48291
start "VPN Sentinel API" cmd /k python -m uvicorn app.main:app --host 127.0.0.1 --port 48291
cd frontend
echo Starting UI on 127.0.0.1:43123
start "VPN Sentinel UI" cmd /k npm run dev
echo.
echo Open http://127.0.0.1:43123
echo Keep both windows open. Use Demo: IKEv1.pcap then Demo: IKEv2.pcap
endlocal
