# VPN Sentinel local demo (Windows)
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
Write-Host "Starting API on 127.0.0.1:48291"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$Root'; python -m uvicorn app.main:app --host 127.0.0.1 --port 48291"
Set-Location (Join-Path $Root "frontend")
Write-Host "Starting UI on 127.0.0.1:43123"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$(Join-Path $Root 'frontend')'; npm run dev"
Write-Host "Open http://127.0.0.1:43123"
