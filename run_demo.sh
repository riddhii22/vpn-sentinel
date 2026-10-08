#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
echo "Start these two terminals:"
echo
echo "  python3 -m uvicorn app.main:app --host 127.0.0.1 --port 48291"
echo "  cd frontend && npm run dev"
echo
echo "Then open http://127.0.0.1:43123"
echo "API health: http://127.0.0.1:48291/health"
echo "Policy:     http://127.0.0.1:48291/rules"
echo
echo "Single-port preview (after npm run build in frontend/):"
echo "  python3 -m uvicorn app.main:app --host 0.0.0.0 --port 43123"
