#!/usr/bin/env bash
# ==============================================================================
# Authorized Security Audit & Vulnerability Analysis Platform
# Single-Command Local Launcher (Native macOS/Linux)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
LAB_DIR="$SCRIPT_DIR/local-lab"

echo "======================================================================"
echo "  AUTHORIZED SECURITY AUDIT & VULNERABILITY ANALYSIS PLATFORM"
echo "  Defensive Cybersecurity Research & Posture Intelligence"
echo "======================================================================"
echo ""

# Check python virtualenv
if [ ! -f "$BACKEND_DIR/.venv/bin/python" ]; then
    echo "[!] Backend virtualenv not found at $BACKEND_DIR/.venv"
    echo "[*] Creating virtualenv and installing dependencies..."
    cd "$BACKEND_DIR"
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -r requirements.txt
    cd "$SCRIPT_DIR"
fi

# Trap to kill child processes on Ctrl+C or script termination
cleanup() {
    echo ""
    echo "[*] Shutting down all security audit services gracefully..."
    kill $(jobs -p) 2>/dev/null || true
    echo "[✓] All platform processes terminated cleanly."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Start Safe Local Lab Service (Port 8888)
echo "[1/3] Starting Safe Local Lab on http://127.0.0.1:8888 ..."
cd "$LAB_DIR"
"$BACKEND_DIR/.venv/bin/python" -m uvicorn app:app --host 127.0.0.1 --port 8888 --log-level warning &
LAB_PID=$!
sleep 1

# 2. Start FastAPI Backend (Port 8000)
echo "[2/3] Starting FastAPI Backend on http://127.0.0.1:8000 ..."
cd "$BACKEND_DIR"
"$BACKEND_DIR/.venv/bin/python" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level info &
BACKEND_PID=$!
sleep 1

# 3. Start Next.js Frontend (Port 3000)
echo "[3/3] Starting Next.js Frontend on http://localhost:3000 ..."
cd "$FRONTEND_DIR"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "======================================================================"
echo "  PLATFORM ONLINE & READY"
echo "======================================================================"
echo "  • Frontend Web Console:    http://localhost:3000"
echo "  • Backend API & Docs:      http://localhost:8000/docs"
echo "  • Safe Local Lab Target:   http://localhost:8888"
echo ""
echo "  Default Security Credentials:"
echo "    Username:  admin"
echo "    Password:  Admin@12345"
echo ""
echo "  Press Ctrl+C at any time to trigger the Emergency Kill Switch & exit."
echo "======================================================================"
echo ""

# Wait for all background processes
wait
