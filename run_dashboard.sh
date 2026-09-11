#!/bin/bash
# NIDS Dashboard Launcher for Kali Linux

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "[*] Installing dependencies..."
pip install --upgrade pip setuptools wheel -q
pip install -r requirements.txt -q

echo "[*] Starting NIDS Dashboard..."
echo "[*] Open http://127.0.0.1:5000 in your browser"
echo "[*] Press Ctrl+C to stop"
echo ""

python dashboard/app.py
