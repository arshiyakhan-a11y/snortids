#!/bin/bash
# Fix directory permissions for NIDS project

cd "$(dirname "$0")"

echo "[*] Fixing permissions..."
chmod 777 data data/preprocessed logs pcaps dashboard/static/charts 2>/dev/null
chmod 755 . dashboard dashboard/templates 2>/dev/null
chmod 644 *.py *.txt *.md dashboard/templates/*.html rules/*.rules 2>/dev/null
chmod 755 run_dashboard.sh fix_permissions.sh 2>/dev/null
echo "[+] Permissions fixed!"
