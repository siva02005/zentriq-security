@echo off
title ZENTRIQ Server + Public Domain
cd /d "%~dp0"

echo ====================================================
echo        Starting ZENTRIQ Security Layer
echo ====================================================

echo 1. Seeding default policies...
python scripts/seed_policies.py

echo.
echo 2. Starting Uvicorn Server on port 8010...
start "ZENTRIQ Backend" /B python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8010

timeout /t 2 /nobreak >nul

echo.
echo 3. Establishing Public Online Domain via SSH Tunnel...
echo ----------------------------------------------------
echo Your live public HTTPS URL will be displayed below:
echo (Keep this terminal window open to keep domain active)
echo ----------------------------------------------------
ssh -p 443 -o StrictHostKeyChecking=no -R0:127.0.0.1:8010 a.pinggy.io
