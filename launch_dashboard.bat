@echo off
title OmniRPC Live Blockchain Dashboard
cd /d "%~dp0"
echo Starting OmniRPC Multi-Chain Gateway & Dashboard on http://127.0.0.1:8787 ...
start "" "http://127.0.0.1:8787"
python "%~dp0omnirpc_server.py" --host 127.0.0.1 --port 8787
pause
