@echo off
cd /d "%~dp0"
start "" http://localhost:3000
python server.py || py server.py
pause
