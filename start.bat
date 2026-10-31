@echo off
chcp 65001 >nul
cd /d %~dp0
if not exist .venv (python -m venv .venv && .venv\Scripts\pip install -r requirements.txt)
.venv\Scripts\python app.py
pause
