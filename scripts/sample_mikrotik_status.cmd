@echo off
rem Probe MikroTik health for the workspace performance trend / outage history.
rem Schedule every 1–2 minutes as "ISPCentric MikroTik status sample".
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
if not defined PYTHON set "PYTHON=python"
"%PYTHON%" manage.py sample_mikrotik_status > "logs\mikrotik_status_sample.log" 2>&1
