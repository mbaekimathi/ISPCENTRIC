@echo off
rem Layered remote CPE access loops (Open client router path).
rem Example: diagnose_cpe_access.cmd --customer 5 --loops 3
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
if not defined PYTHON set "PYTHON=python"
"%PYTHON%" manage.py diagnose_cpe_access %* > "logs\diagnose_cpe_access.log" 2>&1
type "logs\diagnose_cpe_access.log"
