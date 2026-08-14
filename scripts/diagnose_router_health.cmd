@echo off
rem Layered MikroTik health loops (ping / 8728 / 80 / API auth).
rem Use to diagnose Offline / Limited / Auth failed drops.
rem Example: diagnose_router_health.cmd --loops 8 --settle 2
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
if not defined PYTHON set "PYTHON=python"
"%PYTHON%" manage.py diagnose_router_health %* > "logs\diagnose_router_health.log" 2>&1
type "logs\diagnose_router_health.log"
