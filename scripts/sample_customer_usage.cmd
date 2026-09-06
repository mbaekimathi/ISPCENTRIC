@echo off
rem Snapshot PPPoE/Hotspot usage for General usage (no page visit required).
rem Schedule every 1 minute as "ISPCentric customer usage sample".
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
if not defined PYTHON set "PYTHON=python"
"%PYTHON%" manage.py sample_customer_usage > "logs\usage_sample.log" 2>&1
