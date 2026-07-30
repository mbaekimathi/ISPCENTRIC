@echo off
rem Expire lapsed packages on the NAS. Hotspot packages are sold by the hour, so
rem this has to run on a short interval or a device stays online past the time it
rem paid for. Installed as the scheduled task "ISPCentric subscription sweep".
rem Set PYTHON to override the interpreter.
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
if not defined PYTHON set "PYTHON=python"
rem Single > keeps only the last run so the log cannot grow without bound.
"%PYTHON%" manage.py sync_subscription_access > "logs\subscription_sweep.log" 2>&1
