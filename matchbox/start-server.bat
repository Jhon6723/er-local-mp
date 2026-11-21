@echo off
REM start-server.bat — levanta fnserver.py (:10901 + :37017) y matchbox (:37015)
REM en ventanas minimizadas independientes. Doble click y listo.
REM Los logs quedan en este mismo directorio (fnserver.log / matchbox.log).

cd /d "%~dp0"

start "erlmp-fnserver" /min cmd /c "python -u fnserver.py >> fnserver.log 2>&1"
start "erlmp-matchbox" /min cmd /c "python -u -m matchbox.main >> matchbox.log 2>&1"

echo Servidores lanzados:
echo   fnserver  -^> TCP 10901 (FN) + UDP 37017 (lobbies)
echo   matchbox  -^> UDP 37015 (rendezvous)
echo.
echo Para detenerlos: cierra las ventanas minimizadas o
echo   taskkill /f /im python.exe
timeout /t 4 >nul
