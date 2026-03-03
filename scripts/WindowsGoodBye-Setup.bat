@echo off
setlocal
chcp 65001 >nul 2>&1

REM ──────────────────────────────────────────────
REM  WindowsGoodBye — Installer Launcher
REM  Ejecuta el instalador (.exe o .ps1)
REM  Se auto-eleva a Administrador si es necesario
REM ──────────────────────────────────────────────

set "DIR=%~dp0"
set "EXE=%DIR%WindowsGoodBye-Setup.exe"
set "PS1=%DIR%WindowsGoodBye-Setup.ps1"

REM Si existe EXE, ejecutar directamente
if exist "%EXE%" (
    "%EXE%" %*
    goto :EOF
)

REM Ejecutar el PS1 — el propio script se auto-eleva
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*

endlocal
