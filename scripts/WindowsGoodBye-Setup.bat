@echo off
setlocal

REM ──────────────────────────────────────────────
REM  WindowsGoodBye — Installer Launcher
REM  Ejecuta el instalador (.exe o .ps1)
REM  Requiere privilegios de Administrador
REM ──────────────────────────────────────────────

set "DIR=%~dp0"
set "EXE=%DIR%WindowsGoodBye-Setup.exe"
set "PS1=%DIR%WindowsGoodBye-Setup.ps1"

REM Si existe EXE, ejecutar directamente
if exist "%EXE%" (
    "%EXE%" %*
    goto :EOF
)

REM Fallback: ejecutar el PS1 como admin
chcp 65001 >nul 2>&1

REM Verificar si ya somos admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando privilegios de administrador...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\" %*\"' -Verb RunAs"
    goto :EOF
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Unblock-File -Path '%PS1%' -ErrorAction SilentlyContinue; & '%PS1%' %*"

endlocal
