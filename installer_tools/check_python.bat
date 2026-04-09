@echo off
:: check_python.bat
:: Returns ERRORLEVEL 0 if Python 3.12.x is on PATH, else 1.
:: Called by Inno Setup [Run] directive.

setlocal EnableDelayedExpansion

:: ── Try 'python --version' ────────────────────────────────────
for /f "tokens=1,2 delims= " %%A in ('python --version 2^>^&1') do (
    set PY_VER=%%B
)

if not defined PY_VER goto :not_found

:: ── Parse major.minor ─────────────────────────────────────────
for /f "tokens=1,2 delims=." %%M in ("%PY_VER%") do (
    set MAJOR=%%M
    set MINOR=%%N
)

if "%MAJOR%"=="3" (
    if "%MINOR%"=="12" (
        echo Python %PY_VER% detected — OK
        exit /b 0
    )
)

:not_found
echo Python 3.12 not found (found: %PY_VER%)
exit /b 1
