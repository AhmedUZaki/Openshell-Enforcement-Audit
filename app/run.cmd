@echo off
REM Launches the OpenShell Enforcement Audit GUI.
REM Double-click this file, or run it from cmd/PowerShell.

cd /d "%~dp0"

if not exist node_modules (
  echo Installing dependencies...
  call npm install
  if errorlevel 1 (
    echo npm install failed.
    pause
    exit /b 1
  )
)

call npm start
set "RESULT=%ERRORLEVEL%"

echo.
pause
exit /b %RESULT%
