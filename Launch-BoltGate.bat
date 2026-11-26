@echo off
setlocal
cd /d "%~dp0"

if not exist "node_modules" (
  echo Installing dependencies...
  call npm install
  if errorlevel 1 exit /b 1
)

echo Building fresh BoltGate UI and Companion Bridge...
call npm run build
if errorlevel 1 (
  echo Build failed! Aborting launch so stale code is not served.
  exit /b 1
)

echo Starting BoltGate Companion on http://127.0.0.1:3847 ...
echo Browser will open automatically once the Companion binds cleanly.
echo If connecting from GitHub Pages, copy the one-time Pairing Code printed below.
set BOLTGATE_OPEN_BROWSER=1
node dist-server/companion/index.js
if errorlevel 1 (
  echo.
  echo BoltGate Companion exited with an error. Check the message above for port collisions.
  pause
  exit /b 1
)
