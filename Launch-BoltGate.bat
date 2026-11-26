@echo off
setlocal
cd /d "%~dp0"

if not exist "node_modules" (
  echo Installing dependencies...
  call npm install
)

if not exist "dist\index.html" (
  echo Building BoltGate UI and server...
  call npm run build
) else if not exist "dist-server\server\index.js" (
  echo Building BoltGate server...
  call npm run build:server
)

echo Starting BoltGate on http://127.0.0.1:3847 ...
start "" http://127.0.0.1:3847
node dist-server/server/index.js
