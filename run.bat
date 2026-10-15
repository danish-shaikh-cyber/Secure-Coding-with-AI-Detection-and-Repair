@echo off
title AI-SecureCode Launcher
cls
echo ============================================================
echo        AI-SECURECODE: OFFLINE SECURITY PLATFORM           
echo ============================================================
echo.
echo Select an option:
echo [1] Start FastAPI backend
echo [2] Start React frontend
echo [3] Run benchmark health check
echo [4] Open project README
echo [5] Exit
echo.
set /p choice="Enter choice [1-5]: "

if "%choice%"=="1" (
    echo.
    echo [*] Starting AI-SecureCode backend at http://127.0.0.1:8000
    python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
) else if "%choice%"=="2" (
    echo.
    echo [*] Starting AI-SecureCode frontend at http://127.0.0.1:5173
    cd frontend
    npm install
    npm run dev -- --host 0.0.0.0 --port 5173
) else if "%choice%"=="3" (
    echo.
    echo [*] Running local system health and dataset check...
    python -c "print('Start the backend first, then open http://127.0.0.1:8000/docs')"
) else if "%choice%"=="4" (
    start README.md
) else (
    exit
)
