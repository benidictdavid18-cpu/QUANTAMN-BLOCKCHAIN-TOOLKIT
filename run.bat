@echo off
REM Quantum-Resistant Blockchain Security Toolkit - Windows Startup Script

echo =========================================
echo Quantum-Resistant Blockchain Toolkit
echo =========================================
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed
    pause
    exit /b 1
)

echo [OK] Python found
echo.

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
echo.

REM Create directories
echo Creating directories...
if not exist "uploads" mkdir uploads
if not exist "reports" mkdir reports
if not exist "badges" mkdir badges
if not exist "blockchain_proofs" mkdir blockchain_proofs
echo.

REM Start backend server
echo Starting backend server...
cd backend
start "Backend Server" python app.py
cd ..
echo [OK] Backend started
echo.

REM Start frontend server
echo Starting frontend server...
cd frontend
start "Frontend Server" python -m http.server 8080
cd ..
echo [OK] Frontend started
echo.

echo =========================================
echo Application is running!
echo =========================================
echo.
echo Frontend: http://localhost:8080
echo Backend API: http://localhost:8000
echo.
echo Close the command windows to stop servers
echo.
pause
